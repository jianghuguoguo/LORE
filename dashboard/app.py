"""
爬虫管理Web界面 - Flask后端服务
提供RESTful API来管理所有爬虫
"""

import os
import sys
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# 设置 Hugging Face 镜像，解决国内网络连接超时问题
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_cors import CORS

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from crawlers.crawler_manager import CrawlerManager
from crawlers.config import ENABLED_SOURCES

# 导入自适应检索系统
try:
    from processors.adaptive_retriever import AdaptiveRetriever
    from processors.failure_detector import FailureDetector
    from processors.reflection_diagnoser import ReflectionDiagnoser
    from processors.query_rewriter import QueryRewriter
    from processors.ragflow_client import RAGFlowClient
    from processors.evo_config import config
    ADAPTIVE_RETRIEVAL_AVAILABLE = True
except ImportError:
    ADAPTIVE_RETRIEVAL_AVAILABLE = False
    print("警告: 自适应检索模块未找到")


app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
CORS(app)

# 全局变量
crawler_manager = CrawlerManager()
# 存储最近一次检索的结果，用于经验总结推送
last_retrieval_data = {
    'query': None,
    'result': None
}
crawl_status = {
    'running': False,
    'current_source': None,
    'progress': {},
    'logs': [],
    'results': {}
}

training_status = {
    'running': False,
    'phase': 'idle',  # idle, labeling, training, completed, error
    'progress': 0,
    'message': '',
    'logs': []
}

# 任务线程
crawl_thread = None
training_thread = None


class LogCollector:
    """日志收集器"""
    def __init__(self):
        self.logs = []
        self.max_logs = 1000
    
    def add(self, level: str, message: str, source: str = 'system'):
        """添加日志"""
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': level,
            'source': source,
            'message': message
        }
        self.logs.append(log_entry)
        
        # 限制日志数量
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
    
    def get_logs(self, limit: int = 100):
        """获取最新日志"""
        return self.logs[-limit:]
    
    def clear(self):
        """清空日志"""
        self.logs = []


log_collector = LogCollector()


def crawl_task(sources: List[str], query: str, max_pages: int = 5):
    """后台爬取任务"""
    global crawl_status
    
    try:
        crawl_status['running'] = True
        crawl_status['progress'] = {}
        
        log_collector.add('info', f'开始爬取任务 - 关键词: {query}, 数据源: {sources}')
        
        for source in sources:
            if not crawl_status['running']:
                log_collector.add('warning', '爬取任务被中止')
                break
            
            crawl_status['current_source'] = source
            crawl_status['progress'][source] = {'status': 'running', 'count': 0}
            
            log_collector.add('info', f'开始爬取: {source}', source)
            
            try:
                # 调用爬虫
                crawler = crawler_manager.get_crawler(source)
                if crawler:
                    results = crawler.crawl(query, max_pages=max_pages)
                    
                    crawl_status['results'][source] = results
                    crawl_status['progress'][source] = {
                        'status': 'completed',
                        'count': len(results)
                    }
                    
                    log_collector.add('success', f'完成爬取: {source} - {len(results)}条数据', source)
                else:
                    crawl_status['progress'][source] = {'status': 'error', 'count': 0}
                    log_collector.add('error', f'未找到爬虫: {source}', source)
            
            except Exception as e:
                crawl_status['progress'][source] = {'status': 'error', 'count': 0}
                log_collector.add('error', f'爬取失败 {source}: {str(e)}', source)
        
        # 保存结果
        if crawl_status['results']:
            try:
                crawler_manager.save_results(crawl_status['results'], query)
                log_collector.add('success', '结果已保存到raw_data目录')
            except Exception as e:
                log_collector.add('error', f'保存结果失败: {str(e)}')
        
        log_collector.add('info', '爬取任务完成')
    
    except Exception as e:
        log_collector.add('error', f'任务异常: {str(e)}')
    
    finally:
        crawl_status['running'] = False
        crawl_status['current_source'] = None


# ============ API路由 ============

@app.route('/')
def index():
    """主页"""
    return render_template('index.html')


@app.route('/api/crawlers', methods=['GET'])
def get_crawlers():
    """获取所有爬虫信息"""
    crawlers = []
    for name in crawler_manager.list_crawlers():
        crawler = crawler_manager.get_crawler(name)
        crawlers.append({
            'name': name,
            'display_name': name.upper(),
            'enabled': ENABLED_SOURCES.get(name, False),
            'type': crawler.__class__.__name__ if crawler else 'Unknown'
        })
    
    return jsonify({
        'success': True,
        'crawlers': crawlers
    })


@app.route('/api/status', methods=['GET'])
def get_status():
    """获取爬取状态"""
    return jsonify({
        'success': True,
        'status': {
            'running': crawl_status['running'],
            'current_source': crawl_status['current_source'],
            'progress': crawl_status['progress']
        }
    })


@app.route('/api/start', methods=['POST'])
def start_crawl():
    """启动爬取"""
    global crawl_thread
    
    if crawl_status['running']:
        return jsonify({
            'success': False,
            'message': '爬虫正在运行中'
        })
    
    data = request.json
    sources = data.get('sources', [])
    query = data.get('query', '')
    max_pages = data.get('max_pages', 5)
    
    if not sources:
        return jsonify({
            'success': False,
            'message': '请至少选择一个数据源'
        })
    
    # 清空之前的结果和日志
    crawl_status['results'] = {}
    log_collector.clear()
    
    # 启动后台线程
    crawl_thread = threading.Thread(
        target=crawl_task,
        args=(sources, query, max_pages)
    )
    crawl_thread.daemon = True
    crawl_thread.start()
    
    return jsonify({
        'success': True,
        'message': '爬取任务已启动'
    })


@app.route('/api/stop', methods=['POST'])
def stop_crawl():
    """停止爬取"""
    if not crawl_status['running']:
        return jsonify({
            'success': False,
            'message': '没有正在运行的任务'
        })
    
    crawl_status['running'] = False
    log_collector.add('warning', '用户手动停止爬取')
    
    return jsonify({
        'success': True,
        'message': '正在停止爬取任务...'
    })


@app.route('/api/logs', methods=['GET'])
def get_logs():
    """获取日志"""
    limit = request.args.get('limit', 100, type=int)
    logs = log_collector.get_logs(limit)
    
    return jsonify({
        'success': True,
        'logs': logs
    })


@app.route('/api/results', methods=['GET'])
def get_results():
    """获取爬取结果"""
    return jsonify({
        'success': True,
        'results': crawl_status['results']
    })


@app.route('/api/files', methods=['GET'])
def list_files():
    """列出已保存的文件"""
    raw_data_dir = Path(__file__).parent.parent / 'raw_data'
    files = []
    
    if raw_data_dir.exists():
        for source_dir in raw_data_dir.iterdir():
            if source_dir.is_dir():
                for file_path in source_dir.glob('*.json'):
                    stat = file_path.stat()
                    files.append({
                        'name': file_path.name,
                        'source': source_dir.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'path': str(file_path.relative_to(raw_data_dir.parent))
                    })
    
    # 按修改时间排序
    files.sort(key=lambda x: x['modified'], reverse=True)
    
    return jsonify({
        'success': True,
        'files': files
    })


@app.route('/api/config', methods=['GET'])
def get_config():
    """获取配置信息"""
    from crawlers import config
    
    return jsonify({
        'success': True,
        'config': {
            'enabled_sources': ENABLED_SOURCES,
            'request_timeout': config.REQUEST_TIMEOUT,
            'crawl_delay': config.CRAWL_DELAY,
            'max_retries': config.MAX_RETRIES
        }
    })


def training_task():
    """后台训练任务: 标注 -> 训练"""
    global training_status
    
    # 定义日志捕获类
    class DashboardLogHandler(logging.Handler):
        def emit(self, record):
            msg = self.format(record)
            training_status['logs'].append(msg)
            # 自动推进进度
            if "Epoch" in msg and "/" in msg:
                try:
                    epoch_part = msg.split("Epoch ")[1].split("/")[0]
                    total_epoch = msg.split("/")[1]
                    progress = 40 + (int(epoch_part) / int(total_epoch)) * 50
                    training_status['progress'] = int(progress)
                except: pass
    
    handler = DashboardLogHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    # 挂载到相关的 loggers
    loggers = [
        logging.getLogger("EvoPentest.Trainer"),
        logging.getLogger("AutoLabelerV2"),
        logging.getLogger("EvoPentest.Dataset")
    ]
    for l in loggers:
        l.addHandler(handler)
        l.setLevel(logging.INFO)

    try:
        training_status['running'] = True
        training_status['logs'] = []
        
        # 1. 自动标注阶段
        training_status['phase'] = 'labeling'
        training_status['message'] = '正在从攻击日志中提取 HER 经验样本...'
        training_status['progress'] = 10
        
        from processors.auto_labeler_v2 import ImprovedAutoLabeler
        labeler = ImprovedAutoLabeler()
        log_dir = Path(config.LOGS_DIR)
        dataset_path = config.DATA_DIR / "utility_dataset_balanced.jsonl"
        
        labeler.process_all_logs(log_dir, dataset_path)
        
        # 2. 模型训练阶段
        training_status['phase'] = 'training'
        training_status['message'] = '正在训练 Cross-Encoder 重排序模型...'
        training_status['progress'] = 40
        
        from processors.dataset import DatasetLoader
        from processors.trainer import CrossEncoderTrainer
        
        # 加载数据
        loader = DatasetLoader(dataset_path)
        samples = loader.load_from_jsonl()
        train_data, test_data = loader.split_dataset(samples)
        
        # 实例化训练器
        trainer = CrossEncoderTrainer()
        
        # 开始训练
        trainer.train(train_data, test_data)
        
        training_status['progress'] = 90
        
        training_status['phase'] = 'completed'
        training_status['message'] = '系统进化完成！Utility Scorer 已更新。'
        training_status['progress'] = 100
        training_status['logs'].append(">>> 进化流程结束。")

    except Exception as e:
        training_status['phase'] = 'error'
        training_status['message'] = f'训练异常: {str(e)}'
        training_status['logs'].append(f"❌ 错误: {str(e)}")
    
    finally:
        training_status['running'] = False
        for l in loggers:
            l.removeHandler(handler)


@app.route('/api/training/start', methods=['POST'])
def start_training():
    """启动模型训练"""
    global training_thread
    
    if training_status['running']:
        return jsonify({'success': False, 'message': '训练任务已在运行中'})
    
    training_thread = threading.Thread(target=training_task)
    training_thread.daemon = True
    training_thread.start()
    
    return jsonify({'success': True, 'message': '训练任务已启动'})


@app.route('/api/training/status', methods=['GET'])
def get_training_status():
    """获取训练状态"""
    return jsonify({
        'success': True,
        'status': training_status
    })


@app.route('/api/adaptive-search', methods=['POST'])
def adaptive_search():
    """自适应检索API - 真实使用 RAGFlow 语料库并回填经验"""
    if not ADAPTIVE_RETRIEVAL_AVAILABLE:
        return jsonify({
            'success': False,
            'message': '自适应检索模块未安装'
        })
    
    try:
        data = request.json
        query = data.get('query', '')
        max_iterations = data.get('max_iterations', 3)
        target_info = data.get('target_info', 'WebLogic Server 10.3.6')
        
        if not query:
            return jsonify({'success': False, 'message': '查询不能为空'})
        
        start_time = time.time()
        
        # 初始化需要的组件
        from processors.llm_client import DeepSeekClient
        from processors.adaptive_retriever import AdaptiveRetriever, UtilityScorer, RetrievalResult
        from processors.ragflow_client import RAGFlowClient
        from processors.evo_config import config as evo_config
        
        # 初始化客户端
        llm_client = DeepSeekClient(api_key=evo_config.DEEPSEEK_API_KEY)
        rf_client = RAGFlowClient(evo_config.RAGFLOW_API_KEY, evo_config.RAGFLOW_BASE_URL)
        
        # 定义真实检索函数 (读取语料库)
        def real_ragflow_search(q: str) -> List[RetrievalResult]:
            response = rf_client.search(
                query=q,
                dataset_id=evo_config.RAGFLOW_DATASET_ID,
                top_k=10
            )
            
            results = []
            chunks = response.get('data', {}).get('chunks', [])
            for item in chunks:
                results.append(RetrievalResult(
                    title=item.get('document_name', 'Unknown'),
                    content=item.get('content_with_weight', item.get('content', '')),
                    score=item.get('similarity', 0.0),
                    source='ragflow_corpus'
                ))
            return results
        
        # 创建自适应检索器
        retriever = AdaptiveRetriever(
            knowledge_base_search_func=real_ragflow_search,
            utility_scorer=UtilityScorer(model_path=evo_config.UTILITY_MODEL_PATH),
            max_iterations=max_iterations
        )
        
        # 设置 LLM 客户端
        retriever.llm_client = llm_client
        retriever.failure_detector.llm_client = llm_client
        retriever.diagnoser.llm_client = llm_client
        retriever.rewriter.llm_client = llm_client
        
        # 执行检索
        retrieval_result = retriever.retrieve(query=query, target_info=target_info)
        
        # 记录数据以便手动回填推送
        last_retrieval_data['query'] = query
        last_retrieval_data['result'] = retrieval_result
        
        # 如果检索成功, 自动回填经验到经验库
        backfill_status = "Not triggered"
        if retrieval_result.success:
            experience = retriever.summarize_experience(query, retrieval_result)
            push_success = rf_client.push_structured_summary(
                dataset_id=evo_config.RAGFLOW_EXPR_ID, # 经验库 ID
                title=f"Auto Experience: {query}",
                content=experience
            )
            backfill_status = "Success" if push_success else "Failed"
        
        # 封装响应
        workflow_trace = {
            'original_query': query,
            'success': retrieval_result.success,
            'final_query': retrieval_result.final_query,
            'backfill_status': backfill_status,
            'iterations': [],
            'final_results': [
                {'title': r.title, 'content': r.content, 'score': round(r.score, 3)} 
                for r in retrieval_result.reranked_results
            ],
            'total_time': int((time.time() - start_time) * 1000)
        }
        
        for step in retrieval_result.retrieval_history:
            workflow_trace['iterations'].append({
                'iteration': step.iteration,
                'query': step.query,
                'results_count': step.num_results,
                'is_failed': step.failure_detected,
                'diagnosis_type': step.diagnoses[0] if step.diagnoses else None,
                'rewritten_queries': step.rewritten_queries
            })
        
        return jsonify({
            'success': True,
            'data': workflow_trace
        })
        retriever.rewriter.llm_client = llm_client
        
        # 执行自适应检索主流程
        retrieval_result = retriever.retrieve(query=query)
        
        # 缓存数据以便后续总结推送
        last_retrieval_data['query'] = query
        last_retrieval_data['result'] = retrieval_result
        
        # 转换结果为前端响应格式
        workflow_trace = {
            'original_query': query,
            'success': retrieval_result.success,
            'final_query': retrieval_result.final_query,
            'iterations': [],
            'final_results': [
                {'title': r.title, 'content': r.content, 'score': round(r.score, 3)} 
                for r in retrieval_result.reranked_results
            ],
            'total_time': 0 # 统计在 retrieve 中处理
        }
        
        for step in retrieval_result.retrieval_history:
            workflow_trace['iterations'].append({
                'iteration': step.iteration,
                'query': step.query,
                'results_count': step.num_results,
                'is_failed': step.failure_detected,
                'diagnosis': {
                    'type': step.diagnoses[0] if step.diagnoses else "N/A",
                    'suggestion': "See log for details"
                } if step.failure_detected else None,
                'rewritten_queries': step.rewritten_queries
            })
        
        workflow_trace['total_time'] = int((time.time() - start_time) * 1000)
        return jsonify(workflow_trace)
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'错误: {str(e)}'
        })


@app.route('/api/ragflow/push_summary', methods=['POST'])
def push_ragflow_summary():
    """将最近一次检索的经验总结推送到 RAGFlow"""
    if not ADAPTIVE_RETRIEVAL_AVAILABLE:
        return jsonify({'success': False, 'message': '自适应检索系统未加载'})

    if not last_retrieval_data['result']:
        return jsonify({'success': False, 'message': '没有可总结的检索历史'})

    try:
        # 1. 产生总结 (System 2 反思)
        # 初始化需要的组件
        from processors.llm_client import DeepSeekClient
        from processors.adaptive_retriever import AdaptiveRetriever
        
        # 简单实例化用于生成总结
        retriever = AdaptiveRetriever(knowledge_base_search_func=lambda x: [])
        summary = retriever.summarize_experience(
            last_retrieval_data['query'], 
            last_retrieval_data['result']
        )
        
        # 2. 推送到 RAGFlow
        rf_client = RAGFlowClient(config.RAGFLOW_API_KEY, config.RAGFLOW_BASE_URL)
        success = rf_client.push_structured_summary(
            config.RAGFLOW_EXPR_ID,  # 修改为经验库 ID
            title=f"Experience: {last_retrieval_data['query']}",
            content=summary
        )
        
        if success:
            return jsonify({
                'success': True, 
                'summary': summary,
                'message': '经验已成功推送到 RAGFlow 经验库'
            })
        else:
            return jsonify({
                'success': False, 
                'message': '推送至 RAGFlow 失败，请检查配置或网络'
            })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/hindsight/data')
def get_hindsight_data():
    """获取事后经验回放数据"""
    try:
        data_path = Path(r"d:\渗透测试相关\语料库\语料\attack_kb\data\utility_dataset_balanced.jsonl")
        if not data_path.exists():
            return jsonify({'status': 'error', 'message': 'Dataset not found'})
        
        samples = []
        with open(data_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    samples.append(json.loads(line))
        
        # 返回最近的 100 条
        return jsonify({
            'status': 'success',
            'total': len(samples),
            'samples': samples[-100:]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/hindsight/stats')
def get_hindsight_stats():
    """获取数据标注统计"""
    try:
        log_dir = Path(r"d:\渗透测试相关\语料库\语料\logs")
        log_files = list(log_dir.glob("*.jsonl"))
        
        return jsonify({
            'status': 'success',
            'log_files_count': len(log_files),
            'last_processed': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


if __name__ == '__main__':
    print("="*80)
    print("🚀 爬虫管理Web界面启动")
    print("="*80)
    print("访问地址: http://localhost:5000")
    if ADAPTIVE_RETRIEVAL_AVAILABLE:
        print("✅ 自适应检索系统已加载")
    else:
        print("⚠️  自适应检索系统未加载")
    print("="*80)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=True
    )
