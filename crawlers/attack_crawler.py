"""
MITRE ATT&CK爬虫模块 - 集成 attack_kb 知识库构建系统
"""

import json
import time
import os
import sys
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

# 添加父目录到路径以导入base_crawler
sys.path.insert(0, str(Path(__file__).parent.parent))

from crawlers.base_crawler import BaseCrawler

class MITREAttackCrawler(BaseCrawler):
    """MITRE ATT&CK 知识库集成爬虫"""
    
    def __init__(self, session=None):
        super().__init__(session)
        self.source_name = 'attack'
        # 定位 attack_kb 目录 (在 crawlers 的同级目录)
        self.kb_root = Path(__file__).parent / "attack_core"
    
    def get_source_name(self) -> str:
        """返回数据源名称"""
        return self.source_name
    
    def crawl(self, query: str = "", **kwargs) -> List[Dict[str, Any]]:
        """
        执行 ATT&CK 知识库构建流程
        
        Args:
            query: 搜索关键词（用于过滤结果）
            **kwargs: 其他参数
        
        Returns:
            List[Dict]: 构建的知识库对象列表
        """
        print(f"\n{'='*80}")
        print(f"🛡️ MITRE ATT&CK 知识库构建")
        print(f"{'='*80}")
        
        if not self.kb_root.exists():
            print(f"❌ 错误: 找不到 attack_kb 目录: {self.kb_root}")
            return []

        # 保存当前工作目录和 sys.path
        original_cwd = os.getcwd()
        original_path = sys.path[:]
        
        results = []
        
        try:
            # 切换到 attack_kb 目录，确保其内部相对路径正常工作
            print(f"📂 切换工作目录到: {self.kb_root}")
            os.chdir(self.kb_root)
            
            # 将 attack_kb 添加到 sys.path
            if str(self.kb_root) not in sys.path:
                sys.path.insert(0, str(self.kb_root))
            
            # 1. 运行 STIX 静态抽取
            print("\n[1/1] 运行 STIX 静态抽取...")
            try:
                from stix.extract_stix import main as extract_main
                extract_main()
            except ImportError as e:
                print(f"❌ 导入 STIX 模块失败: {e}")
            except Exception as e:
                print(f"❌ STIX 抽取失败: {e}")

            # 2. 加载结果
            print("\n📊 加载构建结果...")

            try:
                import config
                stix_dir = Path(config.STIX_OUTPUT_DIR)
            except ImportError:
                print("⚠️  无法导入 config，使用默认路径")
                stix_dir = Path("data/stix")

            # 尝试加载 enterprise 域的处理后数据
            output_file = stix_dir / "enterprise-attack-processed.json"
            if output_file.exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # 处理不同的 JSON 结构
                    if isinstance(data, list):
                        results = data
                    elif isinstance(data, dict):
                        if 'objects' in data:
                            results = data['objects']
                        else:
                            # 可能是字典形式的 ID -> Object
                            results = list(data.values())
                
                print(f"✓ 成功加载 {len(results)} 条 ATT&CK 对象")
            else:
                print(f"⚠️  未找到结果文件: {output_file}")

            # 5. 关键词过滤
            if query and results:
                print(f"🔍 应用关键词过滤: '{query}'")
                filtered = []
                for item in results:
                    # 将对象转换为字符串进行搜索
                    item_str = json.dumps(item, ensure_ascii=False).lower()
                    if query.lower() in item_str:
                        filtered.append(item)
                results = filtered
                print(f"✓ 过滤后剩余 {len(results)} 条记录")

            return results

        except Exception as e:
            print(f"❌ ATT&CK 任务执行出错: {e}")
            import traceback
            traceback.print_exc()
            return []
            
        finally:
            # 恢复环境
            os.chdir(original_cwd)
            sys.path = original_path
            print(f"\n🔄 已恢复工作目录到: {original_cwd}")

    def get_latest_articles(self, max_items: int = None, fetch_content: bool = True) -> List[Dict[str, Any]]:
        """获取最新数据 (触发完整构建)"""
        return self.crawl()

    def search_by_keyword(self, keyword: str, fetch_content: bool = True) -> List[Dict[str, Any]]:
        """搜索数据"""
        return self.crawl(query=keyword)

