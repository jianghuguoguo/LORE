"""
爬虫管理器 - 统一调度所有数据源爬虫
支持动态注册和管理多个爬虫实例
"""

import json
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
import requests

from crawlers.base_crawler import BaseCrawler
from crawlers.csdn_crawler import CSDNVIPCrawler
from crawlers.github_crawler import GitHubCrawler
from crawlers.qianxin_crawler import QiAnXinCrawler
from crawlers.xianzhi_crawler import XianZhiCrawler
from crawlers.config import (
    ENABLED_SOURCES, OUTPUT_BASE_DIR,
    RSS_FEEDS, RSS_MAX_ITEMS_PER_FEED,
)

# WeChat 爬虫（搜狗模式）通过 wechat_crawler 子包独立调度，不在这里注册

# RAGFlow 暂不可用，数据直接保存到 raw_data/ 目录
PUSH_TO_RAGFLOW = False
RAGFLOW_ONLY    = False
RAGFLOW_API_KEY = ""
RAGFLOW_BASE_URL = ""
RAGFLOW_DATASET_ID = ""


class RAGFlowClient:
    """RAGFlow 占位存根 — 当前不可用，所有操作静默忽略。"""
    def __init__(self, *a, **kw): pass
    def push_json_experience(self, *a, **kw): return False
    def push_document(self, *a, **kw): return False
    def upload_document(self, *a, **kw): return False


class CrawlerManager:
    """爬虫管理器 - 统一管理所有数据源"""
    
    def __init__(self):
        """初始化管理器"""
        self.session = requests.Session()
        self.crawlers: Dict[str, BaseCrawler] = {}
        self._register_default_crawlers()
        
        # 初始化 RAGFlow 客户端
        self.ragflow_client = None
        if PUSH_TO_RAGFLOW and RAGFLOW_API_KEY:
            try:
                self.ragflow_client = RAGFlowClient(RAGFLOW_API_KEY, RAGFLOW_BASE_URL)
                print(f"✅ RAGFlow 联动已启动: {RAGFLOW_BASE_URL}")
            except Exception as e:
                print(f"❌ RAGFlow 客户端初始化失败: {e}")
    
    def _register_default_crawlers(self):
        """注册默认的爬虫"""
        if ENABLED_SOURCES.get('csdn', True):
            self.register_crawler('csdn', CSDNVIPCrawler(self.session))

        if ENABLED_SOURCES.get('github', True):
            self.register_crawler('github', GitHubCrawler(self.session))

        if ENABLED_SOURCES.get('qianxin', True):
            self.register_crawler('qianxin', QiAnXinCrawler(self.session))

        if ENABLED_SOURCES.get('xianzhi', True):
            self.register_crawler('xianzhi', XianZhiCrawler(self.session))

        # RSS 轻量级爬虫（默认全部开启）
        if ENABLED_SOURCES.get('rss', True):
            try:
                from crawlers.rss_crawler import RSSCrawler
                for feed_name, feed_url in RSS_FEEDS.items():
                    # xianzhi/qianxin 已有独立深度爬虫，这里跳过重复注册
                    rss_key = f"rss_{feed_name}"
                    self.register_crawler(rss_key, RSSCrawler(feed_name, feed_url))
            except ImportError:
                pass
    
    def register_crawler(self, name: str, crawler: BaseCrawler):
        """
        注册新的爬虫
        
        Args:
            name: 爬虫名称（唯一标识）
            crawler: 爬虫实例（必须继承BaseCrawler）
        """
        if not isinstance(crawler, BaseCrawler):
            raise TypeError(f"爬虫必须继承自BaseCrawler，当前类型: {type(crawler)}")
        
        self.crawlers[name] = crawler
        print(f"[注册] 已注册爬虫: {name}")
    
    def unregister_crawler(self, name: str):
        """
        注销爬虫
        
        Args:
            name: 爬虫名称
        """
        if name in self.crawlers:
            del self.crawlers[name]
            print(f"[注销] 已注销爬虫: {name}")
    
    def get_crawler(self, name: str) -> Optional[BaseCrawler]:
        """
        获取指定爬虫
        
        Args:
            name: 爬虫名称
            
        Returns:
            爬虫实例或None
        """
        return self.crawlers.get(name)
    
    def list_crawlers(self) -> List[str]:
        """
        列出所有已注册的爬虫
        
        Returns:
            爬虫名称列表
        """
        return list(self.crawlers.keys())
    
    def crawl_single_source(self, source: str, query: str, **kwargs) -> List[Dict[str, Any]]:
        """
        爬取单个数据源
        
        Args:
            source: 数据源名称
            query: 搜索关键词
            **kwargs: 传递给爬虫的其他参数
            
        Returns:
            爬取结果列表
        """
        crawler = self.get_crawler(source)
        if not crawler:
            print(f"[错误] 未找到爬虫: {source}")
            return []
        
        try:
            results = crawler.crawl(query, **kwargs)
            return results
        except Exception as e:
            print(f"[异常] {source} 爬取失败: {e}")
            return []
    
    def crawl_all_sources(self, query: str, **kwargs) -> Dict[str, List[Dict[str, Any]]]:
        """
        爬取所有启用的数据源
        
        Args:
            query: 搜索关键词
            **kwargs: 传递给爬虫的其他参数
            
        Returns:
            Dict[源名称, 结果列表]
        """
        results = {}
        
        print(f"\n{'='*80}")
        print(f"🚀 多源爬虫管理器启动")
        print(f"搜索关键词: {query}")
        print(f"已启用数据源: {self.list_crawlers()}")
        print(f"{'='*80}\n")
        
        for source_name, crawler in self.crawlers.items():
            print(f"\n{'='*80}")
            print(f"📊 正在爬取: {source_name.upper()}")
            print(f"{'='*80}")
            
            try:
                source_results = crawler.crawl(query, **kwargs)
                results[source_name] = source_results
                print(f"\n✅ {source_name} 完成: {len(source_results)} 条结果")
            except Exception as e:
                print(f"\n❌ {source_name} 爬取失败: {e}")
                results[source_name] = []
        
        # 打印总结
        self._print_summary(results)
        
        return results
    
    def _print_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """打印爬取总结"""
        print(f"\n{'='*80}")
        print("📊 爬取总结")
        print(f"{'='*80}")
        
        total_results = 0
        for source, data in results.items():
            count = len(data)
            total_results += count
            status = "✅" if count > 0 else "⚠️"
            print(f"{status} {source.upper():<15} {count:>5} 条")
        
        print(f"{'='*80}")
        print(f"总计: {total_results} 条")
        print(f"{'='*80}\n")
    
    def save_results(self, results: Dict[str, List[Dict[str, Any]]], 
                    query: str, output_dir: Optional[str] = None):
        """
        保存爬取结果
        
        Args:
            results: 爬取结果字典
            query: 搜索关键词（用于文件命名）
            output_dir: 输出目录
        """
        # 1. 优先推送到 RAGFlow
        if self.ragflow_client and PUSH_TO_RAGFLOW:
            print(f"\n🚀 正在推送结果到 RAGFlow 经验库...")
            for source, data in results.items():
                if data:
                    filename = f"{query}_{source}"
                    success = self.ragflow_client.push_json_experience(
                        RAGFLOW_DATASET_ID, 
                        data, 
                        filename_prefix=filename
                    )
                    if success:
                        print(f"✅ {source} 结果已成功推送至 RAGFlow")
                    else:
                        print(f"❌ {source} 结果推送失败")

        # 2. 如果开启了 RAGFLOW_ONLY 并且 RAGFlow 推送已配置，则跳过本地保存
        if RAGFLOW_ONLY and self.ragflow_client:
            print("ℹ️ RAGFLOW_ONLY 模式已启用，跳过本地 raw_data 保存。")
            return

        # 3. 本地保存逻辑 (原本的逻辑)
        if output_dir is None:
            output_dir = OUTPUT_BASE_DIR
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # 为每个数据源单独保存
        for source, data in results.items():
            if data:  # 只保存有数据的源
                filename = f"{query}_{source}_{timestamp}.json"
                filepath = output_path / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                print(f"💾 {source} 结果已保存至: {filepath}")
                
                print(f"[保存] {source}: {filepath}")
    
    def crawl_and_save(self, query: str, output_dir: Optional[str] = None, **kwargs):
        """
        爬取并保存结果（便捷方法）
        
        Args:
            query: 搜索关键词
            output_dir: 输出目录
            **kwargs: 传递给爬虫的其他参数
        """
        results = self.crawl_all_sources(query, **kwargs)
        self.save_results(results, query, output_dir)
        return results
    
    def register_crawler(self, name: str, crawler: BaseCrawler):
        """
        注册新的爬虫
        
        Args:
            name: 爬虫名称（唯一标识）
            crawler: 爬虫实例（必须继承BaseCrawler）
        """
        if not isinstance(crawler, BaseCrawler):
            raise TypeError(f"爬虫必须继承自BaseCrawler，当前类型: {type(crawler)}")
        
        self.crawlers[name] = crawler
        print(f"[注册] 已注册爬虫: {name}")
    
    def unregister_crawler(self, name: str):
        """
        注销爬虫
        
        Args:
            name: 爬虫名称
        """
        if name in self.crawlers:
            del self.crawlers[name]
            print(f"[注销] 已注销爬虫: {name}")
    
    def get_crawler(self, name: str) -> Optional[BaseCrawler]:
        """
        获取指定爬虫
        
        Args:
            name: 爬虫名称
            
        Returns:
            爬虫实例或None
        """
        return self.crawlers.get(name)
    
    def list_crawlers(self) -> List[str]:
        """
        列出所有已注册的爬虫
        
        Returns:
            爬虫名称列表
        """
        return list(self.crawlers.keys())
    
    def crawl_single_source(self, source: str, query: str, **kwargs) -> List[Dict[str, Any]]:
        """
        爬取单个数据源
        
        Args:
            source: 数据源名称
            query: 搜索关键词
            **kwargs: 传递给爬虫的其他参数
            
        Returns:
            爬取结果列表
        """
        crawler = self.get_crawler(source)
        if not crawler:
            print(f"[错误] 未找到爬虫: {source}")
            return []
        
        try:
            results = crawler.crawl(query, **kwargs)
            return results
        except Exception as e:
            print(f"[异常] {source} 爬取失败: {e}")
            return []
    
    def crawl_all_sources(self, query: str, **kwargs) -> Dict[str, List[Dict[str, Any]]]:
        """
        爬取所有启用的数据源
        
        Args:
            query: 搜索关键词
            **kwargs: 传递给爬虫的其他参数
            
        Returns:
            Dict[源名称, 结果列表]
        """
        results = {}
        
        print(f"\n{'='*80}")
        print(f"🚀 多源爬虫管理器启动")
        print(f"搜索关键词: {query}")
        print(f"已启用数据源: {self.list_crawlers()}")
        print(f"{'='*80}\n")
        
        for source_name, crawler in self.crawlers.items():
            print(f"\n{'='*80}")
            print(f"📊 正在爬取: {source_name.upper()}")
            print(f"{'='*80}")
            
            try:
                source_results = crawler.crawl(query, **kwargs)
                results[source_name] = source_results
                print(f"\n✅ {source_name} 完成: {len(source_results)} 条结果")
            except Exception as e:
                print(f"\n❌ {source_name} 爬取失败: {e}")
                results[source_name] = []
        
        # 打印总结
        self._print_summary(results)
        
        return results
    
    def _print_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """打印爬取总结"""
        print(f"\n{'='*80}")
        print("📊 爬取总结")
        print(f"{'='*80}")
        
        total_results = 0
        for source, data in results.items():
            count = len(data)
            total_results += count
            status = "✅" if count > 0 else "⚠️"
            print(f"{status} {source.upper():<15} {count:>5} 条")
        
        print(f"{'='*80}")
        print(f"总计: {total_results} 条")
        print(f"{'='*80}\n")
    
    def save_results(self, results: Dict[str, List[Dict[str, Any]]], 
                    query: str, output_dir: Optional[str] = None):
        """
        保存爬取结果
        
        Args:
            results: 爬取结果字典
            query: 搜索关键词（用于文件命名）
            output_dir: 输出目录，默认使用配置中的目录
        """
        if output_dir is None:
            output_dir = OUTPUT_BASE_DIR
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # 简单的文件名净化
        safe_query = "".join([c if c.isalnum() or c in ('-', '_', '.') else '_' for c in query])
        
        # 为每个数据源单独保存
        for source, data in results.items():
            if data:  # 只保存有数据的源
                filename = f"{safe_query}_{source}_{timestamp}.json"
                filepath = output_path / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                
                print(f"[保存] {source}: {filepath}")
    
    def crawl_and_save(self, query: str, output_dir: Optional[str] = None, **kwargs):
        """
        爬取并保存结果（便捷方法）
        
        Args:
            query: 搜索关键词
            output_dir: 输出目录
            **kwargs: 传递给爬虫的其他参数
        """
        results = self.crawl_all_sources(query, **kwargs)
        self.save_results(results, query, output_dir)
        return results


def main():
    """示例：使用爬虫管理器"""
    # 创建管理器
    manager = CrawlerManager()
    
    # 查看已注册的爬虫
    print(f"已注册的爬虫: {manager.list_crawlers()}")
    
    # 爬取并保存
    query = 'CVE-2021-29442'
    manager.crawl_and_save(
        query=query,
        max_pages=3,  # CSDN参数
        output_dir='multi_source_output'
    )


if __name__ == "__main__":
    main()
