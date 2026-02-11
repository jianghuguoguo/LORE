"""
示例：添加新数据源的模板
这是一个完整的示例，展示如何创建自定义爬虫
"""

import sys
from pathlib import Path
from typing import Dict, List, Any
import time

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from crawlers.base_crawler import BaseCrawler


class ExampleCrawler(BaseCrawler):
    """
    示例爬虫 - 用作创建新爬虫的模板
    
    使用方法:
        crawler = ExampleCrawler()
        results = crawler.crawl('CVE-2024-12345')
    """
    
    def __init__(self, session=None):
        """初始化爬虫"""
        super().__init__(session)
        
        # 添加自定义配置
        self.api_url = "https://api.example.com/search"
        self.max_results = 100
        
        # 设置自定义请求头
        self.session.headers.update({
            'X-Custom-Header': 'value',
        })
    
    def get_source_name(self) -> str:
        """
        返回数据源名称
        这个名称将用于标识结果的来源
        """
        return 'example'
    
    def search_data(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        搜索数据的具体实现
        
        Args:
            query: 搜索关键词
            limit: 最大结果数
            
        Returns:
            原始数据列表
        """
        print(f"[Example] 开始搜索: {query}")
        
        results = []
        
        # 构建请求参数
        params = {
            'q': query,
            'limit': limit
        }
        
        try:
            # 使用 safe_request 发送请求（自动重试）
            response = self.safe_request(
                self.api_url,
                timeout=30,
                params=params
            )
            
            if response is None:
                print("[Example] 请求失败")
                return results
            
            # 解析响应
            data = response.json()
            items = data.get('items', [])
            
            # 提取需要的字段
            for item in items:
                results.append({
                    'title': item.get('title', ''),
                    'url': item.get('url', ''),
                    'content': item.get('content', ''),
                    'published_date': item.get('date', ''),
                    'author': item.get('author', ''),
                    'tags': item.get('tags', [])
                })
            
            print(f"[Example] 找到 {len(results)} 条结果")
            
        except Exception as e:
            print(f"[Example] 搜索异常: {e}")
        
        return results
    
    def extract_detail(self, url: str) -> Dict[str, Any]:
        """
        提取详细信息（可选）
        
        Args:
            url: 详情页URL
            
        Returns:
            详细信息字典
        """
        print(f"[Example] 提取详情: {url}")
        
        detail = {}
        
        try:
            response = self.safe_request(url, timeout=30)
            if response:
                # 解析详情页
                # 这里可以使用BeautifulSoup等工具
                detail = {
                    'full_content': 'extracted content',
                    'metadata': {}
                }
        except Exception as e:
            print(f"[Example] 提取详情失败: {e}")
        
        return detail
    
    def crawl(self, query: str, **kwargs) -> List[Dict[str, Any]]:
        """
        主爬取函数 - 必须实现
        
        Args:
            query: 搜索关键词
            **kwargs: 其他可选参数
                - max_results: 最大结果数
                - with_detail: 是否提取详情
            
        Returns:
            标准化的结果列表
        """
        print(f"\n{'='*60}")
        print(f"🔍 Example爬虫启动")
        print(f"搜索关键词: {query}")
        print(f"{'='*60}\n")
        
        # 获取参数
        max_results = kwargs.get('max_results', self.max_results)
        with_detail = kwargs.get('with_detail', False)
        
        # 搜索数据
        raw_results = self.search_data(query, limit=max_results)
        
        if not raw_results:
            print("[Example] 未找到结果")
            return []
        
        # 处理结果
        processed_results = []
        
        for i, item in enumerate(raw_results, 1):
            # 基础信息
            result = {
                'title': item['title'],
                'link': item['url'],
                'date': item['published_date'],
                'summary': item['content'][:500],  # 截取前500字符作为摘要
                'type': 'example-post',
                'site': self.get_source_name(),
                'author': item['author'],
                'tags': item['tags']
            }
            
            # 如果需要，提取详细信息
            if with_detail and item['url']:
                detail = self.extract_detail(item['url'])
                result['detail'] = detail
                time.sleep(1)  # 避免请求过快
            
            # 标准化结果
            standardized = self.standardize_result(result)
            processed_results.append(standardized)
            
            # 显示进度
            self.print_progress(i, len(raw_results), f"处理: {item['title'][:50]}...")
        
        # 去重
        unique_results = self.deduplicate_results(processed_results)
        
        print(f"\n[Example] 爬取完成，共 {len(unique_results)} 条结果（去重后）")
        print("="*60)
        
        return unique_results


def main():
    """测试示例爬虫"""
    crawler = ExampleCrawler()
    
    # 测试爬取
    results = crawler.crawl(
        query='test query',
        max_results=10,
        with_detail=False
    )
    
    # 打印结果
    print(f"\n获取到 {len(results)} 条结果:")
    for i, result in enumerate(results[:3], 1):  # 只打印前3条
        print(f"\n{i}. {result['title']}")
        print(f"   链接: {result['link']}")
        print(f"   摘要: {result['summary'][:100]}...")


if __name__ == "__main__":
    main()
