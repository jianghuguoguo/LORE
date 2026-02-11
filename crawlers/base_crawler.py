"""
基础爬虫抽象类
定义所有爬虫的统一接口和公共方法
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import requests
from fake_useragent import UserAgent
import time


class BaseCrawler(ABC):
    """爬虫基类 - 所有爬虫必须继承此类"""
    
    def __init__(self, session: Optional[requests.Session] = None):
        """
        初始化基础爬虫
        
        Args:
            session: 复用的requests会话，如果为None则创建新会话
        """
        self.session = session or requests.Session()
        self.ua = UserAgent()
        self.setup_session()
    
    def setup_session(self):
        """设置会话基础配置"""
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })
    
    @abstractmethod
    def crawl(self, query: str, **kwargs) -> List[Dict[str, Any]]:
        """
        执行爬取任务（所有子类必须实现）
        
        Args:
            query: 搜索关键词
            **kwargs: 其他可选参数
            
        Returns:
            List[Dict]: 爬取结果列表
        """
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        """
        获取数据源名称（所有子类必须实现）
        
        Returns:
            str: 数据源名称，如 'csdn', 'github', 'attack'
        """
        pass
    
    def validate_result(self, result: Dict[str, Any]) -> bool:
        """
        验证单条结果的有效性
        
        Args:
            result: 单条爬取结果
            
        Returns:
            bool: 是否有效
        """
        required_fields = ['title', 'link', 'summary']
        return all(field in result and result[field] for field in required_fields)
    
    def standardize_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        标准化输出格式
        
        Args:
            result: 原始结果
            
        Returns:
            Dict: 标准化后的结果
        """
        standardized = {
            'title': result.get('title', ''),
            'link': result.get('link', ''),
            'date': result.get('date', ''),
            'summary': result.get('summary', ''),
            'type': result.get('type', 'unknown'),
            'site': self.get_source_name(),
            'scraped_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 保留原始数据的其他字段
        for key, value in result.items():
            if key not in standardized:
                standardized[key] = value
        
        return standardized
    
    def deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        基于link去重
        
        Args:
            results: 原始结果列表
            
        Returns:
            List[Dict]: 去重后的结果
        """
        seen_urls = set()
        unique_results = []
        
        for result in results:
            link = result.get('link', '')
            if link and link not in seen_urls:
                seen_urls.add(link)
                unique_results.append(result)
        
        return unique_results
    
    def safe_request(self, url: str, timeout: int = 30, **kwargs) -> Optional[requests.Response]:
        """
        安全的HTTP请求（带重试机制）
        
        Args:
            url: 请求URL
            timeout: 超时时间
            **kwargs: requests的其他参数
            
        Returns:
            Response对象或None
        """
        max_retries = 3
        
        for retry in range(max_retries):
            try:
                response = self.session.get(url, timeout=timeout, **kwargs)
                response.raise_for_status()
                return response
            except requests.exceptions.RequestException as e:
                if retry < max_retries - 1:
                    wait_time = 2 ** retry  # 指数退避
                    print(f"   [重试] {retry + 1}/{max_retries}: {e}, 等待{wait_time}秒...")
                    time.sleep(wait_time)
                else:
                    print(f"   [失败] 请求失败: {e}")
                    return None
        
        return None
    
    def print_progress(self, current: int, total: int, message: str = ""):
        """
        打印进度信息
        
        Args:
            current: 当前进度
            total: 总数
            message: 附加消息
        """
        percentage = (current / total * 100) if total > 0 else 0
        progress_bar = f"[{current}/{total}] ({percentage:.1f}%)"
        print(f"{progress_bar} {message}")
