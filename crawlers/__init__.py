"""
爬虫模块初始化文件
导出所有爬虫类和管理器
"""

from crawlers.base_crawler import BaseCrawler
from crawlers.csdn_crawler import CSDNVIPCrawler
from crawlers.attack_crawler import MITREAttackCrawler
from crawlers.github_crawler import GitHubCrawler
from crawlers.crawler_manager import CrawlerManager

__all__ = [
    'BaseCrawler',
    'CSDNVIPCrawler',
    'MITREAttackCrawler',
    'GitHubCrawler',
    'CrawlerManager',
]

__version__ = '2.0.0'
