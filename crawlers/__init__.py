"""爬虫包导出。

避免在包导入阶段级联加载所有爬虫实现，防止某个可选依赖缺失时
连 ``crawlers.wechat_crawler`` 这样的子包也无法导入。
"""

from importlib import import_module

_EXPORTS = {
    'BaseCrawler': ('crawlers.base_crawler', 'BaseCrawler'),
    'CSDNVIPCrawler': ('crawlers.csdn_crawler', 'CSDNVIPCrawler'),
    'MITREAttackCrawler': ('crawlers.attack_crawler', 'MITREAttackCrawler'),
    'GitHubCrawler': ('crawlers.github_crawler', 'GitHubCrawler'),
    'CrawlerManager': ('crawlers.crawler_manager', 'CrawlerManager'),
}

__all__ = list(_EXPORTS)
__version__ = '2.0.0'


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
    module_name, attr_name = _EXPORTS[name]
    module = import_module(module_name)
    return getattr(module, attr_name)


def __dir__():
    return sorted(list(globals()) + __all__)
