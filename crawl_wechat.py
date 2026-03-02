"""向后兼容 shim — 真正代码已移至 crawlers/wechat_crawler/sogou_crawler.py"""
import runpy
from pathlib import Path

if __name__ == '__main__':
    runpy.run_path(
        str(Path(__file__).parent / 'crawlers' / 'wechat_crawler' / 'sogou_crawler.py'),
        run_name='__main__',
    )
