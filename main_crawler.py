"""
main_crawler.py  向后兼容 shim

真正代码已移至 crawlers/main_crawler.py。
保留此文件仅为兼容旧路径调用（如 `python main_crawler.py`）。

推荐使用新路径：
    python crawlers/main_crawler.py [options]
"""
import runpy
from pathlib import Path

if __name__ == "__main__":
    runpy.run_path(
        str(Path(__file__).parent / "crawlers" / "main_crawler.py"),
        run_name="__main__",
    )
