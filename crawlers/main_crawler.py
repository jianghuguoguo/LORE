"""
crawlers/main_crawler.py
========================
多源爬虫系统 — 主入口（交互式 / 命令行双模式）

使用方法（从 LORE/ 根目录运行）:
    python crawlers/main_crawler.py              # 交互式选择数据源
    python crawlers/main_crawler.py --all        # 爬取所有数据源
    python crawlers/main_crawler.py --sources csdn,github -q CVE-2024-23897

向后兼容：调用根目录的 main_crawler.py 同样有效（shim 转发至此文件）。
"""

import sys
from pathlib import Path

# Windows GBK 控制台 / 子进程中强制使用 UTF-8，避免 emoji 等字符 UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# 确保 LORE/ 与 crawlers/ 均在 sys.path，支持 package 与直接执行两种方式
_HERE = Path(__file__).parent          # crawlers/
_ROOT = _HERE.parent                   # LORE/
for _p in [str(_ROOT), str(_HERE)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

import argparse
from crawlers.crawler_manager import CrawlerManager
from crawlers.config import ENABLED_SOURCES


def run_rss_sync_once(query: str = "") -> None:
    """触发一次 RSS 增量同步（不启动调度器）。"""
    from crawlers.rss_crawler import RSSAggregator
    agg = RSSAggregator()
    agg.fetch_all(query=query, save=True)


def select_sources_interactive(available_sources: list) -> list:
    """交互式选择数据源"""
    print("\n" + "="*80)
    print("可用的数据源:")
    print("="*80)

    for i, source in enumerate(available_sources, 1):
        status = "已启用" if ENABLED_SOURCES.get(source, False) else "未启用"
        print(f"{i}. {source.upper():15s} [{status}]")

    print(f"{len(available_sources) + 1}. 全部数据源")
    print("="*80)

    while True:
        choice = input("\n请选择要爬取的数据源 (输入数字，多个用逗号分隔，或 'q' 退出): ").strip()

        if choice.lower() == 'q':
            print("退出程序")
            return []

        try:
            choices = [int(x.strip()) for x in choice.split(',')]

            selected = []
            for num in choices:
                if num == len(available_sources) + 1:
                    return available_sources
                elif 1 <= num <= len(available_sources):
                    source = available_sources[num - 1]
                    if source not in selected:
                        selected.append(source)
                else:
                    print(f"  无效选项: {num}")
                    continue

            if selected:
                return selected
            else:
                print("  请至少选择一个数据源")

        except ValueError:
            print("  输入格式错误，请输入数字（如: 1,2,3）")


def get_search_query() -> tuple:
    """获取搜索关键词和参数（交互式）"""
    print("\n" + "="*80)
    print("设置搜索参数")
    print("="*80)

    query = input("请输入搜索关键词 (直接回车表示无关键词): ").strip()
    if not query:
        print("  未指定关键词，将爬取数据源的所有内容")

    while True:
        try:
            max_pages_input = input("最大爬取页数 (默认 5): ").strip()
            max_pages = int(max_pages_input) if max_pages_input else 5
            if max_pages > 0:
                break
            print("  页数必须大于 0")
        except ValueError:
            print("  请输入有效数字")

    output_dir_input = input("输出目录 (默认 raw_data，回车使用默认值): ").strip()
    output_dir = output_dir_input if output_dir_input else 'raw_data'

    return query, max_pages, output_dir


def main():
    """主函数 — 交互式 / 命令行双模式爬虫入口"""

    parser = argparse.ArgumentParser(
        description="LORE 多源爬虫系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 交互式选择数据源
  python crawlers/main_crawler.py

  # 爬取所有数据源
  python crawlers/main_crawler.py --all -q CVE-2024-23897

  # 指定数据源
  python crawlers/main_crawler.py --sources csdn,github -q CVE-2024-23897 --max-pages 10

  # 快速模式（跳过确认）
  python crawlers/main_crawler.py --all -q CVE-2024-23897 --yes

  # 手动触发一次 RSS 增量同步
  python crawlers/main_crawler.py --rss-sync
  python crawlers/main_crawler.py --rss-sync -q 内网渗透

  # 启动 RSS 定时调度器（每 2 小时轮询一次）
  python crawlers/rss_scheduler.py
        """
    )

    parser.add_argument('--all', action='store_true', help='爬取所有已启用的数据源')
    parser.add_argument('--sources', type=str, help='指定数据源，逗号分隔 (如: csdn,github,attack)')
    parser.add_argument('-q', '--query', type=str, help='搜索关键词')
    parser.add_argument('--max-pages', type=int, default=5, help='最大爬取页数 (默认 5)')
    parser.add_argument('-o', '--output', default='multi_source_output', help='输出目录 (默认 multi_source_output)')
    parser.add_argument('-y', '--yes', action='store_true', help='跳过确认提示')
    parser.add_argument('--rss-sync', action='store_true',
                        help='立即执行一次 RSS 增量同步，完成后退出')

    args = parser.parse_args()

    # RSS 同步快速通道
    if args.rss_sync:
        run_rss_sync_once(query=args.query or "")
        return

    # 创建爬虫管理器
    manager = CrawlerManager()
    available_sources = manager.list_crawlers()

    if not available_sources:
        print("[!] 错误: 没有可用的爬虫")
        return

    print("\n" + "="*80)
    print("LORE — 多源爬虫系统")
    print("="*80)
    print(f"已注册爬虫: {', '.join(available_sources)}")
    print("="*80)

    # 确定要使用的数据源
    if args.all:
        selected_sources = available_sources
        print(f"\n  已选择所有数据源: {', '.join(selected_sources)}")
    elif args.sources:
        requested = [s.strip().lower() for s in args.sources.split(',')]
        selected_sources = [s for s in requested if s in available_sources]

        if not selected_sources:
            print(f"[!] 错误: 指定的数据源均不可用")
            print(f"    可用数据源: {', '.join(available_sources)}")
            return

        invalid = [s for s in requested if s not in available_sources]
        if invalid:
            print(f"[!] 警告: 以下数据源不可用: {', '.join(invalid)}")

        print(f"\n  已选择数据源: {', '.join(selected_sources)}")
    else:
        selected_sources = select_sources_interactive(available_sources)
        if not selected_sources:
            return
        print(f"\n  已选择: {', '.join(selected_sources)}")

    # 获取搜索参数
    # 只要明确通过命令行指定了数据源或快速模式，就走非交互分支。
    non_interactive_mode = args.query is not None or args.sources is not None or args.all or args.yes
    if non_interactive_mode:
        query = args.query if args.query is not None else ""
        max_pages = args.max_pages
        output_dir = args.output
        if query:
            print(f"\n  搜索关键词: {query}")
        else:
            print(f"\n  无关键词模式: 爬取所有内容")
        print(f"  最大爬取页数: {max_pages}")
        print(f"  输出目录: {output_dir}")
    else:
        query, max_pages, output_dir = get_search_query()

    # 确认执行
    if not args.yes:
        print("\n" + "="*80)
        print("爬取任务配置:")
        print("="*80)
        print(f"  数据源: {', '.join(selected_sources)}")
        print(f"  关键词: {query if query else '(无，爬取所有内容)'}")
        print(f"  最大页数: {max_pages}")
        print(f"  输出目录: {output_dir}")
        print("="*80)

        confirm = input("\n是否开始爬取? (y/n): ").strip().lower()
        if confirm != 'y':
            print("已取消")
            return

    # 执行爬取
    print("\n" + "="*80)
    print("开始爬取...")
    print("="*80)

    try:
        results = {}
        for source in selected_sources:
            print(f"\n>>> 爬取 {source.upper()} ...")
            result = manager.crawl_single_source(
                source,
                query,
                max_pages=max_pages
            )

            if result:
                results[source] = result
                print(f"  [OK] {source.upper()}: {len(result)} 条记录")
            else:
                print(f"  [--] {source.upper()}: 无数据")

        if results:
            print(f"\n  保存结果到: {output_dir}")
            manager.save_results(results, query, output_dir=output_dir)
            manager._print_summary(results)

            print("\n" + "="*80)
            print("爬取任务完成！")
            print("="*80)
            print(f"  结果保存在: {output_dir}")
            print(f"  总计: {sum(len(v) for v in results.values())} 条记录")
        else:
            print("\n[!] 没有获取到任何数据")

    except KeyboardInterrupt:
        print("\n\n[!] 用户中断")
    except Exception as e:
        print(f"\n[!] 错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

