"""
run_discovery.py — 三通道账号发现统一入口
==========================================
整合通道 B（文章引用挖掘）和通道 C（GitHub 社区同步），
自动发现新公众号候选并可选地写入 seed_accounts.yaml。

用法：
    # 只运行通道 B（文章引用）
    python run_discovery.py --channel b

    # 只运行通道 C（社区同步，使用 DeepSeek LLM）
    python run_discovery.py --channel c

    # 同时运行 B + C
    python run_discovery.py

    # 运行 B+C 并自动追加到 seed_accounts.yaml（无需人工操作）
    python run_discovery.py --auto-add --min-score 0

    # 运行后立即爬取新发现的账号
    python run_discovery.py --crawl --count 10

    # 通道 C 不调用 LLM（纯正则）
    python run_discovery.py --channel c --no-llm

输出文件：
    raw_data/discovery/channel_b_candidates.json — 通道 B 结果
    raw_data/discovery/channel_c_candidates.json — 通道 C 结果
    raw_data/discovery/merged_candidates.json    — 合并去重结果
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import List, Set

# ── 路径 ─────────────────────────────────────────────────────────────────────
_HERE      = Path(__file__).parent                    # crawlers/wechat_crawler/
_ROOT      = _HERE.parent.parent                      # LORE/
_DISC_DIR  = _ROOT / 'raw_data' / 'discovery'
_SEED_FILE = _HERE / 'seed_accounts.yaml'
_MERGED    = _DISC_DIR / 'merged_candidates.json'

# 将 crawlers/wechat_crawler/ 加入 sys.path，使 discovery.* 可直接导入
sys.path.insert(0, str(_HERE))

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('run_discovery')


# ── 辅助函数 ──────────────────────────────────────────────────────────────────

def _load_existing_output(path: Path) -> List[dict]:
    """读取已有的候选 JSON 文件（可能来自上次运行）。"""
    if path.exists():
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            pass
    return []


def _merge_candidates(b_list: List[dict], c_list: List[dict]) -> List[dict]:
    """合并 B/C 两个通道的候选，按名称去重，来源叠加。"""
    merged: dict[str, dict] = {}
    for item in (b_list or []) + (c_list or []):
        name = item.get('name', '')
        if not name or name.startswith('__biz:'):
            continue
        if name not in merged:
            merged[name] = dict(item)
        else:
            # 来源叠加
            existing_src = merged[name].get('source', '')
            new_src      = item.get('source', '')
            if new_src and new_src not in existing_src:
                merged[name]['source'] = f'{existing_src}+{new_src}'
    return list(merged.values())


def _load_known_names(seed_file: Path) -> Set[str]:
    known: Set[str] = set()
    if not seed_file.exists():
        return known
    try:
        import yaml    # type: ignore
        data = yaml.safe_load(seed_file.read_text(encoding='utf-8')) or {}
        for cat in (data.get('categories') or {}).values():
            if isinstance(cat, list):
                for item in cat:
                    if isinstance(item, dict) and item.get('name'):
                        known.add(item['name'])
        for item in data.get('auto_discovered', []):
            if isinstance(item, dict) and item.get('name'):
                known.add(item['name'])
    except Exception as e:
        log.warning(f'读取 seed_accounts.yaml 失败: {e}')
    return known


def _append_to_seed_yaml(candidates: List[dict], seed_file: Path) -> int:
    """
    将新候选账号追加到 seed_accounts.yaml 的 auto_discovered 分类。
    返回实际新增数量。
    """
    if not candidates:
        return 0
    try:
        import yaml    # type: ignore
    except ImportError:
        log.error('需要 pyyaml: pip install pyyaml')
        return 0

    seed_file.parent.mkdir(parents=True, exist_ok=True)
    existing_text = seed_file.read_text(encoding='utf-8') if seed_file.exists() else ''
    data = yaml.safe_load(existing_text) or {}
    if 'auto_discovered' not in data:
        data['auto_discovered'] = []

    # 已在 auto_discovered 中的名称
    already = {
        item['name']
        for item in data['auto_discovered']
        if isinstance(item, dict) and item.get('name')
    }
    added = 0
    for c in candidates:
        name = c.get('name', '').strip()
        if name and name not in already:
            data['auto_discovered'].append({
                'name':     name,
                'tags':     ['auto_discovered'],
                'priority': 'normal',
                'notes':    f'来源: {c.get("source","")} | {c.get("discovery_keyword","")[:60]}',
            })
            already.add(name)
            added += 1

    # 回写 YAML
    seed_file.write_text(
        '# seed_accounts.yaml — 自动更新\n'
        + yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False),
        encoding='utf-8',
    )
    log.info(f'已将 {added} 个新账号追加到 seed_accounts.yaml (auto_discovered)')
    return added


def _crawl_new_accounts(names: List[str], count: int) -> None:
    """调用 sogou_crawler.py 爬取新发现的账号。"""
    if not names:
        log.info('没有新账号需要爬取')
        return
    script = _HERE / 'sogou_crawler.py'
    cmd = [sys.executable, str(script), '--accounts'] + names[:20] + ['--count', str(count)]
    log.info(f'启动爬取: {" ".join(cmd[:6])} ... --count {count}')
    subprocess.run(cmd, check=False)


# ── 主函数 ────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description='三通道账号发现统一入口')
    ap.add_argument(
        '--channel', choices=['b', 'c', 'all'], default='all',
        help='运行哪个通道（b=引用挖掘, c=社区同步, all=两者，默认 all）',
    )
    ap.add_argument('--threshold', type=int, default=1,
                    help='通道 B 最少引用次数（默认 1）')
    ap.add_argument('--no-llm',    action='store_true',
                    help='通道 C 禁用 LLM（纯正则）')
    ap.add_argument('--auto-add',  action='store_true',
                    help='自动将新发现账号追加到 seed_accounts.yaml')
    ap.add_argument('--crawl',     action='store_true',
                    help='发现后立即爬取新账号')
    ap.add_argument('--count',     type=int, default=10,
                    help='--crawl 时每个账号爬取文章数（默认 10）')
    ap.add_argument('--raw-dir',   default=str(_ROOT / 'raw_data' / 'wechat'),
                    help='通道 B 文章 JSON 目录（默认 raw_data/wechat）')
    args = ap.parse_args()

    run_b = args.channel in ('b', 'all')
    run_c = args.channel in ('c', 'all')

    b_result: List[dict] = []
    c_result: List[dict] = []

    # ── 运行通道 B ────────────────────────────────────────────────────────────
    if run_b:
        print('\n' + '═' * 60)
        print('  通道 B — 文章引用挖掘')
        print('═' * 60)
        from discovery.citation_extractor import run_channel_b
        cands = run_channel_b(
            raw_dir   = args.raw_dir,
            threshold = args.threshold,
        )
        b_result = [c.to_dict() for c in cands]
        print(f'\n[通道 B] 完成，共 {len(b_result)} 个候选账号\n')

    # ── 运行通道 C ────────────────────────────────────────────────────────────
    if run_c:
        print('\n' + '═' * 60)
        print('  通道 C — GitHub 社区同步（DeepSeek LLM）')
        print('═' * 60)
        from discovery.community_sync import run_channel_c
        cands = run_channel_c(use_llm=not args.no_llm)
        c_result = [c.to_dict() for c in cands]
        print(f'\n[通道 C] 完成，共 {len(c_result)} 个候选账号\n')

    # ── 合并 ──────────────────────────────────────────────────────────────────
    if run_b or run_c:
        # 补齐未运行通道的数据（读取上次结果）
        if not run_b:
            b_result = _load_existing_output(_DISC_DIR / 'channel_b_candidates.json')
        if not run_c:
            c_result = _load_existing_output(_DISC_DIR / 'channel_c_candidates.json')

        merged = _merge_candidates(b_result, c_result)
        known  = _load_known_names(_SEED_FILE)
        new    = [c for c in merged if c.get('name') not in known]

        _DISC_DIR.mkdir(parents=True, exist_ok=True)
        _MERGED.write_text(
            json.dumps(merged, ensure_ascii=False, indent=2),
            encoding='utf-8',
        )
        print('\n' + '═' * 60)
        print(f'  合并结果: {len(merged)} 个候选（其中 {len(new)} 个未在种子库中）')
        print(f'  已保存 → {_MERGED}')
        print('═' * 60)

        # ── 精简摘要 ──────────────────────────────────────────────────────────
        if new:
            print(f'\n新发现账号（前 20）：')
            for c in new[:20]:
                print(f'  {c["name"]:<25}  [{c.get("source","")}]')
            if len(new) > 20:
                print(f'  ... 另有 {len(new)-20} 个')

        # ── 可选：写入 seed_accounts.yaml ─────────────────────────────────────
        if args.auto_add:
            added = _append_to_seed_yaml(new, _SEED_FILE)
            print(f'\n✅ 已自动追加 {added} 个新账号到 seed_accounts.yaml')

        # ── 可选：立即爬取 ────────────────────────────────────────────────────
        if args.crawl:
            names = [c['name'] for c in new if not c.get('name','').startswith('__biz:')]
            _crawl_new_accounts(names, args.count)
    else:
        ap.print_help()


if __name__ == '__main__':
    main()

