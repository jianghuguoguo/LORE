"""
discovery/community_sync.py — 通道 C：社区交叉验证（高可信度来源）
============================================================
从 GitHub awesome-security 类项目和安全社区资源列表中自动提取公众号推荐。

这些来源经过人工筛选，与搜狗搜索（自动发现）+引用提取（图谱扩散）组成三通道：
  A（零成本，即时）：搜狗微信搜索
  B（高精度，被动）：文章引用挖掘
  C（高可信，周期）：社区资源列表 ← 本模块

LLM 策略（三级回退）：
  1. DeepSeek API（已在项目中使用，优先）
  2. 本地 Ollama（如已部署）
  3. 纯正则提取（降级保障，不依赖 LLM）

依赖：requests（项目已有）
Optional: httpx（更快，但 requests 也可工作）

用法（独立运行）：
    python -m discovery.community_sync
    python -m discovery.community_sync --no-llm  # 仅正则，不调用 LLM
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

# ── sys.path：供 discovery.* 和 crawlers.wechat_crawler.* 导入 ───────────────
_WC = Path(__file__).parent.parent   # crawlers/wechat_crawler/
_RT = _WC.parent.parent              # RefPenTest/
for _p in (str(_RT), str(_WC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

log = logging.getLogger(__name__)

# requests 是项目必选依赖
import requests

from discovery.models import AccountCandidate

# ── 路径常量 ─────────────────────────────────────────────────────────────────
_HERE       = _RT                               # RefPenTest/
_DISC_DIR   = _HERE / 'raw_data' / 'discovery'
_SEED_FILE  = _WC / 'seed_accounts.yaml'
_C_OUTPUT   = _DISC_DIR / 'channel_c_candidates.json'

# ── DeepSeek API 配置（与项目 run_layer2_analysis.py 保持一致）───────────────
_DEEPSEEK_API_KEY  = 'sk-6bd4ea2482004f44bef2a842a4badc06'
_DEEPSEEK_BASE_URL = 'https://api.deepseek.com/chat/completions'
_DEEPSEEK_MODEL    = 'deepseek-chat'

# ── VPN 代理（项目统一使用 7890）─────────────────────────────────────────────
_PROXY = {
    'http':  'http://127.0.0.1:7890',
    'https': 'http://127.0.0.1:7890',
}

# ── GitHub 来源列表（人工审核的安全资源合集）──────────────────────────────────
GITHUB_SOURCES: List[Dict] = [
    {
        'url':   'https://raw.githubusercontent.com/tom0li/collection-document/master/README.md',
        'label': 'tom0li/collection-document',
        'desc':  '安全文章/工具合集，含微信公众号推荐',
    },
    {
        'url':   'https://raw.githubusercontent.com/ffffffff0x/Digital-Privacy/master/README.md',
        'label': 'ffffffff0x/Digital-Privacy',
        'desc':  '数字安全与隐私保护资源，含中文公众号',
    },
    {
        'url':   'https://raw.githubusercontent.com/Threekiii/Awesome-Redteam/master/README.md',
        'label': 'Threekiii/Awesome-Redteam',
        'desc':  '红队技术合集，包含大量安全公众号推荐',
    },
    {
        'url':   'https://raw.githubusercontent.com/Mr-xn/Penetration_Testing_POC/master/README.md',
        'label': 'Mr-xn/Penetration_Testing_POC',
        'desc':  '渗透测试 POC/EXP 合集，含安全社区公众号',
    },
]

# ── 公众号上下文正则（用于快速提取，减少 LLM token 消耗）──────────────────────
_WECHAT_CONTEXT_PATTERNS: List[re.Pattern] = [
    re.compile(r'微信公众号[：:]\s*[`「【]?([^\s\n`」】,，。]{2,30})[`」】]?'),
    re.compile(r'公众号[：:]\s*[`「【]?([^\s\n`」】,，。]{2,30})[`」】]?'),
    re.compile(r'关注公众号\s*[`「【]?([^\s\n`」】,，。]{2,30})[`」】]?'),
    re.compile(r'搜索公众号[：:]\s*[`「【]?([^\s\n`」】,，。]{2,30})[`」】]?'),
    # Markdown 表格列
    re.compile(r'\|\s*([^\|\n]{2,25})\s*\|[^\n]*?公众号'),
    # 反引号包裹的公众号名称（awesome 列表常用格式）
    re.compile(r'`([^`\n]{2,25})`[^\n]{0,30}?公众号'),
    # 括号内公众号名称
    re.compile(r'[（(]公众号[：:]?\s*([^\s）),，。\n]{2,25})[）)]'),
]

# 黑名单（包含无意义词和占位符）
_BLACKLIST: Set[str] = {
    '微信', '公众号', '关注', '扫码', '二维码', '作者', '更多', '链接',
    '有赞', '点击阅读', '名称', 'xxx', 'XXX', '搜索', '添加', '订阅',
    '账号', '平台', '官方', '小编', '号主', '公号',
}


def _is_valid_name(name: str) -> bool:
    name = name.strip()
    if not (2 <= len(name) <= 35):
        return False
    if name in _BLACKLIST:
        return False
    if re.search(r'http|www\.|github\.com', name, re.IGNORECASE):
        return False
    # 全是英文且很短的通常不是中文公众号名（skip 纯英文缩写）
    return True


class CommunityCrossValidator:
    """
    从安全社区资源列表中同步公众号推荐（通道 C）。

    运行频率：每周日一次（由 Celery Beat 调度）。

    LLM 策略：
      - 先用正则提取（低成本）
      - 若正则命中 < 5 条，再调用 DeepSeek 做深度提取（每个文档约 0.001 元）
      - DeepSeek 不可用时降级到 Ollama，最终降级到纯正则
    """

    def __init__(
        self,
        timeout:     float = 25.0,
        use_llm:     bool  = True,
        proxy:       dict  = None,
        deepseek_key: str  = _DEEPSEEK_API_KEY,
    ) -> None:
        self._timeout      = timeout
        self._use_llm      = use_llm
        self._proxy        = proxy if proxy is not None else _PROXY
        self._deepseek_key = deepseek_key
        self._session      = self._make_session()

    def _make_session(self) -> requests.Session:
        sess = requests.Session()
        sess.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/122.0.0.0 Safari/537.36'
            ),
        })
        return sess

    def _get(self, url: str) -> Optional[str]:
        """GET 请求，经 VPN 代理，返回文本，失败返回 None。"""
        for attempt in range(3):
            try:
                resp = self._session.get(
                    url,
                    proxies=self._proxy,
                    timeout=self._timeout,
                    allow_redirects=True,
                )
                resp.raise_for_status()
                return resp.text
            except Exception as e:
                log.warning(f'[ChannelC] GET 失败 (第{attempt+1}次) {url}: {e}')
                if attempt < 2:
                    time.sleep(3)
        return None

    # ── 主入口 ────────────────────────────────────────────────────────────────

    def sync_from_github(
        self,
        sources: List[Dict] | None = None,
    ) -> List[AccountCandidate]:
        """
        从 GitHub 资源列表提取公众号候选。

        Parameters
        ----------
        sources : 来源配置列表，None 时使用内置 GITHUB_SOURCES

        Returns
        -------
        List[AccountCandidate]
        """
        source_list = sources or GITHUB_SOURCES
        all_candidates: Dict[str, AccountCandidate] = {}

        for src in source_list:
            url   = src['url']
            label = src.get('label', url)
            log.info(f'[ChannelC] 同步: {label}')

            text = self._get(url)
            if not text:
                log.warning(f'[ChannelC] 跳过（获取失败）: {url}')
                continue

            candidates = self._extract_from_markdown(text, source_url=url)
            added = 0
            for c in candidates:
                if c.name not in all_candidates:
                    all_candidates[c.name] = c
                    added += 1

            log.info(f'[ChannelC]   └─ {label}: 提取 {len(candidates)} 个，新增 {added} 个')
            time.sleep(2.0)   # 礼貌延迟

        result = list(all_candidates.values())
        log.info(f'[ChannelC] 从 {len(source_list)} 个来源共提取 {len(result)} 个候选账号')
        return result

    # ── 提取逻辑 ──────────────────────────────────────────────────────────────

    def _extract_from_markdown(
        self,
        text:       str,
        source_url: str = '',
    ) -> List[AccountCandidate]:
        """
        从 Markdown 文本中提取公众号名称。

        策略（三级，按成本从低到高）：
          1. 高精度正则模式
          2. DeepSeek LLM 提取（正则命中 < 5 时触发）
          3. Ollama 本地模型（DeepSeek 不可用时）
        """
        candidates: Dict[str, AccountCandidate] = {}
        ts = time.strftime('%Y-%m-%dT%H:%M:%S')

        # ── 策略 1：正则精确匹配 ──────────────────────────────────────────────
        for pattern in _WECHAT_CONTEXT_PATTERNS:
            for m in pattern.finditer(text):
                name = m.group(1).strip().rstrip('。，！？…`')
                if _is_valid_name(name) and name not in candidates:
                    candidates[name] = AccountCandidate(
                        name=name,
                        source='community_regex',
                        discovery_keyword=source_url,
                        first_seen=ts,
                    )

        # ── 策略 2/3：LLM 深度提取（正则命中不足时）──────────────────────────
        if self._use_llm and len(candidates) < 5:
            log.info(f'[ChannelC] 正则仅找到 {len(candidates)} 个，启动 LLM 深度提取...')
            # 对长文档做分段：每段 3000 字符，避免超 token
            segments = self._split_text(text, chunk_size=3000)
            llm_names: List[str] = []
            for seg in segments:
                names = self._llm_extract(seg)
                llm_names.extend(names)
                if len(llm_names) >= 50:   # 够用就停
                    break

            for name in llm_names:
                name = name.strip().rstrip('。，！？…`')
                if _is_valid_name(name) and name not in candidates:
                    candidates[name] = AccountCandidate(
                        name=name,
                        source='community_llm',
                        discovery_keyword=source_url,
                        first_seen=ts,
                    )

        return list(candidates.values())

    # ── LLM 调用（三级回退）────────────────────────────────────────────────────

    def _llm_extract(self, text: str) -> List[str]:
        """
        调用 LLM 从文本中提取微信公众号名称列表。
        优先级：DeepSeek > Ollama > 空列表（降级不报错）
        """
        prompt = (
            '请仔细阅读以下文本，提取其中所有微信公众号名称。\n'
            '要求：\n'
            '1. 只提取公众号名称（不是个人微信号、不是网站名）\n'
            '2. 每行输出一个名称，不要编号，不要解释\n'
            '3. 如果没有公众号名称，输出"无"\n\n'
            f'文本：\n{text}'
        )

        # 优先 DeepSeek
        names = self._call_deepseek(prompt)
        if names:
            return names

        # 回退 Ollama
        names = self._call_ollama(prompt)
        return names

    def _call_deepseek(self, prompt: str) -> List[str]:
        """调用 DeepSeek API（与项目 run_layer2_analysis.py 保持一致）。"""
        if not self._deepseek_key:
            return []
        try:
            resp = self._session.post(
                _DEEPSEEK_BASE_URL,
                headers={
                    'Authorization': f'Bearer {self._deepseek_key}',
                    'Content-Type': 'application/json',
                },
                json={
                    'model': _DEEPSEEK_MODEL,
                    'messages': [{'role': 'user', 'content': prompt}],
                    'temperature': 0.1,
                    'max_tokens': 1024,
                },
                proxies=self._proxy,
                timeout=60.0,
            )
            resp.raise_for_status()
            data = resp.json()
            raw = data['choices'][0]['message']['content'] or ''
            log.debug(f'[ChannelC] DeepSeek 响应: {raw[:200]}')
            return self._parse_llm_output(raw)
        except Exception as e:
            log.warning(f'[ChannelC] DeepSeek 调用失败: {e}')
            return []

    def _call_ollama(self, prompt: str) -> List[str]:
        """调用本地 Ollama 接口（默认 qwen2.5:3b）。"""
        try:
            resp = self._session.post(
                'http://127.0.0.1:11434/api/generate',
                json={
                    'model': 'qwen2.5:3b',
                    'prompt': prompt,
                    'stream': False,
                    'options': {'temperature': 0.1, 'num_predict': 512},
                },
                timeout=45.0,
                proxies=None,   # 本地不走代理
            )
            resp.raise_for_status()
            raw = resp.json().get('response', '')
            return self._parse_llm_output(raw)
        except Exception as e:
            log.debug(f'[ChannelC] Ollama 调用失败（不影响功能）: {e}')
            return []

    @staticmethod
    def _parse_llm_output(raw: str) -> List[str]:
        """
        解析 LLM 返回文本，提取公众号名称列表。
        - 过滤无效行（太长、太短、含 http、等于"无"）
        - 去掉常见前缀：序号、"-"、"*"、"·" 等
        """
        names = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line in ('无', 'N/A', '-', '*'):
                continue
            # 去掉序号前缀：1. / 1、/ - / * / ·
            line = re.sub(r'^[\d]+[\.、]\s*', '', line)
            line = re.sub(r'^[-*·]\s*', '', line)
            line = line.strip().strip('`"\'"）】')
            if 2 <= len(line) <= 30 and _is_valid_name(line):
                names.append(line)
        return names

    @staticmethod
    def _split_text(text: str, chunk_size: int = 3000) -> List[str]:
        """将长文本按段落切分，尽量在换行处断开。"""
        if len(text) <= chunk_size:
            return [text]
        chunks = []
        while text:
            if len(text) <= chunk_size:
                chunks.append(text)
                break
            # 在 chunk_size 附近找换行
            cut = text.rfind('\n', 0, chunk_size)
            cut = cut if cut > chunk_size // 2 else chunk_size
            chunks.append(text[:cut])
            text = text[cut:]
        return chunks

    @staticmethod
    def _is_valid_name(name: str) -> bool:  # 为外部调用保留
        return _is_valid_name(name)


# ── 独立运行入口：通道 C 主函数 ───────────────────────────────────────────────

def _load_known_names(seed_file: Path) -> Set[str]:
    """从 seed_accounts.yaml 读取所有已知账号名，用于去重。"""
    known: Set[str] = set()
    if not seed_file.exists():
        return known
    try:
        import yaml   # type: ignore
        data = yaml.safe_load(seed_file.read_text(encoding='utf-8')) or {}
        for cat_accounts in (data.get('categories') or {}).values():
            if isinstance(cat_accounts, list):
                for item in cat_accounts:
                    if isinstance(item, dict) and item.get('name'):
                        known.add(item['name'])
        # 同时读取 auto_discovered
        for item in data.get('auto_discovered', []):
            if isinstance(item, dict) and item.get('name'):
                known.add(item['name'])
    except Exception as e:
        log.warning(f'[ChannelC] 读取 seed_accounts.yaml 失败: {e}')
    return known


def run_channel_c(
    sources:      List[Dict] | None = None,
    output:       Path | str        = _C_OUTPUT,
    seed_file:    Path | str        = _SEED_FILE,
    use_llm:      bool              = True,
    verbose:      bool              = True,
) -> List[AccountCandidate]:
    """
    通道 C 主入口：同步 GitHub 安全资源列表中的公众号推荐。

    Parameters
    ----------
    sources   : GitHub 来源配置，None 时使用内置 GITHUB_SOURCES
    output    : 候选结果输出 JSON 文件路径
    seed_file : seed_accounts.yaml 路径（用于去重已知账号）
    use_llm   : 是否启用 LLM 深度提取（默认 True）
    verbose   : 是否打印日志

    Returns
    -------
    新发现（不在种子库中）的 AccountCandidate 列表
    """
    if verbose:
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s %(message)s',
            datefmt='%H:%M:%S',
        )

    output    = Path(output)
    seed_file = Path(seed_file)

    # 1. 同步
    validator = CommunityCrossValidator(use_llm=use_llm)
    all_cands = validator.sync_from_github(sources=sources)

    # 2. 排除已知账号
    known     = _load_known_names(seed_file)
    new_cands = [c for c in all_cands if c.name not in known]

    log.info(f'[ChannelC] 候选账号: 共 {len(all_cands)} 个 | '
             f'新发现 {len(new_cands)} 个 | 已知 {len(all_cands)-len(new_cands)} 个')

    # 3. 保存结果
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps([c.to_dict() for c in new_cands], ensure_ascii=False, indent=2),
        encoding='utf-8',
    )
    log.info(f'[ChannelC] 结果已保存 → {output}')

    # 4. 终端摘要
    if verbose and new_cands:
        print('\n════════ 通道 C 新发现账号 ════════')
        for c in new_cands[:30]:
            print(f'  {c.name:<25}  [来源:{c.source}]  {c.discovery_keyword}')
        if len(new_cands) > 30:
            print(f'  ... 另有 {len(new_cands) - 30} 个，详见 {output}')

    return new_cands


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='通道 C — GitHub 社区同步')
    ap.add_argument('--no-llm',  action='store_true', help='禁用 LLM，仅使用正则提取')
    ap.add_argument('--output',  default=str(_C_OUTPUT), help='输出 JSON 路径')
    args = ap.parse_args()

    run_channel_c(
        output=args.output,
        use_llm=not args.no_llm,
    )
