"""
wechat_article_crawler/ui_bot.py
=================================
PC 微信 3.x UI 自动化机器人

微信 3.x 使用 WebView2 容器，标准 uiautomation 控件树不可用。
本模块使用 win32gui + pyautogui + pyperclip 实现可靠的 UI 操作。

依赖：
    pip install pyautogui pywin32 pyperclip pillow

两种爬取策略：
  A. browse_subscription_feed()  —— 浏览订阅号消息流（passively scroll & click）
  B. browse_account()            —— 搜索指定公众号并点击文章列表

Phase 1：offset/progress_callback 支持断点续爬 + 触发 mitmproxy 拦截
"""

from __future__ import annotations

import logging
import random
import sys
import time
from pathlib import Path
from typing import Callable, Optional

import pyautogui
import pyperclip
import win32api
import win32con
import win32gui

pyautogui.FAILSAFE = False  # 关闭角落失效保险，防止自动化被中断
pyautogui.PAUSE = 0.05      # 操作间最小停顿

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))
from config import MITM_CONFIG

log = logging.getLogger('wechat_ui_bot')

TARGET_ACCOUNTS   = MITM_CONFIG.get('TARGET_ACCOUNTS', [])
ARTICLES_PER_ACCT = MITM_CONFIG.get('ARTICLES_PER_ACCOUNT', 30)
_CLICK_WAIT_BASE  = MITM_CONFIG.get('CLICK_WAIT_SECONDS', 5)
_CAPTURE_WAIT     = float(MITM_CONFIG.get('CAPTURE_WAIT_SECONDS', 4))
_BATCH_SLEEP_BASE = MITM_CONFIG.get('BATCH_SLEEP_SECONDS', 2)
_QUEUE_FILE       = Path(MITM_CONFIG.get('QUEUE_FILE', _HERE / 'captured_queue.jsonl'))
_SAVE_DIR         = Path(MITM_CONFIG.get('SAVE_DIR', _HERE.parent.parent.parent / 'raw_data' / 'wechat'))


def _rand_click_wait() -> float:
    """文章加载等待：base±2 秒随机。"""
    return random.uniform(max(3.0, _CLICK_WAIT_BASE - 1), _CLICK_WAIT_BASE + 3)

def _rand_batch_sleep() -> float:
    """滚动间隔：base±1 秒随机。"""
    return random.uniform(max(1.5, _BATCH_SLEEP_BASE - 1), _BATCH_SLEEP_BASE + 2)


def _capture_marker() -> tuple[int, int, int]:
    save_count = len(list(_SAVE_DIR.glob('*.json'))) if _SAVE_DIR.exists() else 0
    if _QUEUE_FILE.exists():
        stat = _QUEUE_FILE.stat()
        return save_count, int(stat.st_size), int(stat.st_mtime)
    return save_count, 0, 0


def _wait_for_capture(previous_marker: tuple[int, int, int], timeout: float = _CAPTURE_WAIT) -> bool:
    deadline = time.time() + max(0.5, timeout)
    while time.time() < deadline:
        current = _capture_marker()
        if current != previous_marker:
            return True
        time.sleep(0.4)
    return _capture_marker() != previous_marker


class WeChatUIBot:
    """
    WeChat PC 3.x 自动化（Win32 + pyautogui + pyperclip）。

    WeChat 3.x 整体 UI 封装在 CWebviewHostWnd 容器中，标准 uiautomation
    控件树不可用。本类通过以下机制实现自动化：
      - win32gui  : 定位窗口句柄、获取坐标、置前
      - pyautogui : 鼠标点击、键盘快捷键、滚动
      - pyperclip : 中文安全粘贴（绕过 typewrite 乱码）
    """

    WECHAT_CLASS = 'WeChatMainWndForPC'
    WECHAT_TITLE = '微信'

    def __init__(self) -> None:
        self._hwnd: int = 0

    # ─── 窗口基础操作 ──────────────────────────────────────────────────────

    def find_wechat_window(self) -> bool:
        """定位微信主窗口，找不到则抛 RuntimeError。"""
        hwnd = win32gui.FindWindow(self.WECHAT_CLASS, None)
        if not hwnd:
            hwnd = win32gui.FindWindow(None, self.WECHAT_TITLE)
        if not hwnd:
            raise RuntimeError('未找到微信主窗口，请先启动 PC 版微信并登录。')
        self._hwnd = hwnd
        log.info(f'已找到微信主窗口 HWND={hwnd}')
        return True

    def bring_to_front(self) -> None:
        """将微信窗口置于前台并恢复（如果最小化）。"""
        if not self._hwnd:
            self.find_wechat_window()
        try:
            if win32gui.IsIconic(self._hwnd):
                win32gui.ShowWindow(self._hwnd, win32con.SW_RESTORE)
            win32gui.SetForegroundWindow(self._hwnd)
        except Exception as e:
            log.debug(f'bring_to_front 警告: {e}')
        time.sleep(0.6)

    def _get_rect(self) -> tuple[int, int, int, int, int, int]:
        """返回 (left, top, right, bottom, width, height)。"""
        l, t, r, b = win32gui.GetWindowRect(self._hwnd)
        return l, t, r, b, r - l, b - t

    def _abs(self, rx: float, ry: float) -> tuple[int, int]:
        """相对坐标 (0-1) 转绝对屏幕坐标。"""
        l, t, r, b, w, h = self._get_rect()
        return int(l + rx * w), int(t + ry * h)

    def _click(self, rx: float, ry: float, pause: float = 0.4) -> None:
        """在相对坐标处点击。"""
        x, y = self._abs(rx, ry)
        pyautogui.moveTo(x, y, duration=0.15)
        pyautogui.click()
        time.sleep(pause)

    def _scroll_main(self, direction: int = -5) -> None:
        """在主内容区域滚动（direction 负=下翻）。"""
        l, t, r, b, w, h = self._get_rect()
        pyautogui.scroll(direction, x=int(l + w * 0.60), y=int(t + h * 0.45))
        time.sleep(0.8)

    def _paste_text(self, text: str) -> None:
        """通过剪切板粘贴文本（支持中文）。"""
        pyperclip.copy(text)
        time.sleep(0.15)
        pyautogui.hotkey('ctrl', 'a')
        time.sleep(0.05)
        pyautogui.hotkey('ctrl', 'v')
        time.sleep(0.4)

    # ─── 搜索与导航 ───────────────────────────────────────────────────────

    def _open_search(self) -> bool:
        """打开微信全局搜索（Ctrl+F）。"""
        self.bring_to_front()
        pyautogui.hotkey('ctrl', 'f')
        time.sleep(1.2)
        return True

    def _search_and_open_account(self, account_name: str) -> bool:
        """
        搜索公众号并进入账号页面。
        策略：Ctrl+F → 粘贴名称 → Enter 搜索 → 10次Down键 → Enter 进入第一个公众号结果。
        经测试：10次Down键后的结果位置对应搜索列表末尾的「公众号」分区。
        """
        self._open_search()
        self._paste_text(account_name)
        time.sleep(0.8)
        pyautogui.press('enter')
        time.sleep(2.5)   # 等待搜索结果加载

        # 用 Down 键导航到「公众号」区的结果（通常在结果列底部）
        for _ in range(10):
            pyautogui.press('down')
            time.sleep(0.25)

        pyautogui.press('enter')
        time.sleep(2.0)   # 等待账号页面/主内容区加载

        log.info(f'已搜索并导航进入账号: {account_name!r}')
        return True

    def _navigate_to_subscription_feed(self) -> None:
        """
        导航到「订阅号消息」聚合页。
        微信 3.x 中通常以置顶的聊天项呈现，位于聊天列表顶部。
        同时尝试在左侧图标栏找到专属入口。
        """
        self.bring_to_front()

        # 微信 3.x 左侧图标栏第一类图标：聊天(y≈9%)、通讯录(y≈17%)...
        # 先确保在「聊天」标签：
        self._click(0.03, 0.09, pause=0.8)  # 聊天图标

        # 聊天列表顶部通常钉住了「订阅号消息」：
        self._click(0.16, 0.12, pause=1.0)
        log.info('已尝试导航到订阅号消息')

    # ─── 文章点击核心逻辑 ─────────────────────────────────────────────────

    def _click_articles_in_view(
        self,
        count: int,
        offset: int = 0,
        progress_callback: Optional[Callable] = None,
    ) -> int:
        """
        点击当前可见主内容区域中的文章卡片。

        WeChat 主内容区 x≈[29%, 100%]，文章卡片沿 y 轴排列。
        每点击一篇：等待加载（mitmproxy 拦截）→ Escape 关闭 → 继续。

        参数
        ----
        count    : 目标点击数
        offset   : 跳过的条目数（断点续爬）
        progress_callback : 每成功点击后调用 callback(delta=1)
        """
        l, t, r, b, w, h = self._get_rect()

        # 文章卡片 y 相对坐标（主内容区中间偏左）
        card_rx   = 0.60   # 主区域水平中心
        card_ry_s = [0.16, 0.28, 0.40, 0.52, 0.64, 0.76]

        clicked  = 0
        skipped  = 0
        no_new_consecutive = 0   # 连续无新内容计数，防止死循环

        while clicked < count:
            batch_clicked = 0

            for ry in card_ry_s:
                if skipped < offset:
                    skipped += 1
                    continue

                x = int(l + w * card_rx)
                y = int(t + h * ry)
                before_capture = _capture_marker()

                # 点击文章卡片
                pyautogui.moveTo(x, y, duration=0.15)
                pyautogui.click()
                wait = _rand_click_wait()
                log.debug(f'  等待 {wait:.1f}s 让 mitmproxy 拦截...')
                time.sleep(wait)

                # 关闭文章（Escape；部分版本需要 Alt+Left）
                pyautogui.press('escape')
                time.sleep(0.4)
                pyautogui.hotkey('alt', 'left')
                time.sleep(0.4)

                if not _wait_for_capture(before_capture):
                    log.warning(f'点击位置 ({x}, {y}) 后未观察到新的拦截产物，跳过计数')
                    continue

                clicked += 1
                batch_clicked += 1
                if progress_callback:
                    progress_callback(1)
                log.info(f'已点击文章 {clicked}/{count}')

                if clicked >= count:
                    return clicked

            if batch_clicked == 0:
                no_new_consecutive += 1
                if no_new_consecutive >= 3:
                    log.warning('连续 3 轮无新文章，停止（可能已到达底部）')
                    break
            else:
                no_new_consecutive = 0

            # 向下滚动加载更多
            self._scroll_main(-8)
            time.sleep(_rand_batch_sleep())

        return clicked

    # ─── 对外公共 API（与 scheduler.py 调用接口保持一致）────────────────────

    def browse_account(
        self,
        account_name: str,
        count: int = 30,
        offset: int = 0,
        progress_callback: Optional[Callable] = None,
    ) -> int:
        """搜索指定公众号，进入账号页面后点击文章列表。"""
        self.bring_to_front()

        if not self._search_and_open_account(account_name):
            log.warning(f'跳过账号 {account_name!r}（搜索失败）')
            return 0

        time.sleep(1.5)
        n = self._click_articles_in_view(count, offset, progress_callback)
        log.info(f'[{account_name}] 完成，共点击 {n} 篇')
        return n

    def browse_subscription_feed(
        self,
        count: int = 50,
        offset: int = 0,
        progress_callback: Optional[Callable] = None,
    ) -> int:
        """浏览订阅号消息流并逐一点击文章。"""
        self.bring_to_front()
        self._navigate_to_subscription_feed()
        time.sleep(2.0)

        n = self._click_articles_in_view(count, offset, progress_callback)
        log.info(f'[Feed] 完成，共点击 {n} 篇')
        return n

    def run(
        self,
        target_accounts: list | None = None,
        articles_per_account: int | None = None,
    ) -> dict:
        """主入口：按账号列表或订阅号流采集。"""
        accounts = target_accounts if target_accounts is not None else TARGET_ACCOUNTS
        per_acct = articles_per_account if articles_per_account is not None else ARTICLES_PER_ACCT

        self.find_wechat_window()
        stats: dict = {}

        if accounts:
            for acct in accounts:
                n = self.browse_account(acct, per_acct)
                stats[acct] = n
        else:
            n = self.browse_subscription_feed(per_acct)
            stats['feed'] = n

        log.info(f'全部完成！共触发 {sum(stats.values())} 篇')
        return stats


# ── 独立运行入口 ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s %(message)s',
        datefmt='%H:%M:%S',
    )

    parser = argparse.ArgumentParser(description='WeChat UI Bot (Win32+pyautogui)')
    parser.add_argument('--accounts', nargs='*', help='目标公众号名（空格分隔）')
    parser.add_argument('--count', type=int, default=ARTICLES_PER_ACCT)
    parser.add_argument('--feed', action='store_true', help='直接浏览订阅号消息流')
    args = parser.parse_args()

    bot = WeChatUIBot()
    if args.feed or not args.accounts:
        result = bot.run(target_accounts=None, articles_per_account=args.count)
    else:
        result = bot.run(target_accounts=args.accounts, articles_per_account=args.count)
    print('[完成]', result)
