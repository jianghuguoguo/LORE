"""
CSDN VIP爬虫模块
负责爬取CSDN博客和评论内容
"""

import json
import os
import time
import re
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
from pathlib import Path
import sys

# 添加父目录到路径以导入base_crawler
sys.path.insert(0, str(Path(__file__).parent.parent))

from crawlers.base_crawler import BaseCrawler
from crawlers.config import (
    USE_VIP, CSDN_COOKIE, CSDN_USERNAME, CSDN_PASSWORD,
    CUSTOM_USER_AGENT, REQUEST_TIMEOUT, MAX_RETRIES,
    CRAWL_DELAY, CONTENT_SELECTORS, UNWANTED_SELECTORS,
    VIP_SELECTORS, VIP_KEYWORDS
)


class CSDNVIPCrawler(BaseCrawler):
    """CSDN VIP内容爬虫"""
    
    def __init__(self, session=None):
        super().__init__(session)
        self.setup_vip_mode()
    
    def get_source_name(self) -> str:
        """返回数据源名称"""
        return 'csdn'
    
    def setup_vip_mode(self):
        """设置VIP模式"""
        if USE_VIP:
            if CSDN_COOKIE.strip():
                print("[VIP] 使用Cookie进行VIP认证")
                self.session.headers.update({'Cookie': CSDN_COOKIE.strip()})
            elif CSDN_USERNAME and CSDN_PASSWORD:
                print("[VIP] 使用用户名密码进行VIP认证")
                self.login_with_credentials()
            else:
                print("[警告] VIP模式已启用但未配置认证信息")
        else:
            print("[普通] 使用普通模式")
    
    def login_with_credentials(self):
        """使用用户名密码登录（待实现）"""
        print("[警告] 用户名密码登录功能需要进一步开发")
        print("[建议] 推荐使用Cookie方式，更稳定可靠")
    
    def get_headers(self):
        """获取请求头"""
        return {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Referer': 'https://so.csdn.net/',
            'Origin': 'https://so.csdn.net',
        }
    
    def _process_page(self, data, all_results, t, page):
        """子方法：处理单页结果（提取并去重）"""
        result_list = data['result_vos']
        for item in result_list:
            title = item.get('title', '').replace('<em>', '').replace('</em>', '')
            link = item.get('url_location') or item.get('url', '')
            date = item.get('created_at', '') or item.get('create_time_str', '')
            summary = item.get('description', '') or item.get('digest', '') or item.get('body', '')
            summary = summary.replace('<em>', '').replace('</em>', '')
            
            if title and link:
                # 去重：检查 link 是否已存在
                if not any(r['link'] == link for r in all_results):
                    all_results.append({
                        'title': title,
                        'link': link,
                        'date': date,
                        'summary': summary,
                        'page': page,
                        'type': t
                    })
    
    def search_articles(self, query, max_pages=10, types_list=['blog', 'news']):
        """搜索文章（扩展：支持多类型，动态页数）"""
        api_url = "https://so.csdn.net/api/v3/search"
        headers = self.get_headers()
        all_results = []
        total_fetched = 0
        
        for t in types_list:
            print(f"[搜索] 类型: {t}")
            params_base = {'q': query, 't': t, 'size': '20'}
            
            # 首次请求获取 total
            first_params = params_base.copy()
            first_params['p'] = 1
            try:
                response = self.session.get(api_url, params=first_params, headers=headers, timeout=REQUEST_TIMEOUT)
                if response.status_code != 200:
                    print(f"[错误] 类型 {t} 首次请求失败: {response.status_code}")
                    continue
                data = response.json()
                if 'total' not in data:
                    print(f"[错误] 类型 {t} 无 total 数据")
                    continue
                api_total = data['total']
                needed_pages = (api_total + 19) // 20  # ceil division
                actual_pages = min(max_pages, needed_pages)
                print(f"[统计] 类型 {t} 总计 {api_total} 条，需要 {actual_pages} 页")
                
                # 处理第1页
                self._process_page(data, all_results, t, 1)
                total_fetched += len(data.get('result_vos', []))
                
                # 后续页
                for page in range(2, actual_pages + 1):
                    params = params_base.copy()
                    params['p'] = page
                    response = self.session.get(api_url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
                    if response.status_code != 200:
                        print(f"[错误] 类型 {t} 第 {page} 页请求失败")
                        break
                    data = response.json()
                    if 'result_vos' not in data or not data['result_vos']:
                        print(f"[完成] 类型 {t} 第 {page} 页无结果，停止")
                        break
                    
                    self._process_page(data, all_results, t, page)
                    total_fetched += len(data.get('result_vos', []))
                    time.sleep(1)  # 页面间延时
                
            except Exception as e:
                print(f"[异常] 类型 {t} 请求异常: {e}")
                continue
        
        print(f"[完成] 总获取 {total_fetched} 条（去重后 {len(all_results)}）")
        return all_results
    
    def extract_vip_content(self, soup, original_content):
        """提取VIP内容的完整版本"""
        try:
            # 检查当前URL是否为CSDN文库
            current_url = ""
            canonical_link = soup.find('link', rel='canonical')
            if canonical_link and canonical_link.get('href'):
                current_url = canonical_link.get('href')
            else:
                meta_url = soup.find('meta', property='og:url')
                if meta_url and meta_url.get('content'):
                    current_url = meta_url.get('content')
            
            # 针对CSDN文库的特殊处理
            if 'wenku.csdn.net' in current_url or 'wenku.csdn.net' in str(soup):
                return self.extract_wenku_content(soup, original_content)
            
            # VIP内容可能使用特殊的选择器
            vip_content_selectors = [
                '.article-content-box',
                '.pay-article-content',
                '.vip-article-content',
                '.member-content',
                '[data-vip-content]',
                '.full-content',
                '.premium-content',
                'main',
                '.main-content',
                '.content-body',
            ]
            
            # 尝试VIP特殊选择器
            for selector in vip_content_selectors:
                vip_div = soup.select_one(selector)
                if vip_div:
                    for sel in UNWANTED_SELECTORS:
                        for unwanted in vip_div.select(sel):
                            unwanted.decompose()
                    
                    vip_content = vip_div.get_text(separator='\n', strip=True)
                    if len(vip_content) > len(original_content):
                        return vip_content
            
            # 尝试移除登录墙元素后重新提取
            login_wall_selectors = [
                '.login-popup', '.paywall', '.vip-prompt',
                '.subscribe-prompt', '.member-prompt',
                '.app-download-prompt', '.login-overlay',
                '.mask', '.overlay', '.popup'
            ]
            
            for selector in login_wall_selectors:
                for element in soup.select(selector):
                    element.decompose()
            
            # 重新尝试标准选择器
            for selector in CONTENT_SELECTORS:
                content_div = soup.select_one(selector)
                if content_div:
                    for sel in UNWANTED_SELECTORS:
                        for unwanted in content_div.select(sel):
                            unwanted.decompose()
                    
                    new_content = content_div.get_text(separator='\n', strip=True)
                    if len(new_content) > len(original_content):
                        return new_content
            
            return None
            
        except Exception as e:
            print(f"   [警告] VIP内容提取异常: {e}")
            return None
    
    def extract_wenku_content(self, soup, original_content):
        """专门提取CSDN文库内容"""
        try:
            print("   [文库] 检测到CSDN文库，使用专用提取策略...")
            
            wenku_selectors = [
                '.answer-body',
                '.answer-content',
                '.doc-content',
                '.rich-text',
                '.content-wrap',
                '.main-content',
                '.article-wrap',
                '.text-content',
                '[data-content]',
                '.markdown-body',
                'body'
            ]
            
            max_content = original_content
            max_length = len(original_content)
            
            for selector in wenku_selectors:
                try:
                    elements = soup.select(selector)
                    for element in elements:
                        element_copy = BeautifulSoup(str(element), 'html.parser')
                        
                        unwanted_selectors = UNWANTED_SELECTORS + [
                            '.toolbar', '.share-box', '.comment-box',
                            '.recommend-box', '.ad-box', '.sidebar',
                            '.footer', '.header', '.nav', '.menu'
                        ]
                        
                        for unwanted_sel in unwanted_selectors:
                            for unwanted in element_copy.select(unwanted_sel):
                                unwanted.decompose()
                        
                        content = element_copy.get_text(separator='\n', strip=True)
                        
                        if len(content) > max_length:
                            max_content = content
                            max_length = len(content)
                            print(f"   [发现] 找到更长内容 ({selector}): {max_length} 字符")
                
                except Exception as e:
                    print(f"   [警告] 选择器 {selector} 处理异常: {e}")
                    continue
            
            if max_length > len(original_content):
                return max_content
            
            print("   [尝试] 尝试获取页面所有可见文本...")
            
            for element in soup(['script', 'style', 'meta', 'link', 'noscript']):
                element.decompose()
            
            body = soup.find('body')
            if body:
                all_text = body.get_text(separator='\n', strip=True)
                if len(all_text) > max_length:
                    print(f"   [成功] 获取到页面全文: {len(all_text)} 字符")
                    return all_text
            
            return None if max_length <= len(original_content) else max_content
            
        except Exception as e:
            print(f"   [错误] CSDN文库内容提取异常: {e}")
            return None
    
    def check_vip_content(self, soup):
        """检查是否为VIP内容"""
        for selector in VIP_SELECTORS:
            if soup.select(selector):
                return True
        
        text_content = soup.get_text().lower()
        for keyword in VIP_KEYWORDS:
            if keyword in text_content:
                return True
        
        return False
    
    def scrape_article_content(self, url):
        """爬取文章内容"""
        headers = self.get_headers()
        
        for retry in range(MAX_RETRIES):
            try:
                response = self.session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                
                is_vip = self.check_vip_content(soup)
                vip_status = "[VIP]" if is_vip else "[普通]"
                
                best_content = ""
                best_source = ""

                # 1) 文库专用
                canonical_link = soup.find('link', rel='canonical')
                current_url = canonical_link.get('href') if canonical_link and canonical_link.get('href') else url
                if 'wenku.csdn.net' in current_url or 'wenku.csdn.net' in str(soup):
                    wenku = self.extract_wenku_content(soup, "")
                    if wenku and len(wenku) > len(best_content):
                        best_content = wenku
                        best_source = 'wenku_special'

                # 2) 标准 content_views
                if not best_content:
                    content_div = soup.find('div', id='content_views')
                    if content_div:
                        content_text = content_div.get_text(separator='\n', strip=True)
                        if content_text:
                            best_content = content_text
                            best_source = 'content_views'

                # 3) VIP 定制提取
                if is_vip or not best_content:
                    vip_full = self.extract_vip_content(soup, best_content)
                    if vip_full and len(vip_full) > len(best_content):
                        best_content = vip_full
                        best_source = 'vip_selectors'

                # 4) 常见内容选择器兜底
                if not best_content:
                    longest = ""
                    for selector in CONTENT_SELECTORS:
                        node = soup.select_one(selector)
                        if not node:
                            continue
                        node_copy = BeautifulSoup(str(node), 'html.parser')
                        for sel in UNWANTED_SELECTORS:
                            for unwanted in node_copy.select(sel):
                                unwanted.decompose()
                        text = node_copy.get_text(separator='\n', strip=True)
                        if len(text) > len(longest):
                            longest = text
                            best_source = f'selector:{selector}'
                    if longest:
                        best_content = longest

                # 5) 全页可见文本
                if not best_content:
                    for sel in ['script', 'style', 'meta', 'link', 'noscript']:
                        for el in soup.select(sel):
                            el.decompose()
                    body = soup.find('body')
                    if body:
                        text = body.get_text(separator='\n', strip=True)
                        if text:
                            best_content = text
                            best_source = 'body_text'

                if best_content:
                    # --- 新增：获取评论 ---
                    # 注意：只有非 VIP 或能访问的页面才尝试获取评论，
                    # 且文库类(wenku)的评论API不同，这里只针对 blog 处理
                    comments_text = "未获取"
                    if 'blog.csdn.net' in url:
                        print(f"   └── 正在获取评论...", end="\r")
                        comments_text = self.get_article_comments(url)
                        print(f"   └── 评论获取完毕: {comments_text[:20].replace(chr(10), ' ')}...")

                    return {
                        'content': best_content,
                        'comments': comments_text,
                        'is_vip': is_vip,
                        'content_length': len(best_content),
                        'content_source': best_source or 'unknown',
                        'status': f"{vip_status} | 长度: {len(best_content)} | 来源: {best_source or 'unknown'}"
                    }
                else:
                    return {
                        'content': "无法提取文章内容（多策略均未匹配）",
                        'comments': "未获取",
                        'is_vip': is_vip,
                        'content_length': 0,
                        'content_source': "无",
                        'status': f"{vip_status} | 内容提取失败"
                    }
                    
            except Exception as e:
                if retry < MAX_RETRIES - 1:
                    print(f"   [重试] 重试 {retry + 1}/{MAX_RETRIES}: {e}")
                    time.sleep(2)
                else:
                    return {
                        'content': f"爬取失败: {e}",
                        'comments': "获取失败",
                        'is_vip': False,
                        'content_length': 0,
                        'content_source': "错误",
                        'status': f"[失败] {e}"
                    }
        
        return None
    
    # --- 新增方法：获取文章评论 ---
    def get_article_comments(self, article_url, max_comments=100):
        """
        通过API获取文章评论（自动分页获取所有评论）
        
        Args:
            article_url: 文章URL
            max_comments: 最大获取评论数（默认100，防止无限循环）
        
        Returns:
            str: 格式化后的评论内容
        """
        all_comments = []
        try:
            # 1. 从URL中提取 articleId
            # URL格式通常为: https://blog.csdn.net/username/article/details/12345678
            match = re.search(r'details/(\d+)', article_url)
            if not match:
                return "无法提取ID，跳过评论"
            
            article_id = match.group(1)
            
            # 2. 构造评论API URL
            api_url = f"https://blog.csdn.net/phoenix/web/v1/comment/list/{article_id}"
            
            # 必须带上Referer，否则可能被拦截
            headers = self.get_headers().copy()
            headers['Referer'] = article_url
            
            # 分页获取所有评论
            page = 1
            page_size = 20  # 每页20条
            
            while len(all_comments) < max_comments:
                params = {
                    'page': page,
                    'size': page_size,
                    'fold': 'unfold',
                    'commentId': ''
                }
                
                try:
                    response = self.session.get(api_url, params=params, headers=headers, timeout=5)
                    
                    if response.status_code != 200:
                        if page == 1:
                            return f"HTTP错误 {response.status_code}"
                        break
                    
                    data = response.json()
                    
                    if data.get('code') != 200 or 'data' not in data:
                        if page == 1:
                            return f"API返回错误: {data.get('message', '未知错误')}"
                        break
                    
                    comment_list = data['data'].get('list', [])
                    
                    if not comment_list:
                        break
                    
                    # 处理当前页的评论
                    for item in comment_list:
                        # CSDN评论数据在 info 对象中
                        info = item.get('info', {})
                        content = info.get('content', '').strip()
                        username = info.get('userName', 'Unknown')
                        post_time = info.get('postTime', '')
                        
                        # 处理子评论 (回复)
                        sub_comments = []
                        if item.get('sub', []):
                            for sub in item['sub']:
                                sub_info = sub.get('info', {})
                                sub_c = sub_info.get('content', '').strip()
                                sub_u = sub_info.get('userName', 'Unknown')
                                sub_t = sub_info.get('postTime', '')
                                if sub_c:
                                    sub_comments.append(f"@{sub_u} ({sub_t}): {sub_c}")
                        
                        if content:  # 只添加有内容的评论
                            all_comments.append({
                                'user': username,
                                'content': content,
                                'time': post_time,
                                'replies': sub_comments
                            })
                    
                    # 检查是否还有更多评论
                    total = data['data'].get('total', 0)
                    if len(all_comments) >= total or len(comment_list) < page_size:
                        break
                    
                    page += 1
                    time.sleep(0.5)  # 避免请求过快
                    
                except Exception as e:
                    if page == 1:
                        return f"获取评论异常: {str(e)}"
                    break
            
            # 格式化输出为字符串
            if all_comments:
                formatted_str = f"共 {len(all_comments)} 条评论:\n\n"
                for i, c in enumerate(all_comments, 1):
                    time_str = f" ({c['time']})" if c.get('time') else ""
                    formatted_str += f"{i}. [{c['user']}]{time_str}: {c['content']}\n"
                    if c['replies']:
                        for r in c['replies']:
                            formatted_str += f"   └─ {r}\n"
                    formatted_str += "\n"
                return formatted_str.strip()
            else:
                return "无评论"

        except Exception as e:
            return f"获取评论异常: {str(e)}"
    
    def crawl(self, query: str, max_pages: int = 10, **kwargs) -> List[Dict[str, Any]]:
        """
        主爬取函数 - 实现BaseCrawler的抽象方法
        
        Args:
            query: 搜索关键词
            max_pages: 最大爬取页数
            **kwargs: 其他参数
            
        Returns:
            List[Dict]: 爬取结果列表
        """
        print(f"\n{'='*60}")
        print(f"[CSDN] 爬虫启动 (仅Blog + 评论)")
        print(f"搜索关键词: {query}")
        print(f"爬取页数上限: {max_pages}")
        print(f"VIP模式: {'已启用' if USE_VIP else '未启用'}")
        print(f"{'='*60}\n")
        
        # 搜索文章
        search_results = self.search_articles(query, max_pages, types_list=['blog'])
        
        if not search_results:
            print("[错误] 未找到搜索结果")
            return []
        
        print(f"共找到 {len(search_results)} 篇文章，开始爬取内容...")
        print("="*60)
        
        detailed_results = []
        stats = {
            'total': len(search_results),
            'success': 0,
            'vip_count': 0,
            'failed': 0
        }
        
        for i, article in enumerate(search_results, 1):
            print(f"[{i}/{len(search_results)}] [{article['type']}] {article['title'][:80]}...")
            print(f"   链接: {article['link']}")
            
            result = self.scrape_article_content(article['link'])
            
            if result:
                print(f"   状态: {result['status']}")
                
                if result['content_length'] > 0:
                    stats['success'] += 1
                else:
                    stats['failed'] += 1
                
                if result['is_vip']:
                    stats['vip_count'] += 1
                
                detailed_results.append({
                    'title': article['title'],
                    'link': article['link'],
                    'date': article['date'],
                    'summary': article['summary'],
                    'page': article['page'],
                    'type': article['type'],
                    'content': result['content'],
                    'comments': result.get('comments', '未获取'),
                    'is_vip': result['is_vip'],
                    'content_length': result['content_length'],
                    'content_source': result['content_source'],
                    'scraped_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'site': self.get_source_name()
                })
            
            self.print_progress(i, len(search_results))
            print("-"*50)
            
            time.sleep(CRAWL_DELAY)
        
        # 打印统计信息
        self._print_statistics(stats)
        
        return detailed_results
    
    def _print_statistics(self, stats):
        """打印统计信息"""
        print("="*60)
        print("爬取完成！统计报告:")
        print(f"总数: {stats['total']}")
        print(f"成功: {stats['success']}")
        print(f"失败: {stats['failed']}")
        print(f"VIP内容: {stats['vip_count']}")
        
        if stats['total'] > 0:
            print(f"成功率: {stats['success']/stats['total']*100:.1f}%")
            print(f"VIP比例: {stats['vip_count']/stats['total']*100:.1f}%")
        
        print("="*60)
