#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
先知安全技术社区爬虫模块
通过RSS Feed获取文章
数据源: https://xz.aliyun.com/feed
"""

import feedparser
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import sys

# 添加父目录到路径以导入base_crawler
sys.path.insert(0, str(Path(__file__).parent.parent))

from crawlers.base_crawler import BaseCrawler


class XianZhiCrawler(BaseCrawler):
    """先知安全技术社区爬虫"""
    
    def __init__(self, session=None):
        super().__init__(session)
        self.rss_url = "https://xz.aliyun.com/feed"
        self.search_url = "https://xz.aliyun.com/search"  # 搜索页面
        self.source_name = "xianzhi"
    
    def get_source_name(self) -> str:
        """返回数据源名称"""
        return self.source_name
    
    def setup_session(self):
        """设置会话请求头"""
        super().setup_session()
        self.session.headers.update({
            'Cache-Control': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        })
    
    def parse_time(self, time_str: str) -> Optional[datetime]:
        """
        解析时间字符串
        
        Args:
            time_str: 时间字符串
            
        Returns:
            datetime对象或None
        """
        # RSS Feed常见的时间格式
        time_formats = [
            '%a, %d %b %Y %H:%M:%S %z',  # RFC 2822格式
            '%Y-%m-%dT%H:%M:%S%z',       # RFC 3339格式
            '%Y-%m-%dT%H:%M:%SZ',        # ISO 8601格式
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S %z'
        ]
        
        for fmt in time_formats:
            try:
                # 移除时区信息中的冒号 (如 +08:00 -> +0800)
                cleaned_str = time_str.replace('+08:00', '+0800').replace('-08:00', '-0800')
                dt = datetime.strptime(cleaned_str, fmt)
                # 如果没有时区信息，假设为东八区
                if dt.tzinfo is None:
                    # 转换为东八区时间
                    from datetime import timezone
                    dt = dt.replace(tzinfo=timezone(timedelta(hours=8)))
                # 转换为本地时间（不带时区）
                return dt.replace(tzinfo=None)
            except (ValueError, AttributeError):
                continue
        
        # 如果所有格式都失败，返回None
        print(f"   [警告] 无法解析时间: {time_str}")
        return None
    
    def extract_full_content(self, url: str) -> Optional[str]:
        """
        提取文章完整内容 - 使用Selenium绕过WAF

        Args:
            url: 文章URL

        Returns:
            完整内容或None
        """
        try:
            print(f"      [提取全文] {url}")

            # 使用Selenium绕过WAF获取内容
            content = self._extract_with_selenium(url)
            if content:
                return content

            print("      ⚠️ Selenium提取失败")
            return None

        except Exception as e:
            print(f"      ✗ 提取失败: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _extract_with_selenium(self, url: str) -> Optional[str]:
        """
        使用Selenium绕过WAF获取内容
        
        Args:
            url: 文章URL
            
        Returns:
            完整内容或None
        """
        try:
            print("      [方法1] 尝试使用Selenium...")
            
            # 检查是否安装了selenium和webdriver-manager
            try:
                from selenium import webdriver
                from selenium.webdriver.common.by import By
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                from selenium.webdriver.chrome.options import Options
                from webdriver_manager.chrome import ChromeDriverManager
                from selenium.webdriver.chrome.service import Service
            except ImportError as e:
                print(f"      ⚠️ 缺少依赖: {e}，跳过此方法")
                return None

            # 配置Chrome选项
            chrome_options = Options()
            chrome_options.add_argument('--headless')  # 无头模式
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # 随机User-Agent
            chrome_options.add_argument(f'user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')

            try:
                # 使用webdriver-manager自动管理ChromeDriver
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)
                
                # 隐藏webdriver特征
                driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                    'source': '''
                        Object.defineProperty(navigator, 'webdriver', {
                            get: () => undefined
                        })
                    '''
                })

                driver.get(url)
                
                # 等待页面加载完成（最多等待10秒）
                WebDriverWait(driver, 10).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )
                
                # 额外等待JavaScript执行
                time.sleep(3)
                
                # 尝试多种选择器提取内容
                selectors = [
                    '.article-content', '.news-content', '.content',
                    '.post-content', 'article', '.detail-content',
                    '.markdown-body', '.main-content'
                ]
                
                for selector in selectors:
                    try:
                        elements = driver.find_elements(By.CSS_SELECTOR, selector)
                        if elements:
                            content = elements[0].text
                            if len(content) > 100:
                                print(f"      ✓ Selenium成功提取内容 (选择器: {selector}, 长度: {len(content)})")
                                driver.quit()
                                return content
                    except:
                        continue
                
                # 如果所有选择器都失败，获取body文本
                body = driver.find_element(By.TAG_NAME, 'body')
                content = body.text
                driver.quit()
                
                if len(content) > 100:
                    print(f"      ✓ Selenium从body提取内容 (长度: {len(content)})")
                    return content
                
                return None
                
            except Exception as e:
                print(f"      ⚠️ Selenium执行失败: {e}")
                try:
                    driver.quit()
                except:
                    pass
                return None

        except Exception as e:
            print(f"      ⚠️ Selenium方法异常: {e}")
            return None








    def crawl_article_list(self, start_page: int = 1, max_pages: int = 5, max_items: int = None) -> List[Dict[str, Any]]:
        """
        爬取先知首页文章列表（不需要登录，更可靠）
        
        Args:
            start_page: 起始页码
            max_pages: 最大爬取页数
            max_items: 最大返回数量
            
        Returns:
            List[Dict]: 文章列表
        """
        print(f"\n{'='*80}")
        print(f"📄 先知安全技术社区 文章列表模式")
        print(f"{'='*80}")
        print(f"列表URL: {self.list_url}")
        print(f"起始页码: {start_page}")
        print(f"最大页数: {max_pages}")
        if max_items:
            print(f"最大数量限制: {max_items}")
        print(f"{'='*80}\n")
        
        results = []
        
        try:
            end_page = start_page + max_pages
            for page in range(start_page, end_page):
                print(f"\n[{page}/{end_page-1}] 爬取第 {page} 页...")
                
                # 构建URL
                if page == 1:
                    page_url = self.list_url
                else:
                    page_url = f"{self.list_url}/?page={page}"
                
                # 发送请求
                response = self.safe_request(page_url, timeout=30)
                
                if not response:
                    print(f"  ✗ 第 {page} 页请求失败")
                    continue
                
                print(f"  ✓ 请求成功 (状态码: {response.status_code})")
                
                # 解析HTML
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # 查找文章列表（根据参考代码，使用tr标签）
                article_items = soup.find_all("tr")
                
                if not article_items:
                    print(f"  ⚠️  第 {page} 页未找到文章")
                    break
                
                print(f"  ✓ 找到 {len(article_items)} 篇文章")
                
                page_count = 0
                for item in article_items:
                    try:
                        # 提取文章信息（参考原代码的结构）
                        p_tags = item.find_all("p")
                        
                        if len(p_tags) < 2:
                            continue
                        
                        # 第一个p标签包含标题和链接
                        p1 = p_tags[0]
                        if not p1.a:
                            continue
                        
                        article_link = self.list_url + p1.a.attrs.get('href', '')
                        article_title = p1.a.string
                        
                        if article_title:
                            article_title = article_title.strip()
                        else:
                            article_title = p1.a.get_text(strip=True)
                        
                        if not article_title or not article_link:
                            continue
                        
                        # 第二个p标签包含作者、分类、时间等信息
                        p2 = p_tags[1]
                        
                        # 提取作者
                        author_links = p2.find_all("a")
                        author_name = ""
                        classification = ""
                        
                        if len(author_links) >= 1:
                            author_name = author_links[0].string or author_links[0].get_text(strip=True)
                        
                        if len(author_links) >= 2:
                            classification = author_links[1].string or author_links[1].get_text(strip=True)
                        
                        # 提取时间
                        p2_text = p2.get_text()
                        time_match = re.search(r'(\d{4}-\d{2}-\d{2})', p2_text)
                        pub_date = time_match.group(1) if time_match else datetime.now().strftime('%Y-%m-%d')
                        
                        # 提取浏览数（可选）
                        page_view_match = re.search(r'浏览数\s*(\d+)', p2_text)
                        page_view = int(page_view_match.group(1)) if page_view_match else 0
                        
                        # 构建结果
                        result = {
                            'title': article_title,
                            'link': article_link,
                            'date': pub_date,
                            'author': author_name,
                            'classification': classification,
                            'page_view': page_view,
                            'summary': '',
                            'type': 'article',
                            'source': self.source_name,
                            'site': self.source_name
                        }
                        
                        results.append(result)
                        page_count += 1
                        
                        print(f"    [{page_count}] ✓ {article_title[:50]}...")
                        
                        # 检查是否达到最大数量
                        if max_items and len(results) >= max_items:
                            print(f"\n  达到最大数量限制 ({max_items})，停止爬取")
                            break
                            
                    except Exception as e:
                        print(f"    ✗ 提取失败: {e}")
                        continue
                
                # 如果达到最大数量，停止翻页
                if max_items and len(results) >= max_items:
                    break
                
                # 添加延时避免请求过快
                time.sleep(1)
            
            # 去重
            results = self.deduplicate_results(results)
            
            print(f"\n{'='*80}")
            print(f"📊 爬取完成")
            print(f"{'='*80}")
            print(f"总计: {len(results)} 条记录")
            print(f"{'='*80}\n")
            
            return results
            
        except Exception as e:
            print(f"❌ 爬取出错: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def search_articles(self, keyword: str, max_items: int = None) -> List[Dict[str, Any]]:
        """
        通过搜索页面爬取文章（支持历史内容搜索）
        
        Args:
            keyword: 搜索关键词
            max_items: 最大返回数量
            
        Returns:
            List[Dict]: 文章列表
        """
        print(f"\n{'='*80}")
        print(f"🔍 先知安全技术社区 搜索模式")
        print(f"{'='*80}")
        print(f"搜索URL: {self.search_url}")
        print(f"关键词: {keyword}")
        if max_items:
            print(f"最大数量限制: {max_items}")
        print(f"{'='*80}\n")
        
        if not keyword:
            print("❌ 搜索模式需要提供关键词")
            return []
        
        try:
            results = []
            current_time = datetime.now()
            max_pages = 10  # 限制最大搜索页数，避免无限循环
            
            for page in range(1, max_pages + 1):
                print(f"\n[页 {page}/{max_pages}] 搜索第 {page} 页...")
                
                # 构建搜索URL（参照用户提供的格式）
                search_url = f"{self.search_url}/{page}?keywords={keyword}"
                
                # 添加请求头
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Referer': 'https://xz.aliyun.com/',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Cache-Control': 'max-age=0'
                }
                
                response = self.session.get(search_url, headers=headers, timeout=30)
                
                if not response or response.status_code != 200:
                    print(f"   ❌ 第 {page} 页请求失败 (状态码: {response.status_code if response else 'N/A'})")
                    break
                
                print(f"   ✓ 请求成功 (状态码: {response.status_code})")
                
                # 解析搜索结果页面
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # 先知社区搜索结果的选择器（基于页面结构分析）
                result_selectors = [
                    '.search-result-item',
                    '.search-item', 
                    '.article-item',
                    '.post-item',
                    'article',
                    '.result-item',
                    '.list-item',
                    '.content-item',
                    '.topic-item',
                    '.newslist-item',
                    'tr',  # 表格行（类似原代码）
                    '.item'
                ]
                
                articles = []
                for selector in result_selectors:
                    articles = soup.select(selector)
                    if articles:
                        print(f"   ✓ 找到选择器: {selector}, 共 {len(articles)} 条结果")
                        break
                
                if not articles:
                    # 如果标准选择器失败，尝试查找所有包含文章链接的元素
                    print("   ⚠️ 未找到标准选择器，尝试通用方法...")
                    articles = soup.select('a[href*="/t/"]') or soup.select('a[href*="/article/"]') or soup.select('a[href*="/node/"]')
                    articles = [a for a in articles if a.get('href') and len(a.get_text(strip=True)) > 3]
                    
                    if articles:
                        print(f"   ✓ 通过链接找到 {len(articles)} 条结果")
                
                if not articles:
                    print(f"   ⚠️ 第 {page} 页未找到搜索结果")
                    break
                
                print(f"   开始提取第 {page} 页的文章信息...")
                page_results = []
                
                for i, article in enumerate(articles, 1):
                    try:
                        # 提取标题和链接
                        if article.name == 'a':
                            # 如果是链接元素
                            title = article.get_text(strip=True)
                            link = article.get('href', '')
                        else:
                            # 如果是容器元素
                            title_elem = article.select_one('a, .title, h2, h3, h4, .topic-title')
                            if not title_elem:
                                continue
                            title = title_elem.get_text(strip=True)
                            link = title_elem.get('href', '') if title_elem.name == 'a' else (article.select_one('a').get('href', '') if article.select_one('a') else '')
                        
                        if not title or not link or len(title) < 3:
                            continue
                        
                        # 过滤掉导航链接
                        if link in ['/', '/search', '/login', '/register'] or 'search' in link:
                            continue
                        
                        # 补全链接
                        if link.startswith('/'):
                            link = f"https://xz.aliyun.com{link}"
                        elif not link.startswith('http'):
                            link = f"https://xz.aliyun.com/{link}"
                        
                        # 提取时间和作者信息
                        date_elem = article.select_one('.time, .date, time, .publish-time, .topic-time')
                        pub_date = date_elem.get_text(strip=True) if date_elem else current_time.strftime('%Y-%m-%d %H:%M:%S')
                        
                        author_elem = article.select_one('.author, .username, a[href*="/u/"]')
                        author = author_elem.get_text(strip=True) if author_elem else ''
                        
                        # 提取摘要
                        summary_elem = article.select_one('.summary, .description, .excerpt, p, .topic-summary')
                        summary = summary_elem.get_text(strip=True) if summary_elem else ''
                        
                        # 构建结果
                        result = {
                            'title': title,
                            'link': link,
                            'date': pub_date,
                            'author': author,
                            'summary': summary[:500] if summary else '',
                            'type': 'article',
                            'source': self.source_name,
                            'site': self.source_name,
                            'search_keyword': keyword
                        }
                        
                        page_results.append(result)
                        print(f"     [{len(page_results)}] ✓ {title[:60]}...")
                        
                        # 检查是否达到最大数量
                        if max_items and len(results) + len(page_results) >= max_items:
                            break
                            
                    except Exception as e:
                        print(f"     ✗ 提取失败: {e}")
                        continue
                
                # 添加本页结果到总结果
                results.extend(page_results)
                
                print(f"   本页新增 {len(page_results)} 条，累计 {len(results)} 条")
                
                # 检查是否达到最大数量或没有新结果
                if max_items and len(results) >= max_items:
                    print(f"   达到最大数量限制 ({max_items})")
                    break
                
                if len(page_results) == 0:
                    print(f"   第 {page} 页没有新结果，停止翻页")
                    break
                
                # 延时避免请求过快
                time.sleep(2)
            
            # 去重
            results = self.deduplicate_results(results)
            
            print(f"\n{'='*80}")
            print(f"📊 搜索完成")
            print(f"{'='*80}")
            print(f"总计: {len(results)} 条记录")
            
            if len(results) == 0:
                print("\n💡 搜索未找到结果，建议:")
                print("   1. 尝试其他关键词")
                print("   2. 使用RSS模式: crawler.crawl(query='', use_search=False)")
            
            print(f"{'='*80}\n")
            
            return results
            
        except Exception as e:
            print(f"❌ 搜索出错: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def search_articles_by_keyword(self, keyword: str, start_page: int = 1, max_pages: int = 10, max_items: int = None) -> List[Dict[str, Any]]:
        """
        通过关键词搜索文章（支持分页）
        
        Args:
            keyword: 搜索关键词（可为空，表示搜索所有内容）
            start_page: 起始页码
            max_pages: 最大搜索页数
            max_items: 最大返回数量
            
        Returns:
            List[Dict]: 文章列表
        """
        print(f"\n{'='*80}")
        print(f"🔍 先知安全技术社区 关键词搜索")
        print(f"{'='*80}")
        print(f"关键词: '{keyword}' (空关键词表示搜索所有内容)")
        print(f"起始页码: {start_page}")
        print(f"最大页数: {max_pages}")
        if max_items:
            print(f"最大数量限制: {max_items}")
        print(f"{'='*80}\n")
        
        try:
            results = []
            current_time = datetime.now()
            
            # 确保 max_pages 不是 None，如果是None表示爬取所有内容
            if max_pages is None:
                max_pages = 1000  # 设置一个很大的数字表示爬取所有内容
            
            # 先知社区使用API获取搜索数据
            api_url = "https://xz.aliyun.com/search/data"
            
            end_page = start_page + max_pages
            for page in range(start_page, end_page):
                print(f"\n[页 {page}/{end_page-1}] 搜索第 {page} 页...")
                
                # API参数
                params = {
                    'type': '3',  # 3表示文章搜索
                    'limit': '12',  # 每页12条
                    'page': str(page),
                    'keywords': keyword
                }
                
                # 添加请求头（修复中文编码问题）
                from urllib.parse import quote
                encoded_keyword = quote(keyword) if keyword else ''
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Referer': f'https://xz.aliyun.com/search/3?page={page}&limit=12&keywords={encoded_keyword}',
                    'Connection': 'keep-alive',
                    'X-Requested-With': 'XMLHttpRequest'
                }
                
                # 发送请求（修复中文编码问题）
                response = self.session.get(api_url, params=params, headers=headers, timeout=30)
                
                if not response or response.status_code != 200:
                    print(f"   ❌ 第 {page} 页请求失败 (状态码: {response.status_code if response else 'N/A'})")
                    break
                
                try:
                    data = response.json()
                except:
                    print(f"   ❌ 第 {page} 页返回的不是JSON格式")
                    break
                
                # 检查是否有数据
                html_content = data.get('data', '')
                if not html_content:
                    print(f"   ⚠️ 第 {page} 页没有搜索结果")
                    break
                
                print(f"   ✓ 获取到HTML内容，长度: {len(html_content)}")
                
                # 解析API返回的HTML数据
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # 查找文章元素（基于API返回的HTML结构）
                articles = soup.select('.news_item')
                if not articles:
                    # 如果没有找到，尝试其他选择器
                    articles = soup.select('.item, .article-item, .post-item')
                
                if not articles:
                    print(f"   ⚠️ 第 {page} 页无法解析文章数据")
                    # 保存调试信息
                    with open(f'debug_page_{page}.html', 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    print(f"   💾 调试信息已保存到 debug_page_{page}.html")
                    break
                
                print(f"   解析到 {len(articles)} 个文章元素")
                
                page_results = []
                for article in articles:
                    try:
                        # 查找标题和链接（使用正确的选择器）
                        title_elem = article.select_one('.news_title')
                        if not title_elem:
                            continue
                        
                        title = title_elem.get_text(strip=True)
                        link = title_elem.get('href', '')
                        
                        if not title or not link:
                            continue
                        
                        # 过滤导航链接
                        if link in ['/', '/search'] or 'search' in link:
                            continue
                        
                        # 补全链接
                        if link.startswith('/'):
                            link = f"https://xz.aliyun.com{link}"
                        elif not link.startswith('http'):
                            link = f"https://xz.aliyun.com/{link}"
                        
                        # 提取时间和作者信息（基于实际HTML结构）
                        pub_date = current_time.strftime('%Y-%m-%d %H:%M:%S')
                        date_elem = article.select_one('.news_bm span')
                        if date_elem:
                            date_text = date_elem.get_text(strip=True)
                            # 提取日期部分，如 "2024-02-01 06:10"
                            import re
                            date_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2})', date_text)
                            if date_match:
                                date_str = date_match.group(1)
                                try:
                                    # 解析为datetime对象
                                    pub_date = datetime.strptime(date_str, '%Y-%m-%d %H:%M').strftime('%Y-%m-%d %H:%M:%S')
                                except:
                                    pass  # 如果解析失败，使用默认时间
                        
                        author_elem = article.select_one('.user-info .txt-hide')
                        author = author_elem.get_text(strip=True) if author_elem else ''
                        
                        # 提取摘要
                        summary_elem = article.select_one('.news_word p')
                        summary = summary_elem.get_text(strip=True) if summary_elem else ''
                        
                        # 构建结果
                        result = {
                            'title': title,
                            'link': link,
                            'date': pub_date,
                            'author': author,
                            'summary': summary[:500] if summary else '',
                            'type': 'article',
                            'source': self.source_name,
                            'site': self.source_name,
                            'search_keyword': keyword if keyword else ''
                        }
                        
                        page_results.append(result)
                        
                        # 检查是否达到最大数量
                        if max_items and len(results) + len(page_results) >= max_items:
                            break
                            
                    except Exception as e:
                        print(f"     ✗ 解析文章失败: {e}")
                        continue
                
                # 添加本页结果到总结果
                results.extend(page_results)
                
                print(f"   本页新增 {len(page_results)} 条，累计 {len(results)} 条")
                
                # 检查是否达到最大数量或没有新结果
                if max_items and len(results) >= max_items:
                    print(f"   达到最大数量限制 ({max_items})")
                    break
                
                if len(page_results) == 0:
                    print(f"   第 {page} 页没有新结果，停止翻页")
                    break
                
                # 延时避免请求过快
                time.sleep(2)
            
            # 去重
            results = self.deduplicate_results(results)
            
            print(f"\n{'='*80}")
            print(f"📊 搜索完成")
            print(f"{'='*80}")
            print(f"总计: {len(results)} 条记录")
            
            if len(results) == 0:
                print("\n💡 搜索未找到结果，建议:")
                print("   1. 尝试其他关键词")
                print("   2. 检查网络连接")
                print("   3. 使用RSS模式: crawler.crawl(query='', use_search=False)")
            
            print(f"{'='*80}\n")
            
            return results
            
        except Exception as e:
            print(f"❌ 搜索出错: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def crawl(self, query: str = "", **kwargs) -> List[Dict[str, Any]]:
        """
        爬取先知安全技术社区
        
        Args:
            query: 搜索关键词（可选）
                - 提供关键词: 通过搜索页面爬取相关文章
                - 留空: 爬取所有文章（通过搜索页面分页）
            **kwargs: 其他参数
                - max_items: 最大返回数量，默认不限制
                - fetch_content: 是否获取完整内容，默认True
                - max_pages: 最大搜索页数
                - start_page: 起始页码，默认1
        
        Returns:
            List[Dict]: 爬取结果列表
        """
        max_items = kwargs.get('max_items', None)
        fetch_content = kwargs.get('fetch_content', True)
        max_pages = kwargs.get('max_pages')  # 如果没提供就是None，表示爬取所有
        start_page = kwargs.get('start_page', 1)
        
        # 如果有关键词，使用搜索模式
        if query:
            print(f"\n💡 先知社区爬虫: 搜索模式 - 关键词 '{query}'")
            print(f"   - 起始页码: {start_page}")
            print(f"   - 最大页数: {max_pages if max_pages else '不限制（爬取所有内容）'}")
            print(f"   - 是否获取完整内容: {'是' if fetch_content else '否'}")
            if max_items:
                print(f"   - 最大条目数: {max_items}")
            
            results = self.search_articles_by_keyword(query, start_page=start_page, max_pages=max_pages, max_items=max_items)
        else:
            # 如果没有关键词，爬取所有文章（通过搜索空关键词或热门内容）
            print(f"\n💡 先知社区爬虫: 爬取所有文章（通过搜索页面）")
            print(f"   - 起始页码: {start_page}")
            print(f"   - 最大页数: {max_pages if max_pages else '不限制（爬取所有内容）'}")
            print(f"   - 是否获取完整内容: {'是' if fetch_content else '否'}")
            if max_items:
                print(f"   - 最大条目数: {max_items}")
            
            # 使用空关键词搜索来获取所有文章（或使用热门关键词）
            results = self.search_articles_by_keyword("", start_page=start_page, max_pages=max_pages, max_items=max_items)
        
        # 如果需要获取完整内容
        if fetch_content and results:
            print(f"\n📖 开始获取完整内容...")
            success_count = 0
            for i, result in enumerate(results, 1):
                if 'content' not in result or not result['content']:
                    print(f"[{i}/{len(results)}] 处理: {result['title'][:50]}...")
                    full_content = self.extract_full_content(result['link'])
                    if full_content and len(full_content) > len(result.get('summary', '')):
                        result['content'] = full_content
                        result['content_length'] = len(full_content)
                        print(f"   ✓ 获取 {len(full_content)} 字符")
                        success_count += 1
                    else:
                        # 如果无法获取完整内容，使用摘要或标题作为内容
                        fallback_content = result.get('summary', '').strip()
                        if not fallback_content:
                            fallback_content = result.get('title', '').strip()
                        result['content'] = fallback_content
                        result['content_length'] = len(fallback_content)
                        print(f"   ⚠️ 使用摘要作为内容 ({result['content_length']} 字符)")
                    time.sleep(2)  # 增加延时避免触发WAF
            print(f"   📊 内容提取完成: {success_count}/{len(results)} 成功")
        else:
            print(f"\n📋 跳过内容提取 (fetch_content={fetch_content})")
        
        return results
    
    def _crawl_rss(self, query: str = "", max_items: int = None, fetch_content: bool = True) -> List[Dict[str, Any]]:
        """
        通过RSS Feed爬取（原crawl方法的逻辑）
        
        Args:
            query: 搜索关键词（可选，用于过滤标题）
            max_items: 最大返回数量
            fetch_content: 是否获取完整内容
        
        Returns:
            List[Dict]: 爬取结果列表
        """
        print(f"\n{'='*80}")
        print(f"📡 先知安全技术社区 RSS爬虫")
        print(f"{'='*80}")
        print(f"RSS源: {self.rss_url}")
        if query:
            print(f"关键词过滤: {query}")
        if max_items:
            print(f"最大数量限制: {max_items}")
        print(f"获取完整内容: {'是' if fetch_content else '否'}")
        print(f"{'='*80}\n")
        
        # 获取RSS Feed
        try:
            print("[1/3] 获取RSS Feed...")
            response = self.safe_request(self.rss_url, timeout=30)
            
            if not response:
                print("❌ 获取RSS Feed失败")
                return []
            
            print(f"✓ RSS Feed获取成功 (状态码: {response.status_code})")
            
            # 解析RSS Feed
            print("\n[2/3] 解析RSS Feed...")
            feed = feedparser.parse(response.content)
            
            if not feed.entries:
                print("⚠️  RSS Feed中没有条目")
                return []
            
            print(f"✓ 解析完成，共 {len(feed.entries)} 条记录")
            
            # 处理条目
            print(f"\n[3/3] 处理RSS条目...")
            results = []
            current_time = datetime.now()
            
            for i, entry in enumerate(feed.entries, 1):
                # 解析发布时间
                pub_time_str = entry.get('published', '') or entry.get('updated', '')
                
                if not pub_time_str:
                    print(f"   [{i}] 跳过（无时间信息）: {entry.get('title', 'N/A')}")
                    continue
                
                pub_time = self.parse_time(pub_time_str)
                
                if not pub_time:
                    print(f"   [{i}] 跳过（时间解析失败）: {entry.get('title', 'N/A')}")
                    continue
                
                # 计算时间差（仅用于显示）
                time_diff = current_time - pub_time
                hours_diff = time_diff.total_seconds() / 3600
                
                # 提取信息
                title = entry.get('title', '').strip()
                link = entry.get('link', '') or entry.get('id', '')
                summary = entry.get('summary', '') or entry.get('description', '')
                
                # 移除HTML标签
                if summary:
                    from bs4 import BeautifulSoup
                    summary = BeautifulSoup(summary, 'html.parser').get_text().strip()
                
                # 关键词过滤
                if query and query.lower() not in title.lower() and query.lower() not in summary.lower():
                    print(f"   [{i}] 跳过（不匹配关键词）: {title}")
                    continue
                
                # 构建结果
                result = {
                    'title': title,
                    'link': link,
                    'date': pub_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'summary': summary[:500] if summary else '',  # 限制摘要长度
                    'published': pub_time_str,
                    'hours_ago': round(hours_diff, 1),
                    'type': 'article',
                    'source': self.source_name,
                    'site': self.source_name
                }
                
                # 获取完整内容（如果需要）
                if fetch_content:
                    full_content = self.extract_full_content(link)
                    if full_content:
                        result['content'] = full_content
                        result['content_length'] = len(full_content)
                    else:
                        result['content'] = summary  # 回退到摘要
                        result['content_length'] = len(summary)
                else:
                    result['content'] = summary
                    result['content_length'] = len(summary)
                
                results.append(result)
                
                print(f"   [{i}] ✓ {pub_time.strftime('%Y-%m-%d %H:%M:%S')} - {title}")
                
                # 检查是否达到最大数量
                if max_items and len(results) >= max_items:
                    print(f"   达到最大数量限制 ({max_items})，停止爬取")
                    break
            
            # 去重
            results = self.deduplicate_results(results)
            
            print(f"\n{'='*80}")
            print(f"📊 爬取完成")
            print(f"{'='*80}")
            print(f"总计: {len(results)} 条记录")
            print(f"{'='*80}\n")
            
            if not results:
                print(f"⚠️  没有符合条件的文章")
            
            return results
            
        except Exception as e:
            print(f"❌ 爬取出错: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_latest_articles(self, max_items: int = None, fetch_content: bool = True) -> List[Dict[str, Any]]:
        """
        获取最新文章（便捷方法）
        
        Args:
            max_items: 最大返回数量
            fetch_content: 是否获取完整内容
            
        Returns:
            List[Dict]: 文章列表
        """
        return self.crawl(query="", max_items=max_items, fetch_content=fetch_content)
    
    def search_by_keyword(self, keyword: str, fetch_content: bool = True) -> List[Dict[str, Any]]:
        """
        按关键词搜索文章
        
        Args:
            keyword: 搜索关键词
            fetch_content: 是否获取完整内容
            
        Returns:
            List[Dict]: 匹配的文章列表
        """
        return self.crawl(query=keyword, fetch_content=fetch_content)


def main():
    """测试爬虫"""
    print("先知安全技术社区爬虫测试")
    print("="*80)
    
    # 创建爬虫实例
    crawler = XianZhiCrawler()
    
    # 测试1: 搜索模式（使用新的搜索页面）
    print("\n测试1: 搜索模式 - 搜索CVE-2024-23897")
    results = crawler.crawl(query="CVE-2024-23897", max_items=5, fetch_content=False)
    
    if results:
        print(f"\n找到 {len(results)} 条记录:")
        for i, item in enumerate(results[:3], 1):
            print(f"\n{i}. {item['title']}")
            print(f"   链接: {item['link']}")
            print(f"   时间: {item.get('date', 'N/A')}")
            print(f"   作者: {item.get('author', 'N/A')}")
    else:
        print("未找到记录")
    
    # 测试2: 爬取所有文章（空关键词）
    print("\n" + "="*80)
    print("\n测试2: 爬取所有文章（通过搜索页面）")
    results = crawler.crawl(query="", max_items=5, fetch_content=False)
    
    if results:
        print(f"\n获取到 {len(results)} 条记录:")
        for i, item in enumerate(results[:3], 1):
            print(f"\n{i}. {item['title']}")
            print(f"   链接: {item['link']}")
            print(f"   时间: {item.get('date', 'N/A')}")
    else:
        print("未获取到记录")
    
    # 测试3: 分批爬取示例
    print("\n" + "="*80)
    print("\n测试3: 分批爬取示例 (第128-290页)")
    # 假设每页12条，爬取163页约1956条
    results = crawler.crawl(query="", start_page=128, max_pages=200, fetch_content=False)
    
    if results:
        print(f"\n获取到 {len(results)} 条记录")
        print("下次可以从第3页开始: start_page=3")
    else:
        print("未获取到记录")
    
    print("\n" + "="*80)
    print("测试完成")


if __name__ == "__main__":
    main()
