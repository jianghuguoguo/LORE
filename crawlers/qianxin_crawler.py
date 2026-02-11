import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import sys

# 添加父目录到路径以导入base_crawler
sys.path.insert(0, str(Path(__file__).parent.parent))

from crawlers.base_crawler import BaseCrawler


class QiAnXinCrawler(BaseCrawler):
    """奇安信攻防社区爬虫"""
    
    def __init__(self, session=None):
        super().__init__(session)
        self.rss_url = "https://forum.butian.net/Rss"
        self.search_url = "https://forum.butian.net/search"
        self.source_name = "qianxin"
    
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
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S%z',
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
        提取文章完整内容
        
        Args:
            url: 文章URL
            
        Returns:
            完整内容或None
        """
        try:
            response = self.safe_request(url, timeout=30)
            
            if not response:
                return None
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # 奇安信论坛的文章内容选择器（优先级从高到低）
            content_selectors = [
                '.article-content',           # 奇安信文章内容
                '.share-content',             # 分享内容
                '.detail-content',            # 详情内容
                '.post-content',              # 帖子内容
                'article .content',           # article标签内的内容
                '.markdown-body',             # Markdown渲染内容
                '#article-content',           # ID选择器
                '.entry-content',             # 条目内容
                'article',                    # article标签
                '.content'                    # 通用内容
            ]
            
            for selector in content_selectors:
                content_div = soup.select_one(selector)
                if content_div:
                    # 移除不需要的元素
                    for unwanted in content_div.select('script, style, nav, aside, .ad, .comment, .share-bar, .author-info, .related-articles'):
                        unwanted.decompose()
                    
                    content = content_div.get_text(separator='\n', strip=True)
                    if len(content) > 100:  # 确保获取到有效内容
                        return content
            
            # 如果上面的选择器都失败，尝试获取main或body内容
            main = soup.find('main') or soup.find('body')
            if main:
                # 移除常见的非内容元素
                for tag in main.select('header, footer, nav, aside, script, style, .sidebar, .menu, .ad, .navbar, .header, .footer'):
                    tag.decompose()
                
                content = main.get_text(separator='\n', strip=True)
                if len(content) > 100:
                    return content
            
            return None
            
        except Exception as e:
            print(f"      ✗ 提取内容失败: {e}")
            return None
    
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
        print(f"🔍 奇安信攻防社区 搜索模式")
        print(f"{'='*80}")
        print(f"搜索URL: {self.search_url}")
        print(f"关键词: {keyword}")
        if max_items:
            print(f"最大数量限制: {max_items}")
        print(f"{'='*80}\n")
        
        if not keyword:
            print("❌ 搜索模式需要提供关键词")
            return []
        
        print("⚠️  警告: 奇安信搜索页面可能需要登录")
        print("💡 建议: 如果搜索失败，请尝试使用RSS模式获取最新内容")
        print("💡 或者: 手动在浏览器中搜索并复制文章链接\n")
        
        try:
            # 构建搜索URL
            search_params = {'word': keyword}
            
            # 添加更多的请求头来模拟浏览器
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://forum.butian.net/',
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
            
            print("[1/3] 发送搜索请求...")
            response = self.session.get(self.search_url, params=search_params, headers=headers, timeout=30)
            
            if not response:
                print("❌ 搜索请求失败")
                return []
            
            print(f"✓ 搜索请求成功 (状态码: {response.status_code})")
            
            # 检查是否需要登录
            if 'login' in response.url.lower() or '登录' in response.text:
                print("❌ 检测到登录页面，搜索功能需要登录")
                print("💡 解决方案:")
                print("   1. 在浏览器中登录 forum.butian.net")
                print("   2. 复制浏览器的Cookie")
                print("   3. 在 crawlers/config.py 中配置 Cookie")
                print("   4. 或者使用RSS模式: use_search=False")
                return []
            
            # 检查是否是JavaScript渲染页面
            if 'doesn\'t work properly without JavaScript' in response.text:
                print("❌ 页面需要JavaScript渲染，无法直接爬取")
                print("💡 解决方案:")
                print("   1. 使用RSS模式获取最新内容")
                print("   2. 或考虑使用Selenium进行JavaScript渲染")
                return []
            
            # 解析搜索结果页面
            print("\n[2/3] 解析搜索结果...")
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # 保存页面内容用于调试
            # with open('debug_search_page.html', 'w', encoding='utf-8') as f:
            #     f.write(response.text)
            # print("💾 页面内容已保存到 debug_search_page.html 供调试")
            
            results = []
            
            # 尝试多种可能的搜索结果选择器
            result_selectors = [
                '.search-result-item',
                '.search-item',
                '.article-item',
                '.post-item',
                'article',
                '.result-item',
                '.list-item',
                '.content-item',
                '.bt-item',
                '.share-item'
            ]
            
            articles = []
            for selector in result_selectors:
                articles = soup.select(selector)
                if articles:
                    print(f"✓ 找到选择器: {selector}, 共 {len(articles)} 条结果")
                    break
            
            if not articles:
                # 如果没有找到标准选择器，尝试查找所有包含链接的项目
                print("⚠️  未找到标准选择器，尝试通用方法...")
                articles = soup.select('a[href*="/share/"]') or soup.select('a[href*="/article/"]')
                
                # 过滤掉非文章链接
                articles = [a for a in articles if a.get('href') and not a.get('href').endswith('/share/create')]
                
                if articles:
                    print(f"✓ 通过链接找到 {len(articles)} 条结果")
            
            if not articles:
                print("⚠️  未找到搜索结果")
                print("💡 可能原因:")
                print("   - 关键词没有匹配的文章")
                print("   - 页面需要登录才能查看")
                print("   - 网站更新了页面结构")
                print("\n建议: 使用RSS模式获取最新内容")
                return []
            
            print(f"\n[3/3] 提取文章信息...")
            current_time = datetime.now()
            
            for i, article in enumerate(articles, 1):
                try:
                    # 提取标题和链接
                    if article.name == 'a':
                        # 如果是链接元素
                        title = article.get_text(strip=True)
                        link = article.get('href', '')
                        
                        # 跳过"创建文章"等功能链接
                        if not title or title in ['文章', '创建', '发布'] or 'create' in link:
                            continue
                    else:
                        # 如果是容器元素
                        title_elem = article.select_one('a, .title, h2, h3, h4')
                        if not title_elem:
                            continue
                        title = title_elem.get_text(strip=True)
                        link = title_elem.get('href', '') if title_elem.name == 'a' else article.select_one('a').get('href', '')
                    
                    if not title or not link or len(title) < 3:  # 标题太短可能不是文章
                        continue
                    
                    # 补全链接
                    if link.startswith('/'):
                        link = f"https://forum.butian.net{link}"
                    elif not link.startswith('http'):
                        link = f"https://forum.butian.net/{link}"
                    
                    # 提取发布时间（如果有）
                    date_elem = article.select_one('.time, .date, time, .publish-time') if article.name != 'a' else None
                    pub_date = date_elem.get_text(strip=True) if date_elem else current_time.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # 提取摘要（如果有）
                    summary_elem = article.select_one('.summary, .description, .excerpt, p') if article.name != 'a' else None
                    summary = summary_elem.get_text(strip=True) if summary_elem else ''
                    
                    # 构建结果
                    result = {
                        'title': title,
                        'link': link,
                        'date': pub_date,
                        'summary': summary[:500] if summary else '',
                        'type': 'article',
                        'source': self.source_name,
                        'site': self.source_name,
                        'search_keyword': keyword
                    }
                    
                    results.append(result)
                    print(f"   [{len(results)}] ✓ {title[:60]}...")
                    
                    # 检查是否达到最大数量
                    if max_items and len(results) >= max_items:
                        print(f"   达到最大数量限制 ({max_items})，停止提取")
                        break
                        
                except Exception as e:
                    print(f"   ✗ 提取失败: {e}")
                    continue
            
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
                print("   3. 检查是否需要登录")
            
            print(f"{'='*80}\n")
            
            return results
            
        except Exception as e:
            print(f"❌ 搜索出错: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def crawl(self, query: str = "", **kwargs) -> List[Dict[str, Any]]:
        """
        爬取奇安信攻防社区
        
        Args:
            query: 搜索关键词（可选）
                - 留空: 爬取所有文章（推荐）
                - 提供关键词: 可用于后续过滤（暂不支持搜索模式）
            **kwargs: 其他参数
                - max_items: 最大返回数量，默认不限制
                - fetch_content: 是否获取完整内容，默认True
                - max_pages: 最大爬取页数，默认94页（全部）
        
        Returns:
            List[Dict]: 爬取结果列表
        """
        max_items = kwargs.get('max_items', None)
        fetch_content = kwargs.get('fetch_content', True)
        max_pages = kwargs.get('max_pages', 94)
        
        # 直接使用文章列表抓取（分页），爬取所有内容
        if query:
            print(f"\n💡 奇安信社区爬虫: 爬取所有文章（关键词 '{query}' 仅用于标记）")
        else:
            print(f"\n💡 奇安信社区爬虫: 爬取所有文章（无关键词过滤）")
        
        print(f"   - 页数范围: 1-{max_pages}")
        print(f"   - 是否获取完整内容: {'是' if fetch_content else '否'}")
        if max_items:
            print(f"   - 最大条目数: {max_items}")
        
        results = self.crawl_article_list(
            base_path='/community',
            max_pages=max_pages, 
            max_items=max_items, 
            fetch_content=fetch_content
        )
        
        # 如果提供了关键词，在结果中添加标记（但不过滤）
        if query and results:
            for item in results:
                item['search_keyword'] = query
        
        return results
    
    def crawl_article_list(self, base_path: str = '/community', max_pages: int = 94, max_items: int = None, fetch_content: bool = True) -> List[Dict[str, Any]]:
        """
        通过分页的文章列表页面爬取最新文章（替代RSS）

        Args:
            base_path: 文章列表页面的路径（相对于域名）
            max_pages: 要抓取的最大页数
            max_items: 最大返回数量
            fetch_content: 是否获取完整内容

        Returns:
            List[Dict]: 文章列表
        """
        print(f"\n{'='*80}")
        print(f"� 奇安信文章列表爬取")
        print(f"{'='*80}")
        print(f"起始路径: {base_path}")
        print(f"页数: {max_pages}, 最大条目: {max_items or '不限'}")
        print(f"是否获取完整内容: {'是' if fetch_content else '否'}")
        print(f"{'='*80}\n")

        results: List[Dict[str, Any]] = []
        domain = 'https://forum.butian.net'
        current_time = datetime.now()

        try:
            for page in range(1, max_pages + 1):
                url = f"{domain}{base_path}" + (f"?page={page}" if page > 1 else "")
                print(f"[页 {page}/{max_pages}] 请求: {url}")
                
                # 增加重试次数和延时
                response = None
                for retry in range(3):
                    try:
                        response = self.safe_request(url, timeout=30)
                        if response:
                            break
                    except Exception as e:
                        if retry < 2:
                            print(f"   [重试 {retry+1}/3] 等待3秒后重试...")
                            time.sleep(3)
                        else:
                            print(f"   ❌ 3次重试均失败: {e}")
                
                if not response:
                    print(f"   ❌ 第 {page} 页请求失败，跳过")
                    continue

                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.content, 'html.parser')

                # 优先常见选择器
                candidates = []
                selectors = [
                    '.stream-list-item',  # 奇安信的文章列表项
                    '.share-item', 
                    '.article-item', 
                    '.post-item', 
                    '.list-item', 
                    '.bt-item', 
                    '.card', 
                    'article'
                ]
                for sel in selectors:
                    found = soup.select(sel)
                    if found:
                        candidates = found
                        print(f"   使用选择器: {sel} -> {len(found)} 项")
                        break

                if not candidates:
                    # 回退到查找所有包含 /share/数字 链接的元素
                    import re
                    all_links = soup.find_all('a', href=re.compile(r'/share/\d+'))
                    # 获取这些链接的父容器
                    candidates = list(set([link.parent for link in all_links]))
                    print(f"   通过 /share/ 链接找到 {len(candidates)} 个候选项")

                page_items = []
                for elem in candidates:
                    try:
                        # 查找文章链接 (匹配 /share/数字)
                        import re
                        title_link = elem.find('a', href=re.compile(r'/share/\d+'))
                        
                        if not title_link:
                            continue
                        
                        title = title_link.get_text(strip=True)
                        href = title_link.get('href')
                        
                        if not title or not href:
                            continue
                        
                        # 过滤掉导航链接和非文章链接
                        if href in ['/', '/question/create', '/share/create', '/questions', '/community', '/movable']:
                            continue
                        if title in ['提问', '文章', '首页', '问答', '攻防', '活动', '首页(current)']:
                            continue
                        if 'create' in href or 'login' in href or 'register' in href:
                            continue

                        if href.startswith('/'):
                            link = domain + href
                        elif href.startswith('http'):
                            link = href
                        else:
                            link = domain + '/' + href

                        # 尝试提取时间与摘要
                        date_elem = elem.select_one('.time, .date, time, .publish-time, .meta time')
                        pub_date = date_elem.get_text(strip=True) if date_elem else current_time.strftime('%Y-%m-%d %H:%M:%S')

                        summary_elem = elem.select_one('.summary, .excerpt, p.content')
                        summary = summary_elem.get_text(strip=True) if summary_elem else ''
                        
                        # 提取作者
                        author_elem = elem.select_one('.author, .username, a[href*="/user/"]')
                        author = author_elem.get_text(strip=True) if author_elem else ''

                        item = {
                            'title': title,
                            'link': link,
                            'date': pub_date,
                            'summary': summary[:500],
                            'author': author,
                            'type': 'article',
                            'source': self.source_name,
                            'site': self.source_name
                        }

                        page_items.append(item)
                        if max_items and len(results) + len(page_items) >= max_items:
                            break

                    except Exception as e:
                        continue

                # 去重并加入总结果
                for item in page_items:
                    # 检查是否已存在（根据链接去重）
                    if not any(r['link'] == item['link'] for r in results):
                        results.append(item)

                print(f"   本页新增 {len(page_items)} 条，累计 {len(results)} 条")

                # 如果需要获取完整内容
                if fetch_content and page_items:
                    print(f"   开始获取本页文章完整内容...")
                    for i, item in enumerate(page_items, 1):
                        if 'content' not in item or not item['content']:
                            print(f"      [{i}/{len(page_items)}] {item['title'][:40]}...")
                            full = self.extract_full_content(item['link'])
                            if full:
                                item['content'] = full
                                item['content_length'] = len(full)
                                print(f"         ✓ 获取 {len(full)} 字符")
                            else:
                                item['content'] = item.get('summary', '')
                                item['content_length'] = len(item.get('summary', ''))
                                print(f"         ✗ 使用摘要 ({item['content_length']} 字符)")
                            time.sleep(1)  # 避免请求过快

                if max_items and len(results) >= max_items:
                    print(f"   达到最大数量限制: {max_items}")
                    break

                # 礼貌延时，避免被封
                if page < max_pages:
                    print(f"   等待2秒后继续...")
                    time.sleep(2)

            # 最终去重并返回
            results = self.deduplicate_results(results)
            print(f"\n{'='*80}")
            print(f"📊 爬取完成，总计 {len(results)} 条记录")
            print(f"{'='*80}\n")
            return results

        except Exception as e:
            print(f"❌ 列表爬取失败: {e}")
            return results
    
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
    print("奇安信攻防社区爬虫测试")
    print("="*80)
    
    # 创建爬虫实例
    crawler = QiAnXinCrawler()
    
    # 测试1: 搜索模式（支持历史内容）
    print("\n测试1: 搜索模式 - 搜索CVE-2024-23897")
    results = crawler.crawl(query="CVE-2024-23897", max_items=5, fetch_content=False)
    
    if results:
        print(f"\n找到 {len(results)} 条记录:")
        for i, item in enumerate(results[:3], 1):
            print(f"\n{i}. {item['title']}")
            print(f"   链接: {item['link']}")
            print(f"   时间: {item.get('date', 'N/A')}")
    else:
        print("未找到记录")
    
    # 测试2: RSS模式（仅最新内容）
    print("\n" + "="*80)
    print("\n测试2: RSS模式 - 获取最新文章")
    results = crawler.crawl(query="", max_items=5, use_search=False, fetch_content=False)
    
    if results:
        print(f"\n获取到 {len(results)} 条记录")
    else:
        print("未获取到记录")
    
    print("\n" + "="*80)
    print("测试完成")


if __name__ == "__main__":
    main()
