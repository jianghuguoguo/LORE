import json
import time
import random
import logging
import os
import re
from datetime import datetime
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional
import requests
import urllib3
from pathlib import Path
import sys

# 添加父目录到路径以导入 base_crawler
sys.path.insert(0, str(Path(__file__).parent.parent))

from crawlers.base_crawler import BaseCrawler
from wechat_article_crawler.config import WECHAT_CONFIG, WECHAT_MAX_PAGES, WECHAT_CRAWL_DELAY

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WeChatCrawler(BaseCrawler):
    """微信公众号文章爬虫"""
    
    def __init__(self, session: Optional[requests.Session] = None):
        super().__init__(session)
        self.config = WECHAT_CONFIG
        self.logger = logging.getLogger("WeChatCrawler")
        self._setup_wechat_headers()
        
    def _setup_wechat_headers(self):
        """设置微信专用的请求头"""
        self.headers = {
            'Host': 'mp.weixin.qq.com',
            'Cookie': self.config.get('COOKIE', ''),
            'x-wechat-key': self.config.get('X_WECHAT_KEY', ''),
            'x-wechat-uin': self.config.get('X_WECHAT_UIN', ''),
            'exportkey': self.config.get('EXPORTKEY', ''),
            'user-agent': self.config.get('USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'zh-CN,zh;q=0.9',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-user': '?1',
            'sec-fetch-dest': 'document'
        }
        self.session.headers.update(self.headers)

    def get_source_name(self) -> str:
        return 'wechat'

    def get_article_list(self, offset=0) -> Optional[Dict]:
        """获取文章列表"""
        url = 'https://mp.weixin.qq.com/mp/profile_ext'
        params = {
            'action': 'getmsg',
            '__biz': self.config.get('BIZ', ''),
            'offset': offset,
            'count': '10',
            'uin': self.headers.get('x-wechat-uin', '').replace('%3D%3D', '=='),
            'key': self.headers.get('x-wechat-key', ''),
            'f': 'json'
        }

        try:
            time.sleep(random.uniform(2, 5))
            response = self.session.get(url, params=params, verify=False, timeout=10)
            data = response.json()

            if data.get('ret') == 0:
                return json.loads(data.get('general_msg_list', '{"list":[]}'))
            else:
                self.logger.error(f"Failed to get article list: {data}")
                return None
        except Exception as e:
            self.logger.error(f"Error getting article list: {str(e)}")
            return None

    def extract_location_info(self, html_content: str) -> str:
        """提取发布位置信息"""
        try:
            ip_wording_match = re.search(r'window.ip_wording\s*=\s*({[^}]+})', html_content)
            if ip_wording_match:
                ip_data_str = ip_wording_match.group(1)
                ip_data_str = re.sub(r'\s+', ' ', ip_data_str.strip())
                ip_data_str = re.sub(r'(\w+):', r'"\1":', ip_data_str)
                ip_data_str = ip_data_str.replace("'", '"')

                try:
                    ip_data = json.loads(ip_data_str)
                    location_parts = []
                    if ip_data.get('countryName'): location_parts.append(ip_data['countryName'])
                    if ip_data.get('provinceName'): location_parts.append(ip_data['provinceName'])
                    if ip_data.get('cityName'): location_parts.append(ip_data['cityName'])
                    return ' '.join(location_parts).strip()
                except json.JSONDecodeError:
                    return ''
        except Exception:
            pass
        return ''

    def parse_article(self, url: str) -> Optional[Dict[str, Any]]:
        """解析文章内容"""
        try:
            url = self.get_article_with_params(url)
            time.sleep(random.uniform(WECHAT_CRAWL_DELAY, WECHAT_CRAWL_DELAY + 3))

            response = self.session.get(url, timeout=10, verify=False)
            if "请在微信客户端打开链接" in response.text:
                self.logger.error(f"Access denied for {url}. Please update cookies/keys.")
                return None

            soup = BeautifulSoup(response.text, 'html.parser')

            # 提取元数据
            biz_id = re.search(r'__biz=([^&]+)', url).group(1) if re.search(r'__biz=([^&]+)', url) else ''
            mid_id = re.search(r'mid=(\d+)', url).group(1) if re.search(r'mid=(\d+)', url) else ''
            
            modify_time_match = re.search(r'var\s+modify_time\s*=\s*["\'](\d+)["\']', response.text)
            publish_time = ''
            if modify_time_match:
                timestamp = int(modify_time_match.group(1))
                publish_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

            push_location = self.extract_location_info(response.text)

            article = {
                'title': '',
                'author': '',
                'content': '',
                'publish_time': publish_time,
                'url': url,
                'biz_id': biz_id,
                'mid_id': mid_id,
                'push_location': push_location,
                'site': self.get_source_name()
            }

            if soup.find('div', id='js_article'):
                article['title'] = soup.find('h1', class_='rich_media_title').text.strip() if soup.find('h1', class_='rich_media_title') else ''
                article['content'] = soup.find('div', id='js_content').get_text('\n', strip=True) if soup.find('div', id='js_content') else ''
                article['author'] = soup.find('span', class_='rich_media_meta rich_media_meta_text').text.strip() if soup.find('span', class_='rich_media_meta rich_media_meta_text') else ''

            if article['title'] and article['content']:
                return article

            return None
        except Exception as e:
            self.logger.error(f"Error parsing article {url}: {str(e)}")
            return None

    def get_article_with_params(self, url: str) -> str:
        """添加微信专用参数访问文章"""
        try:
            url = url.replace('&amp;', '&')
            if '?' not in url: return url
            
            params_parts = url.split('?')[1].split('&')
            url_params = {}
            for part in params_parts:
                if '=' in part:
                    k, v = part.split('=', 1)
                    url_params[k] = v

            biz = url_params.get('__biz', '')
            mid = url_params.get('mid', '')
            idx = url_params.get('idx', '')
            sn = url_params.get('sn', '')

            params = {
                '__biz': biz,
                'mid': mid,
                'idx': idx,
                'sn': sn,
                'scene': 27,
                'key': self.config.get('X_WECHAT_KEY', ''),
                'ascene': 1,
                'uin': self.config.get('X_WECHAT_UIN', ''),
                'devicetype': 'Windows 11 x64',
                'version': '63090c11',
                'lang': 'zh_CN',
                'exportkey': self.config.get('EXPORTKEY', ''),
                'pass_ticket': self.config.get('PASS_TICKET', ''),
                'wx_header': 1
            }

            base_url = 'https://mp.weixin.qq.com/s?'
            return base_url + '&'.join([f'{k}={v}' for k, v in params.items()])
        except Exception:
            return url

    def crawl(self, query: str, **kwargs) -> List[Dict[str, Any]]:
        """
        实现 BaseCrawler 的 crawl 接口
        query 在此版本中暂时不被直接作为搜索词（因为微信反爬较严，主要基于 BIZ 爬取特定公众号）
        如果需要基于关键词，建议 BIZ 配置为特定目标公众号
        """
        max_pages = kwargs.get('max_pages', WECHAT_MAX_PAGES)
        articles = []
        offset = 0
        page = 0

        print(f"[WeChat] 开始爬取公众号文章, BIZ: {self.config.get('BIZ')}")

        while page < max_pages:
            print(f"[WeChat] 正在爬取第 {page + 1} 页...")
            articles_data = self.get_article_list(offset)
            
            if not articles_data or not articles_data.get('list'):
                print(f"[WeChat] 没有找到更多文章，爬取完成")
                break

            for msg in articles_data['list']:
                if 'app_msg_ext_info' in msg:
                    # 主文章
                    info = msg['app_msg_ext_info']
                    article_url = info.get('content_url')
                    if article_url:
                        article = self.parse_article(article_url)
                        if article:
                            articles.append(article)
                    
                    # 多图文消息中的其他文章
                    if 'multi_app_msg_item_list' in info:
                        for sub_msg in info['multi_app_msg_item_list']:
                            sub_url = sub_msg.get('content_url')
                            if sub_url:
                                sub_article = self.parse_article(sub_url)
                                if sub_article:
                                    articles.append(sub_article)

            offset += 10
            page += 1
            time.sleep(random.uniform(5, 10))

        print(f"[WeChat] 爬取完成，共获取 {len(articles)} 篇文章")
        return articles
