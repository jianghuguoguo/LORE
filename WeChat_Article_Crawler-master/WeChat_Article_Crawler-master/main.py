import requests
import json
import time
import random
import logging
import os
from datetime import datetime
from bs4 import BeautifulSoup
import pandas as pd
import urllib3
import re
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



def load_config():
    """从配置文件加载配置"""
    config_file = 'config.txt'

    # 检查配置文件是否存在
    if not os.path.exists(config_file):
        config_template = '''COOKIE=wxuin=2367572668; pass_ticket=xxx...
X_WECHAT_KEY=xxx...
X_WECHAT_UIN=xxx...
EXPORTKEY=xxx...
USER_AGENT=xxx...
PASS_TICKET=xxx...
BIZ=xxx...'''

        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(config_template)
        print(f"已创建配置文件模板: {config_file}")
        print("请填写配置信息后重新运行程序")
        input("按任意键退出...")
        sys.exit(0)

    # 读取配置
    config = {}
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()

        # 验证必要的配置项
        required_keys = ['COOKIE', 'X_WECHAT_KEY', 'X_WECHAT_UIN',
                         'EXPORTKEY', 'USER_AGENT', 'PASS_TICKET', 'BIZ']

        missing = [key for key in required_keys if key not in config]
        if missing:
            raise ValueError(f"配置文件缺少必要的参数: {', '.join(missing)}")

        return config

    except Exception as e:
        print(f"读取配置文件出错: {str(e)}")
        input("按任意键退出...")
        sys.exit(1)

class WeChatCrawler:
    def __init__(self, save_format='excel'):
        # 加载配置
        self.config = load_config()

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('wechat_crawler.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        self.data_dir = 'wechat_articles'
        os.makedirs(self.data_dir, exist_ok=True)

        if save_format not in ['excel', 'csv', 'json']:
            raise ValueError("save_format must be one of: 'excel', 'csv', 'json'")
        self.save_format = save_format

        self.articles = []

        self.headers = {
            'Host': 'mp.weixin.qq.com',
            'Cookie': self.config['COOKIE'],
            'x-wechat-key': self.config['X_WECHAT_KEY'],
            'x-wechat-uin': self.config['X_WECHAT_UIN'],
            'exportkey': self.config['EXPORTKEY'],
            'user-agent': self.config['USER_AGENT'],
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'zh-CN,zh;q=0.9',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-user': '?1',
            'sec-fetch-dest': 'document'
        }

    def get_article_list(self, offset=0):
        """获取文章列表"""
        url = 'https://mp.weixin.qq.com/mp/profile_ext'
        params = {
            'action': 'getmsg',
            '__biz': self.config['BIZ'],
            'offset': offset,
            'count': '10',
            'uin': self.headers['x-wechat-uin'].replace('%3D%3D', '=='),
            'key': self.headers['x-wechat-key'],
            'f': 'json'
        }

        try:
            time.sleep(random.uniform(2, 5))
            response = requests.get(url, headers=self.headers, params=params, verify=False, timeout=10)
            data = response.json()

            if data.get('ret') == 0:
                return json.loads(data.get('general_msg_list', '{"list":[]}'))
            else:
                self.logger.error(f"Failed to get article list: {data}")
                return None
        except Exception as e:
            self.logger.error(f"Error getting article list: {str(e)}")
            return None

    def extract_location_info(self, html_content):
        """提取发布位置信息"""
        try:
            ip_wording_match = re.search(r'window.ip_wording\s*=\s*({[^}]+})', html_content)
            if ip_wording_match:
                # 获取匹配的内容
                ip_data_str = ip_wording_match.group(1)

                # 1. 先处理换行和空格，让JSON更紧凑
                ip_data_str = re.sub(r'\s+', ' ', ip_data_str.strip())

                # 2. 给属性名添加双引号
                ip_data_str = re.sub(r'(\w+):', r'"\1":', ip_data_str)

                # 3. 确保值的引号是双引号
                ip_data_str = ip_data_str.replace("'", '"')

                try:
                    ip_data = json.loads(ip_data_str)
                    location_parts = []
                    if ip_data.get('countryName'):
                        location_parts.append(ip_data['countryName'])
                    if ip_data.get('provinceName'):
                        location_parts.append(ip_data['provinceName'])
                    if ip_data.get('cityName'):
                        location_parts.append(ip_data['cityName'])
                    return ' '.join(location_parts).strip()
                except json.JSONDecodeError as e:
                    self.logger.error(f"JSON decode error: {str(e)}")
                    return ''
        except Exception as e:
            self.logger.error(f"Error extracting location info: {str(e)}")
        return ''





    # def get_comments(self, url, article_data):
    #     try:
    #         # 从URL中提取必要参数
    #         biz = re.search(r'__biz=([^&]+)', url).group(1)
    #         mid = re.search(r'mid=(\d+)', url).group(1)
    #         idx = re.search(r'idx=(\d+)', url).group(1)
    #         sn = re.search(r'sn=([^&]+)', url).group(1)
    #
    #         comment_url = 'https://mp.weixin.qq.com/mp/appmsg_comment'
    #         params = {
    #             'action': 'getcomment',
    #             '__biz': biz,
    #             'mid': mid,  # 改用 mid 而不是 appmsgid
    #             'idx': idx,
    #             'sn': sn,  # 添加 sn 参数
    #             'scene': 27,  # 添加场景值
    #             'appmsg_type': 9,  # 添加类型
    #             'comment_id': '',
    #             'offset': 0,
    #             'limit': 100,
    #             'send_time': '',
    #             'enterid': str(int(time.time())),  # 添加时间戳
    #             'sessionid': int(random.random() * 10 ** 9),  # 添加随机session
    #             'key': self.headers['x-wechat-key'],
    #             'pass_ticket': PASS_TICKET,
    #             'devicetype': 'Windows11x64',
    #             'clientversion': '63090c11',
    #             'exportkey': self.headers['exportkey'],
    #             'x-wechat-key': self.headers['x-wechat-key'],
    #             'f': 'json'
    #         }
    #
    #         headers = self.headers.copy()
    #         headers['Referer'] = url
    #         headers['Content-Type'] = 'application/json'
    #
    #         comments = []
    #         offset = 0
    #         while True:
    #             params['offset'] = offset
    #             try:
    #                 time.sleep(random.uniform(2, 4))  # 添加随机延迟
    #                 response = requests.get(
    #                     comment_url,
    #                     headers=headers,
    #                     params=params,
    #                     verify=False,
    #                     timeout=10
    #                 )
    #
    #                 if response.status_code == 200:
    #                     data = response.json()
    #                     if data.get('base_resp', {}).get('ret') == 0:
    #                         comment_data = data.get('elected_comment', [])
    #                         if not comment_data:
    #                             break
    #
    #                         for comment in comment_data:
    #                             comments.append({
    #                                 'content': comment.get('content', ''),
    #                                 'nick_name': comment.get('nick_name', ''),
    #                                 'create_time': datetime.fromtimestamp(
    #                                     comment.get('create_time', 0)
    #                                 ).strftime('%Y-%m-%d %H:%M:%S'),
    #                                 'like_num': comment.get('like_num', 0),
    #                                 'reply_list': len(comment.get('reply_list', [])),
    #                             })
    #
    #                         if len(comment_data) < 100:
    #                             break
    #
    #                         offset += 100
    #                     else:
    #                         self.logger.error(f"Failed to get comments: {data}")
    #                         break
    #                 else:
    #                     self.logger.error(f"Comment request failed with status code: {response.status_code}")
    #                     break
    #
    #             except Exception as e:
    #                 self.logger.error(f"Error getting comments at offset {offset}: {str(e)}")
    #                 break
    #
    #         return comments
    #
        # except Exception as e:
        #     self.logger.error(f"Error parsing comment URL: {str(e)}")
        #     return []

    def parse_article(self, url):
        """解析文章内容"""
        try:
            url = self.get_article_with_params(url)
            time.sleep(random.uniform(3, 7))

            session = requests.Session()
            response = session.get(url, headers=self.headers, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            if "请在微信客户端打开链接" in response.text:
                self.logger.error(f"Access denied for {url}")
                return None

            # 提取biz_id和mid_id
            biz_id = re.search(r'__biz=([^&]+)', url).group(1) if re.search(r'__biz=([^&]+)', url) else ''
            mid_id = re.search(r'mid=(\d+)', url).group(1) if re.search(r'mid=(\d+)', url) else ''

            # 提取发布时间
            modify_time_match = re.search(r'var\s+modify_time\s*=\s*["\'](\d+)["\']', response.text)
            publish_time = ''
            if modify_time_match:
                timestamp = int(modify_time_match.group(1))
                publish_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

            # 提取位置信息
            push_location = self.extract_location_info(response.text)


            article = {
                'title': '',
                'author': '',
                'content': '',
                'publish_time': publish_time,
                'url': url,
                'biz_id': biz_id,
                'mid_id': mid_id,
                'push_location': push_location
            }



            if soup.find('div', id='js_article'):
                article['title'] = soup.find('h1', class_='rich_media_title').text.strip() if soup.find('h1', class_='rich_media_title') else ''
                article['content'] = soup.find('div', id='js_content').get_text('\n', strip=True) if soup.find('div', id='js_content') else ''
                article['author'] = soup.find('span', class_='rich_media_meta rich_media_meta_text').text.strip() if soup.find('span', class_='rich_media_meta rich_media_meta_text') else ''
                # 获取评论
                # comments = self.get_comments(url, article)
                # article['comments'] = comments
                # article['comment_count'] = len(comments)

            if article['title'] and article['content']:
                self.logger.info(f"Successfully parsed article: {article['title']}")
                return article

            self.logger.error(f"Failed to parse content for {url}")
            return None

        except Exception as e:
            self.logger.error(f"Error parsing article {url}: {str(e)}")
            return None

    def get_article_with_params(self, url):
        """添加微信专用参数访问文章"""
        try:
            url = url.replace('&amp;', '&')
            biz = url.split('__biz=')[1].split('&')[0]
            mid = url.split('mid=')[1].split('&')[0]
            idx = url.split('idx=')[1].split('&')[0]
            sn = url.split('sn=')[1].split('&')[0]

            params = {
                '__biz': biz,
                'mid': mid,
                'idx': idx,
                'sn': sn,
                'scene': 27,
                'key': self.headers['x-wechat-key'],
                'ascene': 1,
                'uin': self.headers['x-wechat-uin'],
                'devicetype': 'Windows 11 x64',
                'version': '63090c11',
                'lang': 'zh_CN',
                'exportkey': self.headers['exportkey'],
                'pass_ticket': self.config['PASS_TICKET'],
                'wx_header': 1
            }

            base_url = 'https://mp.weixin.qq.com/s?'
            return base_url + '&'.join([f'{k}={v}' for k, v in params.items()])
        except Exception as e:
            self.logger.error(f"Error processing URL: {str(e)}")
            return url

    def save_articles(self):
        """保存所有文章"""
        if not self.articles:
            self.logger.warning("No articles to save")
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        try:
            # 分离评论数据
            articles_without_comments = []
            all_comments = []

            for article in self.articles:
                article_copy = article.copy()
                comments = article_copy.pop('comments', [])
                articles_without_comments.append(article_copy)

                # 为每条评论添加文章信息
                for comment in comments:
                    comment['article_title'] = article['title']
                    comment['article_url'] = article['url']
                    all_comments.append(comment)

            # 保存文章数据
            df_articles = pd.DataFrame(articles_without_comments)

            # 保存评论数据
            df_comments = pd.DataFrame(all_comments)

            if self.save_format == 'excel':
                with pd.ExcelWriter(f"{self.data_dir}/wechat_data_{timestamp}.xlsx") as writer:
                    df_articles.to_excel(writer, sheet_name='Articles', index=False)
                    df_comments.to_excel(writer, sheet_name='Comments', index=False)
                self.logger.info(f"Saved articles and comments to Excel")

            elif self.save_format == 'csv':
                df_articles.to_csv(f"{self.data_dir}/wechat_articles_{timestamp}.csv", index=False,
                                   encoding='utf-8-sig')
                df_comments.to_csv(f"{self.data_dir}/wechat_comments_{timestamp}.csv", index=False,
                                   encoding='utf-8-sig')
                self.logger.info(f"Saved articles and comments to CSV")

            elif self.save_format == 'json':
                with open(f"{self.data_dir}/wechat_data_{timestamp}.json", 'w', encoding='utf-8') as f:
                    json.dump({
                        'articles': articles_without_comments,
                        'comments': all_comments
                    }, f, ensure_ascii=False, indent=4)
                self.logger.info(f"Saved articles and comments to JSON")

        except Exception as e:
            self.logger.error(f"Error saving articles and comments: {str(e)}")

    def crawl(self, max_pages=5, initial_offset=0, initial_page=0):
        """主爬虫逻辑"""
        offset = initial_offset
        page = initial_page
        total_articles = 0

        print(f"\n开始爬取文章...")
        print(f"\n每一页10篇文章")
        print(f"起始页码: 第{initial_page + 1}页")
        print(f"起始偏移量: {initial_offset}")
        print(f"计划爬取页数: {max_pages}页\n")

        while page < initial_page + max_pages:
            self.logger.info(f"正在爬取第 {page + 1} 页")
            print(f"正在爬取第 {page + 1} 页...")

            articles_data = self.get_article_list(offset)
            if not articles_data or not articles_data['list']:
                print(f"没有找到更多文章，爬取结束")
                break

            page_articles = 0
            for msg in articles_data['list']:
                if 'app_msg_ext_info' in msg:
                    article_url = msg['app_msg_ext_info']['content_url']
                    if article_url:
                        article = self.parse_article(article_url)
                        if article:
                            self.articles.append(article)
                            page_articles += 1
                            total_articles += 1

            print(f"第 {page + 1} 页完成，本页获取 {page_articles} 篇文章")
            print(f"当前共计爬取 {total_articles} 篇文章\n")

            offset += 10
            page += 1
            time.sleep(random.uniform(5, 10))

        print(f"\n爬取完成！")
        print(f"总计爬取页数: {page - initial_page} 页")
        print(f"总计爬取文章: {total_articles} 篇")

        self.save_articles()

def main():
    # 让用户选择保存格式
    print("请选择数据保存格式：")
    print("1. Excel格式 (.xlsx)")
    print("2. CSV格式 (.csv)")
    print("3. JSON格式 (.json)")

    choice = input("请输入选择(1-3): ").strip()
    save_format = {
        '1': 'excel',
        '2': 'csv',
        '3': 'json'
    }.get(choice, 'excel')

    # 初始化爬虫
    crawler = WeChatCrawler(save_format=save_format)

    # 设置起始页数（从1开始计数）
    start_page = input("请输入起始页码(从1开始): ").strip()
    start_page = int(start_page) if start_page.isdigit() and int(start_page) > 0 else 1

    # 计算offset
    initial_offset = (start_page - 1) * 10
    initial_page = start_page - 1

    # 设置爬取页数
    max_pages = input(f"请输入要爬取的页数(从第{start_page}页开始): ").strip()
    max_pages = int(max_pages) if max_pages.isdigit() else 5

    print(f"\n开始爬取: 从第{start_page}页开始，共爬取{max_pages}页")
    print(f"将爬取第{start_page}页到第{start_page + max_pages - 1}页的内容")

    # 开始爬取
    crawler.crawl(max_pages=max_pages, initial_offset=initial_offset, initial_page=initial_page)


if __name__ == "__main__":
    main()