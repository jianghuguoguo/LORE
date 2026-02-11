"""
GitHub爬虫模块
负责爬取GitHub的Issues和Repositories
"""

import time
import requests
from typing import Dict, List, Any, Optional
import sys
from pathlib import Path
from crawlers.base_crawler import BaseCrawler
from crawlers.config import (
    GITHUB_TOKEN, GITHUB_MAX_ISSUES, GITHUB_MAX_REPOS,
    GITHUB_REQUEST_DELAY, REQUEST_TIMEOUT
)
# 添加父目录到路径以导入base_crawler
sys.path.insert(0, str(Path(__file__).parent.parent))



class GitHubCrawler(BaseCrawler):
    """GitHub 爬虫"""
    
    def __init__(self, session=None):
        super().__init__(session)
        self._setup_github_auth()
        # 扩展支持的语言后缀映射
        self.language_map = {
            '.py': 'python', '.sh': 'shell', '.go': 'go', 
            '.rb': 'ruby', '.pl': 'perl', '.js': 'javascript', 
            '.ts': 'typescript', '.java': 'java', 
            '.c': 'c', '.cpp': 'cpp', '.rs': 'rust',
            '.php': 'php', '.lua': 'lua', '.yaml': 'yaml', '.yml': 'yaml'
        }
        self.config_files = {'requirements.txt', 'go.mod', 'pom.xml', 'package.json', 'Dockerfile'}
    
    def get_source_name(self) -> str:
        """返回数据源名称"""
        return 'github'
    
    def _setup_github_auth(self):
        """设置GitHub认证"""
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        if GITHUB_TOKEN:
            self.headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
            print("[GitHub] ✅ Token 认证已启用")
        else:
            print("[GitHub] ⚠️ 未检测到 Token，仅使用匿名访问 (限制极低)")
        
        self.session.headers.update(self.headers)
    
    def search_issues(self, query: str) -> List[Dict[str, Any]]:
        """搜索GitHub Issues"""
        print(f"[GitHub] 搜索Issues: {query}")
        
        api_url = "https://api.github.com/search/issues"
        results = []
        
        # 多种搜索策略
        search_queries = [
            f'"{query}"',
            f'{query} vulnerability',
            f'{query} exploit',
            f'{query} security'
        ]
        
        for search_query in search_queries[:2]:  # 限制搜索次数
            params = {
                "q": search_query, 
                "per_page": min(GITHUB_MAX_ISSUES // 2, 50)
            }
            
            try:
                response = self.session.get(api_url, params=params, timeout=REQUEST_TIMEOUT)
                if response.status_code != 200:
                    print(f"[GitHub] Issues搜索失败: {response.status_code}")
                    continue
                
                data = response.json()
                for item in data.get("items", []):
                    results.append({
                        'title': item["title"],
                        'link': item["html_url"],
                        'date': item["created_at"],
                        'summary': (item.get("body") or "")[:500],
                        'content': item.get("body") or "",
                        'type': 'github-issue',
                        'site': self.get_source_name(),
                        'author': item["user"]["login"],
                        'repository': item["repository_url"].split("/")[-1],
                        'state': item["state"],
                        'labels': [label["name"] for label in item.get("labels", [])],
                        'comments': item["comments"]
                    })
                
                time.sleep(GITHUB_REQUEST_DELAY)
                
            except Exception as e:
                print(f"[GitHub] Issues搜索异常: {e}")
                continue
        
        return results
    
    def search_repositories(self, query: str) -> List[Dict[str, Any]]:
        """搜索GitHub仓库"""
        print(f"[GitHub] 搜索仓库: {query}")
        
        api_url = "https://api.github.com/search/repositories"
        params = {
            "q": f'"{query}" in:readme,description',
            "per_page": min(GITHUB_MAX_REPOS, 30),
            "sort": "stars",
            "order": "desc"
        }
        
        results = []
        try:
            response = self.session.get(api_url, params=params, timeout=REQUEST_TIMEOUT)
            if response.status_code != 200:
                print(f"[GitHub] 仓库搜索失败: {response.status_code}")
                return results
            
            data = response.json()
            for item in data.get("items", []):
                results.append({
                    'title': item["full_name"],
                    'link': item["html_url"],
                    'date': item["created_at"],
                    'summary': item.get("description", "") or "",
                    'type': 'github-repository',
                    'site': self.get_source_name(),
                    'author': item["owner"]["login"],
                    'stars': item["stargazers_count"],
                    'forks': item["forks_count"],
                    'language': item.get("language"),
                    'topics': item.get("topics", []),
                    'default_branch': item.get("default_branch", "main")
                })
                
        except Exception as e:
            print(f"[GitHub] 仓库搜索异常: {e}")
        
        return results
    
    def get_repository_readme(self, owner: str, repo: str, default_branch: str = 'main') -> str:
        """
        通过 Raw URL 获取 README，节省一次 API 调用
        """
        # 常见的 README 文件名
        readme_variants = ['README.md', 'README.rst', 'README.txt', 'readme.md']
        
        for name in readme_variants:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/{name}"
            try:
                # 尝试不带 Authorization 头访问 Raw 内容，避免权限问题
                raw_headers = {
                    'User-Agent': self.session.headers.get('User-Agent', 'Mozilla/5.0')
                }
                resp = self.session.get(raw_url, headers=raw_headers, timeout=10)
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                continue
        return ""

    def _get_repo_files(self, owner: str, repo: str, branch: str) -> List[Dict[str, str]]:
        """
        优化后的文件获取逻辑：
        1. API 获取文件树 (耗费 1 次 Quota)
        2. 本地筛选
        3. Raw URL 并发或串行下载文件内容 (不耗费 API Quota)
        """
        files_data = []
        
        # 1. 获取文件树 (API)
        tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        
        try:
            response = self.session.get(tree_url, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 403:
                print(f"  [GitHub] ⚠️ Tree API 受限 (403): {owner}/{repo}")
                return []
                
            if response.status_code != 200:
                print(f"  [GitHub] 获取文件树失败: {response.status_code}")
                return []
            
            tree = response.json().get('tree', [])
            
        except Exception as e:
            print(f"  [GitHub] Tree API 异常: {e}")
            return []

        # 2. 筛选目标文件
        target_files = []
        for item in tree:
            if item['type'] != 'blob': # 只看文件
                continue
            
            path = item['path']
            filename = path.split('/')[-1]
            ext = Path(path).suffix.lower()
            size = item.get('size', 0)
            
            # 过滤规则
            if size > 100 * 1024: continue # 跳过大于 100KB 的文件
            if any(p in path for p in ['.git/', 'vendor/', 'node_modules/', 'test/', 'docs/', 'images/']): continue
            
            lang = self.language_map.get(ext)
            if filename in self.config_files:
                lang = 'config'
            
            if lang:
                # 优先级打分：根目录文件优先级更高，config文件优先级高
                priority = 0
                if '/' not in path: priority += 10
                if lang == 'config': priority += 5
                
                target_files.append({
                    'path': path,
                    'language': lang,
                    'priority': priority
                })

        # 3. 排序并限制数量
        # 按优先级降序，取前 8 个文件
        target_files.sort(key=lambda x: x['priority'], reverse=True)
        target_files = target_files[:8]
        
        if not target_files:
            return []

        print(f"  [GitHub] 选中 {len(target_files)} 个核心文件，通过 Raw 下载...")

        # 4. 通过 Raw URL 获取内容 (不消耗 API 配额)
        for file_info in target_files:
            # 构造 Raw URL
            # 注意：raw.githubusercontent.com 可能会被墙，如果失败请检查网络或配置代理
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_info['path']}"
            
            try:
                raw_headers = {
                    'User-Agent': self.session.headers.get('User-Agent', 'Mozilla/5.0')
                }
                
                resp = self.session.get(raw_url, headers=raw_headers, timeout=10)
                
                if resp.status_code == 200:
                    content = resp.text
                    if '\0' not in content:
                        files_data.append({
                            'filename': file_info['path'],
                            'language': file_info['language'],
                            'content': content
                        })
                else:
                    print(f"    - 下载失败 {file_info['path']}: {resp.status_code}")

                time.sleep(0.1)
                
            except Exception as e:
                print(f"    - 下载异常 {file_info['path']}: {e}")

        return files_data

    def crawl(self, query: str, **kwargs) -> List[Dict[str, Any]]:
        """
        主爬取函数 - 实现BaseCrawler的抽象方法
        
        Args:
            query: 搜索关键词
            **kwargs: 其他参数
            
        Returns:
            List[Dict]: 爬取结果列表
        """
        print(f"\n{'='*60}")
        print(f"💻 GitHub爬虫启动")
        print(f"搜索关键词: {query}")
        print(f"{'='*60}\n")
        
        all_results = []
        
        # 搜索Issues
        issues = self.search_issues(query)
        all_results.extend(issues)
        print(f"[GitHub] Issues: {len(issues)} 条")
        
        # 搜索仓库
        repos = self.search_repositories(query)
        
        # 获取仓库详细内容 (README + Code)
        print(f"[GitHub] 正在深入分析 {len(repos)} 个仓库...")
        for i, repo in enumerate(repos, 1):
            try:
                full_name = repo['title']
                print(f"[{i}/{len(repos)}] 分析仓库: {full_name}")
                
                if '/' in full_name:
                    owner, repo_name = full_name.split('/')
                    default_branch = repo.get('default_branch', 'main')
                    
                    # 1. 获取README (Usage Docs)
                    readme_content = self.get_repository_readme(owner, repo_name, default_branch)
                    repo['usage_docs'] = readme_content
                    
                    # 2. 获取核心代码文件
                    code_files = self._get_repo_files(owner, repo_name, default_branch)
                    repo['code_files'] = code_files
                    
                    # 3. 构建 RAG 友好的 content 字段
                    # 组合 README 和 代码片段
                    content_parts = []
                    if readme_content:
                        content_parts.append(f"=== README ===\n{readme_content}")
                    
                    if code_files:
                        content_parts.append(f"\n=== CODE FILES ({len(code_files)}) ===")
                        for f in code_files:
                            # 限制每个文件的展示长度，避免 content 过大
                            preview = f['content'][:2000] + ("\n... (truncated)" if len(f['content']) > 2000 else "")
                            content_parts.append(f"\n--- File: {f['filename']} ({f['language']}) ---\n{preview}")
                    
                    repo['content'] = "\n".join(content_parts)
                    repo['content_type'] = 'exploit_code'
                    
                    # 如果没有摘要，使用README前500字符
                    if not repo['summary'] and readme_content:
                        repo['summary'] = readme_content[:500]
                        
                time.sleep(1)  # 仓库间延时
            except Exception as e:
                print(f"[GitHub] 处理仓库失败 {repo.get('title')}: {e}")
                repo['content'] = ""
        all_results.extend(repos)
        print(f"[GitHub] 仓库: {len(repos)} 条")
        
        # 去重
        unique_results = self.deduplicate_results(all_results)
        
        print(f"\n[GitHub] 爬取完成，共 {len(unique_results)} 条结果")
        print("="*60)
        
        return unique_results
