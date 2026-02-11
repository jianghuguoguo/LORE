import os
import time
import requests
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("EvoPentest.RAGFlowClient")

class RAGFlowClient:
    """
    RAGFlow API 客户端
    用于将经验总结或爬取的数据推送至 RAGFlow 知识库
    """
    
    def __init__(self, api_key: str, base_url: str = "http://60.205.197.71"):
        """
        Args:
            api_key: RAGFlow API Key
            base_url: RAGFlow 服务的地址
        """
        self.api_key = api_key
        # 去掉结尾的 /
        self.base_url = base_url.rstrip('/')
        self.headers = {
            "Authorization": f"Bearer {self.api_key}"
        }

    def upload_document(self, dataset_id: str, blob: bytes, filename: str) -> bool:
        """
        上传文件到指定的知识库
        """
        # 强制使用 .txt 扩展名以配合文本转换，除非文件名已经包含允许的后缀
        if not filename.lower().endswith(('.txt', '.md', '.json')):
            filename += ".txt"
            
        # 经过实测暴力探测，当前服务器 (http://60.205.197.71) 的正确 API 路径为：
        # /api/v1/datasets/{dataset_id}/documents (注意：是 datasets 复数)
        url = f"{self.base_url}/api/v1/datasets/{dataset_id}/documents"
        
        # 使用 text/plain 提高 RAGFlow 的解析成功率和预览友好度
        files = {
            'file': (filename, blob, 'text/plain')
        }
        
        try:
            logger.info(f"正在上传文件 {filename} ({len(blob)} bytes) 到 RAGFlow...")
            response = requests.post(
                url, 
                headers=self.headers, 
                files=files, 
                timeout=30
            )
            
            res_json = response.json()
            if response.status_code == 200 and res_json.get("code") == 0:
                doc_list = res_json.get("data", [])
                if doc_list and isinstance(doc_list, list):
                    doc_id = doc_list[0].get("id")
                    logger.info(f"✅ RAGFlow 确认收到文件，ID: {doc_id}")
                    # 尝试触发解析
                    self._run_parsing(dataset_id, doc_id)
                return True
            else:
                logger.error(f"❌ RAGFlow 上传失败: {res_json.get('message', '未知错误')}")
                return False
                
        except Exception as e:
            logger.error(f"❌ 物理连接或请求异常: {e}")
            return False

    def _run_parsing(self, dataset_id: str, doc_id: str):
        """触发文档解析流程"""
        url = f"{self.base_url}/api/v1/datasets/{dataset_id}/documents/{doc_id}/run"
        try:
            res = requests.post(url, headers=self.headers, timeout=5)
            if res.status_code == 200:
                logger.debug(f"已向 RAGFlow 发送解析请求 ({doc_id})")
        except:
            pass

    def push_json_experience(self, dataset_id: str, data: List[Dict[str, Any]], filename_prefix: str = "exp"):
        """
        将数据推送到 RAGFlow。
        为了确保 RAGFlow 能够正确切片和显示内容，我们将内容转换为纯文本格式的 .txt 文件。
        """
        if not data:
            logger.warning("No data to push to RAGFlow")
            return False
            
        # 将结构化 JSON 转换为易于检索的纯文本格式 (Markdown 风格)
        text_lines = []
        for item in data:
            item_title = item.get("title", "Untitled")
            item_content = item.get("content", "")
            ts = item.get("timestamp", "")
            
            text_lines.append(f"# {item_title}")
            text_lines.append(f"Date: {ts}")
            text_lines.append("-" * 20)
            text_lines.append(str(item_content))
            text_lines.append("\n" + "=" * 40 + "\n")
            
        full_text = "\n".join(text_lines)
        content_bytes = full_text.encode('utf-8')
        
        # 净化文件名：只保留字母、数字、下划线和点
        safe_prefix = "".join([c if c.isalnum() or c == '_' else '_' for c in filename_prefix])
        filename = f"{safe_prefix}_{int(time.time())}.txt"
        
        return self.upload_document(dataset_id, content_bytes, filename)

    def push_structured_summary(self, dataset_id: str, title: str, content: str):
        """
        将单条结构化经验总结推送到 RAGFlow
        """
        data = {
            "title": title,
            "content": content,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
        # 移除 [:20] 限制，防止文件名截断重要信息 (如 CVE 编号末位)
        # 并将后缀改为 .txt 以便 RAGFlow 直接预览和切片
        filename_prefix = f"summary_{title.replace(' ', '_')}"
        return self.push_json_experience(dataset_id, [data], filename_prefix=filename_prefix)

    def search(self, query: str, dataset_id: str, top_k: int = 10) -> Dict[str, Any]:
        """
        在指定的知识库中进行检索
        """
        # 统一使用 datasets 复数接口
        url = f"{self.base_url}/api/v1/datasets/{dataset_id}/retrieval"
        
        payload = {
            "question": query,
            "top_k": top_k
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=15)
            response.raise_for_status()
            res_json = response.json()
            
            if not res_json:
                return {"data": {"chunks": []}}
            
            # 如果 data 字段不存在或为 None，确保它变成一个空字典，防止后续 .get 报错
            if res_json.get("data") is None:
                res_json["data"] = {"chunks": []}
                
            return res_json
        except Exception as e:
            logger.error(f"❌ RAGFlow search failed: {e}")
            return {"data": {"chunks": []}}
