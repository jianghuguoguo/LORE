import os
import json
import logging
import requests
from typing import List, Dict, Any, Optional

logger = logging.getLogger("EvoPentest.DeepSeekClient")

class DeepSeekClient:
    """
    DeepSeek API 客户端
    集成到 RAG 流程中实现真实 LLM 推理
    """
    
    def __init__(self, api_key: str = None, base_url: str = "https://api.deepseek.com/v1"):
        """
        Args:
            api_key: DeepSeek API 秘钥
            base_url: API 基础地址
        """
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self.base_url = base_url
        if not self.api_key:
            logger.warning("DeepSeek API Key not found!")

    def chat(self, prompt: str, system_prompt: str = "You are an expert penetration testing assistant.", temperature: float = 0.3) -> str:
        """
        发起对话请求
        """
        if not self.api_key:
            return "Error: No API Key provided."

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": temperature,
            "response_format": {"type": "json_object"} if "JSON" in prompt else None
        }

        try:
            response = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()
            return result['choices'][0]['message']['content']
        except Exception as e:
            logger.error(f"DeepSeek API call failed: {e}")
            raise e

    def extract_json(self, response: str) -> Dict[str, Any]:
        """从响应文本中提取并解析 JSON"""
        try:
            # 找到第一个 { 和最后一个 }
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end != 0:
                return json.loads(response[start:end])
            return json.loads(response)
        except Exception as e:
            logger.error(f"Failed to parse JSON from response: {e}")
            return {}
