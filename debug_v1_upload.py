
import requests
import json
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("RAGFlowFinalTest")

API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003" # 渗透测试经验库

def test_v1_upload():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    # 准备测试数据
    test_data = [{"title": "API Test", "content": "RAGFlow API v1 Document Upload Test"}]
    blob = json.dumps(test_data, ensure_ascii=False).encode('utf-8')
    filename = f"api_test_{int(time.time())}.json"
    
    # 路径 1: /api/v1/document/upload (这是官方文档通常给出的 v1 接口)
    # 路径 2: /api/v1/dataset/{dataset_id}/document/upload
    
    patterns = [
        (f"{BASE_URL}/api/v1/document/upload", {"kb_id": DATASET_ID}),
        (f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/document/upload", {})
    ]
    
    for url, extra_data in patterns:
        logger.info(f"正在测试: {url}")
        try:
            files = {'file': (filename, blob, 'application/json')}
            response = requests.post(url, headers=headers, files=files, data=extra_data, timeout=10)
            logger.info(f"Status: {response.status_code}, Body: {response.text}")
            if response.status_code == 200 and response.json().get("code") == 0:
                logger.info("✅ 成功！")
                return True
        except Exception as e:
            logger.error(f"Error: {e}")
    return False

if __name__ == "__main__":
    test_v1_upload()
