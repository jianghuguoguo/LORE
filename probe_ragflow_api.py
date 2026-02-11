
import requests
import json
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("RAGFlowProbe")

# 配置信息
API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003"

def probe_api():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    # 尝试列出知识库文档，这不需要上传内容，可以验证端点是否正确
    urls = [
        f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/documents",
        f"{BASE_URL}/api/v1/dataset/info?dataset_id={DATASET_ID}",
        f"{BASE_URL}/api/v1/dataset/list",
    ]
    
    for url in urls:
        logger.info(f"探测 GET 接口: {url}")
        try:
            res = requests.get(url, headers=headers, timeout=10)
            logger.info(f"Status: {res.status_code}, Resp: {res.text[:200]}")
        except Exception as e:
            logger.error(f"Error: {e}")

    # 尝试上传文档的不同变体
    filename = f"probe_{int(time.time())}.txt"
    content = b"probe content"
    
    # 变体 1: 某些版本可能在 v1 后面没有 dataset
    # 变体 2: 某些版本可能使用 multipart 且 kb_id 在 url 中
    # 变体 3: 某些版本使用 /api/dataset/upload (没有 v1)
    
    upload_variants = [
        f"{BASE_URL}/api/v1/document/upload", # 标准
        f"{BASE_URL}/api/v1/dataset/upload",   # 变体
        f"{BASE_URL}/api/document/upload",    # 无 v1
        f"{BASE_URL}/api/v1/upload",          # 简写
    ]

    for url in upload_variants:
        logger.info(f"探测 POST 上传: {url}")
        try:
            files = {'file': (filename, content, 'text/plain')}
            # 尝试不同的 ID 字段名
            for id_field in ['kb_id', 'dataset_id', 'id']:
                data = {id_field: DATASET_ID}
                res = requests.post(url, headers=headers, files=files, data=data, timeout=5)
                if res.status_code != 404 and "NotFound" not in res.text:
                    logger.info(f"FOUND POTENTIAL ENDPOINT: {url} with field {id_field} -> Status {res.status_code}, Resp: {res.text}")
                    return url, id_field
                else:
                    logger.debug(f"Tried {url} {id_field}: 404")
        except Exception as e:
            logger.error(f"Error during POST: {e}")

    return None, None

if __name__ == "__main__":
    probe_api()
