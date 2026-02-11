
import requests
import json
import logging

logging.basicConfig(level=logging.INFO)
API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003"
headers = {"Authorization": f"Bearer {API_KEY}"}

def test_v1_standard():
    # v1 标准文档：POST /api/v1/dataset/{dataset_id}/document/upload
    # 注意：RAGFlow API 有时非常挑剔 Headers
    url = f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/document/upload"
    
    import time
    filename = f"std_test_{int(time.time())}.json"
    content = json.dumps([{"title": "test", "content": "standard v1"}]).encode('utf-8')
    
    print(f"尝试标准 v1 路径: {url}")
    # 尝试不带 Content-Type 后缀的文件元组
    files = {'file': (filename, content)}
    
    try:
        # 有些系统需要明确指定 Content-Type: multipart/form-data，但 requests 会自动处理
        res = requests.post(url, headers=headers, files=files)
        print(f"Status: {res.status_code}")
        print(f"Body: {res.text}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_v1_standard()
