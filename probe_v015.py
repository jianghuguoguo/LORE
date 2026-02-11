
import requests
import json
import logging

logging.basicConfig(level=logging.INFO)
API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003"
headers = {"Authorization": f"Bearer {API_KEY}"}

def try_new_v1_upload():
    # RAGFlow v0.15+ 使用 /api/v1/dataset/{kb_id}/document 上传
    # 负载为多部分表单，文件字段名为 'file'
    url = f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/document"
    
    import time
    filename = f"v015_test_{int(time.time())}.json"
    content = json.dumps([{"title": "test", "content": "RCE exploit"}]).encode('utf-8')
    
    print(f"尝试 RAGFlow v0.15 风格上传: {url}")
    files = {'file': (filename, content, 'application/json')}
    
    try:
        res = requests.post(url, headers=headers, files=files)
        print(f"Status: {res.status_code}")
        print(f"Body: {res.text}")
        if res.status_code == 200 and res.json().get("code") == 0:
            print("✅ 探测成功！")
            return True
    except Exception as e:
        print(f"Error: {e}")
    return False

if __name__ == "__main__":
    try_new_v1_upload()
