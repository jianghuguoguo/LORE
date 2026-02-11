
import requests
import json
import logging

logging.basicConfig(level=logging.INFO)
API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"

headers = {"Authorization": f"Bearer {API_KEY}"}

print("--- 探测基本端点 ---")
test_urls = [
    f"{BASE_URL}/api/v1/datasets",        # 成功
    f"{BASE_URL}/api/v1/dataset/list",   # 探测
    f"{BASE_URL}/api/v1/kb/list",        # 探测 (Knowledge Base)
    f"{BASE_URL}/api/v1/kb/upload",      # 探测
]

for url in test_urls:
    res = requests.get(url, headers=headers)
    print(f"GET {url} -> {res.status_code} {res.text[:100]}")
    
# 既然 /api/v1/datasets 成功了，我们看看能不能根据 dataset 查 documents
# 通常 RAGFlow 的 URL 结构是 /api/v1/document/upload，但我们之前的尝试返回 404
# 可能是因为不需要 /v1/？或者是 /api/document/upload？
print("\n--- 探测上传端点变体 ---")
import time
filename = f"test_{int(time.time())}.txt"
content = b"test"
upload_urls = [
    f"{BASE_URL}/api/v1/document/upload",
    f"{BASE_URL}/api/document/upload",
    f"{BASE_URL}/api/v1/kb/document/upload",
]

for url in upload_urls:
    files = {'file': (filename, content)}
    data = {'kb_id': '1144627c05c911f197890242ac140003'}
    try:
        res = requests.post(url, headers=headers, files=files, data=data)
        print(f"POST {url} -> {res.status_code} {res.text[:100]}")
    except:
        print(f"POST {url} -> Failed")
