
import requests
import json
import logging

logging.basicConfig(level=logging.INFO)
API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003"

headers = {"Authorization": f"Bearer {API_KEY}"}

print("--- 探测端点结构 ---")
# 既然 /api/v1/datasets 能通，说明 /api/v1/ 是正确的
# 尝试列出文档，看哪个能通
test_urls = [
    f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/documents",
    f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/list",
    f"{BASE_URL}/api/v1/document/list?dataset_id={DATASET_ID}",
    f"{BASE_URL}/api/v1/dataset/info?id={DATASET_ID}",
]

for url in test_urls:
    res = requests.get(url, headers=headers)
    print(f"GET {url} -> {res.status_code} {res.text[:100]}")
