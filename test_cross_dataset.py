
import requests
import json
import logging

logging.basicConfig(level=logging.INFO)
API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"

# 尝试上传到另一个知识库 ID 537706727fd211f0a4890242ac120006
DATASET_ID = "537706727fd211f0a4890242ac120006"
headers = {"Authorization": f"Bearer {API_KEY}"}

url = f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/document/upload"
import time
filename = f"cross_test_{int(time.time())}.txt"
files = {'file': (filename, b"cross test")}

print(f"尝试上传到另一个已存在的知识库: {url}")
res = requests.post(url, headers=headers, files=files)
print(f"Status: {res.status_code}, Body: {res.text}")
