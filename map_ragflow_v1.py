
import requests
import json

API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003"
headers = {"Authorization": f"Bearer {API_KEY}"}

def map_datasets():
    # 我们知道 /api/v1/datasets (GET) 是通的
    # 测试所有可能的子路径
    subpaths = [
        "/document/upload",
        "/document",
        "/documents",
        "/upload",
        "/chunks",
        "/retrieval",
    ]
    
    for sub in subpaths:
        url = f"{BASE_URL}/api/v1/datasets/{DATASET_ID}{sub}"
        print(f"--- Path: {url} ---")
        try:
            r1 = requests.get(url, headers=headers)
            print(f"  GET  -> {r1.status_code} {r1.text[:50]}")
            r2 = requests.post(url, headers=headers, json={})
            print(f"  POST -> {r2.status_code} {r2.text[:50]}")
        except:
            print("  FAILED")

if __name__ == "__main__":
    map_datasets()
