
import requests
import json

API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003"
headers = {"Authorization": f"Bearer {API_KEY}"}

def try_plural():
    # 注意这里是 datasetS 包含 S
    endpoints = [
        f"{BASE_URL}/api/v1/datasets/{DATASET_ID}/retrieval",
        f"{BASE_URL}/api/v1/datasets/{DATASET_ID}/document/upload",
        f"{BASE_URL}/api/v1/datasets/{DATASET_ID}/document",
        f"{BASE_URL}/api/v1/datasets/{DATASET_ID}"
    ]
    
    for url in endpoints:
        print(f"Trying: {url}")
        res = requests.post(url, headers=headers, json={"question": "test"}) if "retrieval" in url else requests.get(url, headers=headers)
        print(f"Result: {res.status_code} {res.text[:100]}")

if __name__ == "__main__":
    try_plural()
