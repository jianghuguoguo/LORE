
import requests
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RAGFlowAuthTest")

API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"

def test_auth():
    # 尝试一个最基础的可能接口，看是否报错 401/403
    url = f"{BASE_URL}/api/v1/datasets" # 某些 API 使用复数
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    try:
        res = requests.get(url, headers=headers)
        print(f"URL: {url}")
        print(f"Status: {res.status_code}")
        print(f"Body: {res.text}")
        
        # 尝试带 /api/v2
        url_v2 = f"{BASE_URL}/api/v2/datasets"
        res_v2 = requests.get(url_v2, headers=headers)
        print(f"\nURL: {url_v2}")
        print(f"Status: {res_v2.status_code}")
        print(f"Body: {res_v2.text}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_auth()
