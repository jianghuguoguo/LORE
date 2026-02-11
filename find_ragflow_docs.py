
import requests
import json

API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
headers = {"Authorization": f"Bearer {API_KEY}"}

def find_docs():
    # 尝试查找 OpenAPI 定义以确定所有可用路径
    paths = [
        "/api/v1/openapi.json",
        "/api/openapi.json",
        "/openapi.json",
        "/api/v1/docs",
        "/api/docs",
        "/docs"
    ]
    
    print("--- 探测 OpenAPI/文档路径 ---")
    for p in paths:
        url = f"{BASE_URL}{p}"
        try:
            res = requests.get(url, timeout=5)
            print(f"GET {url} -> {res.status_code}")
            if res.status_code == 200:
                print(f"FOUND DOCS at {url}")
                if "json" in p:
                    with open(f"ragflow_api_{p.replace('/', '_')}.json", "w") as f:
                        f.write(res.text)
        except:
            pass

if __name__ == "__main__":
    find_docs()
