
import requests
import json

API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003"
headers = {"Authorization": f"Bearer {API_KEY}"}

def brute_endpoints():
    # 我们知道 .../dataset/{id}/retrieval 是通的
    # 测试相关变体
    actions = [
        "document/upload",
        "document",
        "upload",
        "doc/upload",
        "docs/upload",
        "documents",
        "docs",
        "info"
    ]
    
    print(f"--- 探测 /api/v1/dataset/{DATASET_ID}/[ACTION] ---")
    for action in actions:
        url = f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/{action}"
        # 尝试 GET
        res_get = requests.get(url, headers=headers)
        # 尝试 POST (带一个空文件字段，看报错是 404 还是 405 或 400)
        res_post = requests.post(url, headers=headers, files={'file': ('test.txt', b'test')})
        
        print(f"Action: {action}")
        print(f"  GET  -> {res_get.status_code} {res_get.text[:60]}")
        print(f"  POST -> {res_post.status_code} {res_post.text[:60]}")

if __name__ == "__main__":
    brute_endpoints()
