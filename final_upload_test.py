
import requests
import json
import time

API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003"
headers = {"Authorization": f"Bearer {API_KEY}"}

def test_final_upload():
    # 路径：POST /api/v1/datasets/{id}/documents
    url = f"{BASE_URL}/api/v1/datasets/{DATASET_ID}/documents"
    
    filename = f"final_success_test_{int(time.time())}.json"
    data = [{"title": "Success", "content": "Finally found the path!"}]
    blob = json.dumps(data).encode('utf-8')
    
    files = {'file': (filename, blob, 'application/json')}
    
    print(f"Final testing upload: {url}")
    res = requests.post(url, headers=headers, files=files)
    print(f"Status: {res.status_code}")
    print(f"Body: {res.text}")
    
    if res.status_code == 200 and res.json().get("code") == 0:
        print("🎉 SUCCESS! THE PATH IS CORRECT!")
        # 尝试运行解析
        doc_id = res.json().get("data", {}).get("id")
        if doc_id:
            print(f"Attempting to run parsing for doc_id: {doc_id}")
            # 根据之前的经验，解析可能在不同的端点
            run_url = f"{BASE_URL}/api/v1/datasets/{DATASET_ID}/documents/{doc_id}/run"
            res_run = requests.post(run_url, headers=headers)
            print(f"Run Status: {res_run.status_code}, Body: {res_run.text}")

if __name__ == "__main__":
    test_final_upload()
