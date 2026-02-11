
import requests
import json

API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003"
headers = {"Authorization": f"Bearer {API_KEY}"}

def verify_retrieval():
    url = f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/retrieval"
    print(f"Testing retrieval: {url}")
    res = requests.post(url, headers=headers, json={"question": "test"})
    print(f"Result: {res.status_code} {res.text}")

if __name__ == "__main__":
    verify_retrieval()
