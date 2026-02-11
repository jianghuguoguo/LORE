
import requests
import json
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("RAGFlowTest")

# 配置信息
API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
BASE_URL = "http://60.205.197.71"
DATASET_ID = "1144627c05c911f197890242ac140003" # 经验库

def test_upload_flow():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    # 准备测试数据
    test_data = [{
        "title": "System 2 Test Summary",
        "content": "This is a test summary from diagnostic agent. Iteration: 3, Success: False.",
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
    }]
    content = json.dumps(test_data, ensure_ascii=False, indent=2).encode('utf-8')
    filename = f"test_debug_{int(time.time())}.json"
    
    # 路径 A: /api/v1/dataset/{id}/document/upload (旧文档/某些特定版本)
    # 路径 B: /api/v1/document/upload (通用版本)
    
    urls_to_try = [
        # (URL, Data_Field_Name)
        (f"{BASE_URL}/api/v1/dataset/{DATASET_ID}/document/upload", None),
        (f"{BASE_URL}/api/v1/document/upload", "kb_id"),
    ]
    
    for url, kb_field in urls_to_try:
        logger.info(f"--- 正在尝试接口: {url} ---")
        try:
            files = {'file': (filename, content, 'application/json')}
            data = {kb_field: DATASET_ID} if kb_field else {}
            
            response = requests.post(url, headers=headers, files=files, data=data, timeout=10)
            logger.info(f"Status Code: {response.status_code}")
            try:
                res_json = response.json()
                logger.info(f"Response Body: {json.dumps(res_json, ensure_ascii=False)}")
                
                if res_json.get("code") == 0:
                    logger.info("✅ 上传接口成功！")
                    # 如果成功，记录成功的 URL 模式
                    return url, kb_field
            except:
                logger.error(f"非 JSON 响应: {response.text}")
        except Exception as e:
            logger.error(f"连接错误: {e}")
            
    return None, None

if __name__ == "__main__":
    success_url, field = test_upload_flow()
    if success_url:
        print(f"\nSUCCESS_PATTERN: {success_url} | FIELD: {field}")
    else:
        print("\nFAILED: 无法找到有效的 RAGFlow 上传接口")
