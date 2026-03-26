import json
import os

file_path = 'data/layer3_output/phase34_consolidated.jsonl'
if not os.path.exists(file_path):
    print(f"Error: {file_path} not found")
    exit(1)

matches = []
with open(file_path, 'r', encoding='utf-8') as f:
    for line in f:
        try:
            l = json.loads(line)
            # 搜索整个 JSON 字符串
            if 'activemq' in line.lower() or '46604' in line.lower():
                matches.append(l)
        except:
            continue

if not matches:
    print("Found no ActiveMQ matches in file. Listing first 30 entries:")
    with open(file_path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if i >= 30: break
            l = json.loads(line)
            print(f"[{i}] {l.get('security_id')}")
else:
    for m in matches:
        print(f"ID: {m.get('security_id')}")
        print(f"  - P: {m.get('p_fused'):.3f}")
        print(f"  - Mat: {m.get('maturity')}")
        print(f"  - Reason: {m.get('upgrade_reason')}")
        print(f"  - CVE top-level: {m.get('cve_ids')}")
        # Check content sync
        content = m.get('content', {})
        cve_ctx = content.get('cve_context', {})
        print(f"  - CVE in content: {cve_ctx.get('attempted')}")
        print("-" * 20)
