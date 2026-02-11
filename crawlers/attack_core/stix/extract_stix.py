# stix/extract_stix.py
"""
从 GitHub 下载 STIX 2.1 JSON 数据集并解析
这是最稳定的数据获取方式，适合首次构建知识库
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any

import requests
from tqdm import tqdm

import sys
sys.path.append(str(Path(__file__).parent.parent))

from config import (
    ENTERPRISE_STIX_URL,
    MOBILE_STIX_URL,
    ICS_STIX_URL,
    STIX_OUTPUT_DIR,
)
from stix.load_from_stix import STIXToJSONLoader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


def download_stix_bundle(url: str, domain: str) -> Dict[str, Any]:
    """
    从 GitHub 下载 STIX bundle
    
    Args:
        url: STIX JSON 文件 URL
        domain: 域名（enterprise/mobile/ics）
    
    Returns:
        STIX bundle 字典
    """
    logger.info(f"Downloading {domain} STIX data from {url}")
    
    try:
        resp = requests.get(url, timeout=120)
        resp.raise_for_status()
        
        bundle = resp.json()
        
        # 保存原始 JSON
        output_dir = Path(STIX_OUTPUT_DIR)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        raw_file = output_dir / f"{domain}-attack-raw.json"
        with open(raw_file, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved raw bundle to {raw_file}")
        logger.info(f"Bundle contains {len(bundle.get('objects', []))} objects")
        
        return bundle
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download {domain} bundle: {e}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {domain} bundle: {e}")
        raise


def process_bundle(bundle: Dict[str, Any], domain: str):
    """
    处理 STIX bundle 并保存为结构化 JSON
    
    Args:
        bundle: STIX bundle 字典
        domain: 域名
    """
    logger.info(f"Processing {domain} bundle...")
    
    loader = STIXToJSONLoader(bundle, domain)
    results = loader.load_all()
    
    # 输出统计信息
    stats = {
        "tactics": len(results["tactics"]),
        "techniques": len(results["techniques"]),
        "groups": len(results["groups"]),
        "software": len(results["software"]),
        "campaigns": len(results["campaigns"]),
        "mitigations": len(results["mitigations"]),
        "datasources": len(results["datasources"]),
        "relationships": sum(len(v) for v in results["relationships"].values()),
    }
    
    logger.info(f"{domain} statistics: {stats}")
    
    # 保存处理后的 JSON
    output_file = Path(STIX_OUTPUT_DIR) / f"{domain}-attack-processed.json"
    loader.save_to_json(str(output_file))
    
    return results


def extract_all_domains():
    """提取所有三个域的 STIX 数据"""
    domains = {
        "enterprise": ENTERPRISE_STIX_URL,
        "mobile": MOBILE_STIX_URL,
        "ics": ICS_STIX_URL,
    }
    
    all_results = {}
    
    for domain, url in tqdm(domains.items(), desc="Extracting STIX data"):
        try:
            # 下载
            bundle = download_stix_bundle(url, domain)
            
            # 处理
            results = process_bundle(bundle, domain)
            all_results[domain] = results
            
        except Exception as e:
            logger.error(f"Failed to process {domain}: {e}")
            continue
    
    # 生成汇总报告
    generate_summary_report(all_results)
    
    logger.info("=" * 60)
    logger.info("STIX extraction completed successfully!")
    logger.info(f"Output directory: {STIX_OUTPUT_DIR}")
    logger.info("=" * 60)


def generate_summary_report(all_results: Dict[str, Any]):
    """生成汇总报告"""
    output_file = Path(STIX_OUTPUT_DIR) / "extraction_summary.md"
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# ATT&CK STIX 数据提取汇总报告\n\n")
        
        for domain, results in all_results.items():
            f.write(f"## {domain.upper()} 域\n\n")
            f.write(f"- 战术 (Tactics): {len(results['tactics'])}\n")
            f.write(f"- 技术 (Techniques): {len(results['techniques'])}\n")
            f.write(f"- 组织 (Groups): {len(results['groups'])}\n")
            f.write(f"- 软件 (Software): {len(results['software'])}\n")
            f.write(f"- 活动 (Campaigns): {len(results['campaigns'])}\n")
            f.write(f"- 缓解措施 (Mitigations): {len(results['mitigations'])}\n")
            f.write(f"- 数据源 (Data Sources): {len(results['datasources'])}\n")
            
            rel_stats = results['relationships']
            f.write(f"\n### 关系统计\n\n")
            f.write(f"- Group → Technique: {len(rel_stats['group_technique'])}\n")
            f.write(f"- Software → Technique: {len(rel_stats['software_technique'])}\n")
            f.write(f"- Mitigation → Technique: {len(rel_stats['technique_mitigation'])}\n")
            f.write("\n")
    
    logger.info(f"Summary report saved to {output_file}")


def main():
    """主函数"""
    logger.info("Starting STIX extraction from GitHub...")
    logger.info(f"Output directory: {STIX_OUTPUT_DIR}")
    
    extract_all_domains()


if __name__ == "__main__":
    main()
