# run_all.py
"""
ATT&CK 知识库构建 - 一键运行脚本
仅执行：STIX 抽取
"""

import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


def run_stix_extraction():
    """运行 STIX 静态抽取"""
    logger.info("=" * 80)
    logger.info("STEP 1: STIX Static Extraction")
    logger.info("=" * 80)
    
    try:
        from stix.extract_stix import main as extract_main
        extract_main()
        return True
    except Exception as e:
        logger.error(f"STIX extraction failed: {e}")
        return False


def generate_final_report():
    """生成最终汇总报告"""
    logger.info("=" * 80)
    logger.info("Generating Final Report")
    logger.info("=" * 80)
    
    from config import STIX_OUTPUT_DIR
    import json
    
    report_lines = [
        "# ATT&CK 知识库构建完成报告\n",
        f"\n## 数据源1: STIX 静态抽取\n",
        f"输出目录: `{STIX_OUTPUT_DIR}`\n",
        "文件:\n",
    ]
    
    # 统计 STIX 数据
    stix_dir = Path(STIX_OUTPUT_DIR)
    if stix_dir.exists():
        for domain in ["enterprise", "mobile", "ics"]:
            processed_file = stix_dir / f"{domain}-attack-processed.json"
            if processed_file.exists():

                with open(processed_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                report_lines.append(f"\n### {domain.upper()} 域\n")
                report_lines.append(f"- 战术: {len(data['tactics'])}\n")
                report_lines.append(f"- 技术: {len(data['techniques'])}\n")
                report_lines.append(f"- 组织: {len(data['groups'])}\n")
                report_lines.append(f"- 软件: {len(data['software'])}\n")
    
    # 统计 HTML 数据
    report_lines.append(f"\n## 数据源2: HTML 爬虫\n")
    report_lines.append(f"输出目录: `{HTML_OUTPUT_DIR}`\n")
    
    html_dir = Path(HTML_OUTPUT_DIR)
    if html_dir.exists():
        html_files = list(html_dir.glob("*.html"))
        report_lines.append(f"- 抓取页面数: {len(html_files)}\n")
        
        # 统计解析结果
        tech_extra = html_dir / "techniques_html_extra.json"
        if tech_extra.exists():
            with open(tech_extra, "r", encoding="utf-8") as f:
                tech_data = json.load(f)
            report_lines.append(f"- 技术补充信息: {len(tech_data)} 条\n")
    
    # 保存报告
    report_file = Path("FINAL_REPORT.md")
    with open(report_file, "w", encoding="utf-8") as f:
        f.writelines(report_lines)
    
    logger.info(f"Final report saved to {report_file}")
    
    # 打印报告
    print("\n" + "".join(report_lines))


def main():
    """主函数"""
    logger.info("=" * 80)
    logger.info("ATT&CK Knowledge Base Builder - Full Pipeline")
    logger.info("=" * 80)
    
    steps = [
        ("STIX Extraction", run_stix_extraction, True),
    steps = [
        ("STIX Extraction", run_stix_extraction, True),
    ]
    
    results = {}
    
    for step_name, step_func, required in steps:

        logger.info(f"\n{'='*80}")
        logger.info(f"Running: {step_name}")
        logger.info(f"{'='*80}\n")
        
        success = step_func()
        results[step_name] = success
        
        if required and not success:
            logger.error(f"Required step '{step_name}' failed. Aborting.")
            sys.exit(1)
        
        if not success and not required:
            logger.warning(f"Optional step '{step_name}' failed. Continuing...")
    
    # 生成最终报告
    generate_final_report()
    
    # 汇总
    logger.info("\n" + "=" * 80)
    logger.info("PIPELINE COMPLETED")
    logger.info("=" * 80)
    
    for step_name, success in results.items():
        status = "✓ SUCCESS" if success else "✗ FAILED"
        logger.info(f"{status}: {step_name}")
    
    logger.info("=" * 80)
    logger.info("All done! Check FINAL_REPORT.md for details.")
    logger.info("=" * 80)


if __name__ == "__main__":
    main()
