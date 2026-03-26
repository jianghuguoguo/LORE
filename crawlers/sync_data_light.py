"""
crawlers/sync_data_light.py
===========================
外部安全知识库同步工具

支持 11 个外部安全数据库的一键同步，结果保存到 raw_data/

用法（从 LORE/ 根目录运行）:
    python crawlers/sync_data_light.py                      # 全部同步
    python crawlers/sync_data_light.py --repos attack        # 只同步 ATT&CK
    python crawlers/sync_data_light.py --repos cisa-kev,cwe # 指定仓库
"""
import os
import sys
import argparse
import requests
import zipfile
import tarfile
import io
import json
import shutil
import tempfile
from pathlib import Path

# 路径配置（基于脚本位置自动定位项目根目录）
_ROOT         = Path(__file__).parent.parent   # LORE/
RAW_DATA_DIR  = _ROOT / "raw_data"
PROCESSED_DIR = _ROOT / "processed_data"

# Ensure directories exist
RAW_DATA_DIR.mkdir(exist_ok=True)
PROCESSED_DIR.mkdir(exist_ok=True)
(PROCESSED_DIR / "relationships").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "cisa-kev-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "cwe-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "capec-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "d3fend-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "attack-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "github-advisory-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "zdi-advisory-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "cve-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "nvd-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "exploit-db-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "linux-vulns-database").mkdir(exist_ok=True, parents=True)

def download_file(url, dest_path):
    print(f"Downloading {url} to {dest_path}...")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(dest_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print("Done.")
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False

def download_and_extract_zip(url, extract_to, rename_map=None):
    print(f"Downloading and extracting {url} to {extract_to}...")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            z.extractall(extract_to)
        
        if rename_map:
            for pattern, new_name in rename_map.items():
                # Simple glob matching
                for file in extract_to.glob(pattern):
                    print(f"Renaming {file.name} to {new_name}")
                    file.rename(extract_to / new_name)
                    break # Only rename the first match as per script logic
        print("Done.")
        return True
    except Exception as e:
        print(f"Error processing {url}: {e}")
        return False

def download_repo_snapshot(url, dest_dir, branch="main", is_gitlab=False):
    """
    Downloads a repository snapshot (zip) and extracts it.
    This avoids using git and downloading history.
    It also strips the top-level directory from the archive.
    """
    print(f"Downloading snapshot for {dest_dir} from {url}...")
    
    # Construct snapshot URL
    if is_gitlab:
        # GitLab: https://gitlab.com/user/repo/-/archive/main/repo-main.zip
        snapshot_url = f"{url}/-/archive/{branch}/{url.split('/')[-1]}-{branch}.zip"
    elif "git.kernel.org" in url:
        # Kernel.org: https://git.kernel.org/pub/scm/linux/security/vulns.git/snapshot/vulns-master.tar.gz
        repo_name = url.split('/')[-1].replace('.git', '')
        snapshot_url = f"{url}/snapshot/{repo_name}-{branch}.tar.gz"
    else:
        # GitHub: https://github.com/user/repo/archive/refs/heads/main.zip
        snapshot_url = f"{url}/archive/refs/heads/{branch}.zip"

    dest_path = RAW_DATA_DIR / dest_dir
    dest_path.mkdir(exist_ok=True, parents=True)

    try:
        response = requests.get(snapshot_url, stream=True)
        response.raise_for_status()
        
        with tempfile.TemporaryDirectory() as tmpdirname:
            tmp_path = Path(tmpdirname)
            
            if snapshot_url.endswith('.tar.gz'):
                with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                    tar.extractall(tmp_path)
            else:
                with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                    z.extractall(tmp_path)
            
            # Find the top-level directory
            items = list(tmp_path.iterdir())
            if len(items) == 1 and items[0].is_dir():
                source_dir = items[0]
                print(f"Moving contents from {source_dir.name} to {dest_path}...")
                for item in source_dir.iterdir():
                    dst_item = dest_path / item.name
                    if dst_item.exists():
                        if dst_item.is_dir():
                            shutil.rmtree(dst_item)
                        else:
                            dst_item.unlink()
                    shutil.move(str(item), str(dest_path))
            else:
                print(f"Moving contents to {dest_path}...")
                for item in items:
                    dst_item = dest_path / item.name
                    if dst_item.exists():
                        if dst_item.is_dir():
                            shutil.rmtree(dst_item)
                        else:
                            dst_item.unlink()
                    shutil.move(str(item), str(dest_path))
        
        print(f"Extracted to {dest_path}")
        return True
    except Exception as e:
        print(f"Error downloading snapshot from {snapshot_url}: {e}")
        return False

def main(repos_filter=None):
    """同步知识库数据。
    
    Args:
        repos_filter: 可选的仓库 ID 列表（如 ['cisa-kev','cwe']），None 表示全部同步。
    """

    # ── 任务映射表 ───────────────────────────────────────────────────────────
    def _do_attack():
        attack_dir = RAW_DATA_DIR / "attack-database"
        attack_dir.mkdir(exist_ok=True, parents=True)
        # 下载 MITRE ATT&CK 企业威胁矩阵 STIX 数据（enterprise domain）
        download_file(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
            attack_dir / "enterprise-attack.json"
        )
        # 附加下载 ICS 和 移动端 domain（可选）
        download_file(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
            attack_dir / "ics-attack.json"
        )
        download_file(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
            attack_dir / "mobile-attack.json"
        )

    def _do_cisa_kev():
        kev_json_path = RAW_DATA_DIR / "cisa-kev-database" / "kev.json"
        if download_file("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", kev_json_path):
            try:
                with open(kev_json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                cve_ids = [v['cveID'] for v in data.get('vulnerabilities', [])]
                rel_path = PROCESSED_DIR / "relationships" / "rel-cve-kev.json"
                with open(rel_path, 'w', encoding='utf-8') as f:
                    json.dump(cve_ids, f, indent=2)
                print(f"Generated {rel_path}")
            except Exception as e:
                print(f"Error processing KEV JSON: {e}")

    def _do_cwe():
        download_and_extract_zip(
            "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
            RAW_DATA_DIR / "cwe-database",
            rename_map={"cwec*.xml": "cwec.xml"}
        )

    def _do_capec():
        download_and_extract_zip(
            "https://capec.mitre.org/data/archive/capec_latest.zip",
            RAW_DATA_DIR / "capec-database",
            rename_map={"ap_schema*.xsd": "ap_schema.xsd", "capec*.xml": "capec.xml"}
        )

    def _do_d3fend():
        d3fend_dir = RAW_DATA_DIR / "d3fend-database"
        download_file("https://d3fend.mitre.org/ontologies/d3fend.json", d3fend_dir / "d3fend_ontology.json")
        download_file("https://d3fend.mitre.org/ontologies/d3fend.csv", d3fend_dir / "d3fend.csv")
        download_file("https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json", d3fend_dir / "d3fend_full_mappings.json")

    def _do_github_advisory():
        download_repo_snapshot("https://github.com/github/advisory-database", "github-advisory-database", branch="main")

    def _do_zdi():
        download_repo_snapshot("https://github.com/delikely/ZDI_Advisories", "zdi-advisory-database", branch="main")

    def _do_cve():
        download_repo_snapshot("https://github.com/CVEProject/cvelistV5", "cve-database", branch="main")

    def _do_nvd():
        download_repo_snapshot("https://github.com/fkie-cad/nvd-json-data-feeds", "nvd-database", branch="main")

    def _do_exploitdb():
        download_repo_snapshot("https://gitlab.com/exploit-database/exploitdb", "exploit-db-database", branch="main", is_gitlab=True)

    def _do_linux_vulns():
        # kernel.org snapshot 接口限制访问，改用 GitHub 镜像 (nluedtke/linux_kernel_cves)
        download_repo_snapshot("https://github.com/nluedtke/linux_kernel_cves", "linux-vulns-database", branch="master")

    REPO_TASKS = {
        "attack":          _do_attack,
        "cisa-kev":       _do_cisa_kev,
        "cwe":            _do_cwe,
        "capec":          _do_capec,
        "d3fend":         _do_d3fend,
        "github-advisory":_do_github_advisory,
        "zdi":            _do_zdi,
        "cve":            _do_cve,
        "nvd":            _do_nvd,
        "exploit-db":     _do_exploitdb,
        "linux-vulns":    _do_linux_vulns,
    }

    # ── 执行选中任务 ─────────────────────────────────────────────────────────
    to_run = list(repos_filter) if repos_filter else list(REPO_TASKS.keys())
    invalid = [r for r in to_run if r not in REPO_TASKS]
    if invalid:
        print(f"[!] 未知仓库 ID: {', '.join(invalid)}")
        print(f"    有效 ID: {', '.join(REPO_TASKS.keys())}")
        sys.exit(1)

    print(f"\n[sync] 同步目标: {', '.join(to_run)}\n")
    for repo_id in to_run:
        print(f"\n{'='*60}")
        print(f"  同步: {repo_id}")
        print(f"{'='*60}")
        try:
            REPO_TASKS[repo_id]()
        except Exception as e:
            print(f"[!] {repo_id} 同步失败: {e}")

    print("\n[!] Note: Scripts 'sync-oss-security.py' and 'sync-full-disclosure.py' were not run as they are external scripts.")
    print("[!] Please manually run 'sync-attackerkb.py' and 'sync-cpe.sh' if needed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="同步外部 CVE/漏洞知识库数据",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
可用仓库 ID:
  attack          MITRE ATT&CK (Enterprise/ICS/Mobile STIX)
  cisa-kev        CISA 已知利用漏洞 (KEV)
  cwe             MITRE CWE 数据库
  capec           MITRE CAPEC 数据库
  d3fend          MITRE D3FEND 数据库
  github-advisory GitHub 安全公告数据库
  zdi             ZDI 漏洞公告
  cve             CVE 官方列表 (cvelistV5, 较大)
  nvd             NVD JSON 数据 (fkie-cad)
  exploit-db      Exploit-DB 漏洞利用数据库
  linux-vulns     Linux 内核安全漏洞列表

示例:
  python crawlers/sync_data_light.py                          # 全部同步
  python crawlers/sync_data_light.py --repos attack           # 只同步 MITRE ATT&CK
  python crawlers/sync_data_light.py --repos cisa-kev,cwe    # 只同步指定仓库
        """
    )
    parser.add_argument(
        "--repos", "-r",
        type=str,
        default=None,
        help="要同步的仓库 ID（逗号分隔），默认全部"
    )
    args = parser.parse_args()
    repos_list = [r.strip() for r in args.repos.split(",")] if args.repos else None
    main(repos_filter=repos_list)

