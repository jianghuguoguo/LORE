import os
import requests
import zipfile
import tarfile
import io
import json
import shutil
import tempfile
from pathlib import Path

# Configuration
RAW_DATA_DIR = Path("raw_data")
PROCESSED_DIR = Path("processed_data")

# Ensure directories exist
RAW_DATA_DIR.mkdir(exist_ok=True)
PROCESSED_DIR.mkdir(exist_ok=True)
(PROCESSED_DIR / "relationships").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "cisa-kev-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "cwe-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "capec-database").mkdir(exist_ok=True, parents=True)
(RAW_DATA_DIR / "d3fend-database").mkdir(exist_ok=True, parents=True)

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

def main():
    # 1. CISA KEV
    kev_json_path = RAW_DATA_DIR / "cisa-kev-database" / "kev.json"
    if download_file("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", kev_json_path):
        # Process jq logic: [.vulnerabilities[].cveID]
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

    # 2. CWE
    download_and_extract_zip(
        "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        RAW_DATA_DIR / "cwe-database",
        rename_map={"cwec*.xml": "cwec.xml"}
    )

    # 3. CAPEC
    download_and_extract_zip(
        "https://capec.mitre.org/data/archive/capec_latest.zip",
        RAW_DATA_DIR / "capec-database",
        rename_map={"ap_schema*.xsd": "ap_schema.xsd", "capec*.xml": "capec.xml"}
    )

    # 4. D3FEND
    d3fend_dir = RAW_DATA_DIR / "d3fend-database"
    download_file("https://d3fend.mitre.org/ontologies/d3fend.json", d3fend_dir / "d3fend_ontology.json")
    download_file("https://d3fend.mitre.org/ontologies/d3fend.csv", d3fend_dir / "d3fend.csv")
    download_file("https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json", d3fend_dir / "d3fend_full_mappings.json")

    # 5. Repo Snapshots (Replacing git submodules)
    # GitHub Advisory
    download_repo_snapshot("https://github.com/github/advisory-database", "github-advisory-database", branch="main")
    
    # ZDI
    download_repo_snapshot("https://github.com/delikely/ZDI_Advisories", "zdi-advisory-database", branch="main")
    
    # CVE (cvelist) - Note: This is large
    download_repo_snapshot("https://github.com/CVEProject/cvelistV5", "cve-database", branch="main")
    
    # NVD (JSON Feeds)
    download_repo_snapshot("https://github.com/fkie-cad/nvd-json-data-feeds", "nvd-database", branch="main")
    
    # Exploit-DB
    download_repo_snapshot("https://gitlab.com/exploit-database/exploitdb", "exploit-db-database", branch="main", is_gitlab=True)
    
    # Linux Vulns
    # Note: The branch might be 'master' or something else. The script says 'vulns.git'.
    # Checking online, the default branch for linux-vulns is usually 'master'.
    download_repo_snapshot("https://git.kernel.org/pub/scm/linux/security/vulns.git", "linux-vulns-database", branch="master")

    print("\n[!] Note: Scripts 'sync-oss-security.py' and 'sync-full-disclosure.py' were not run as they are external scripts.")
    print("[!] Please manually run 'sync-attackerkb.py' and 'sync-cpe.sh' if needed.")

if __name__ == "__main__":
    main()
