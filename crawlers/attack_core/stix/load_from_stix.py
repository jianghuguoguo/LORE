# stix/load_from_stix.py
"""
从 STIX bundle 加载数据到数据库（或导出 JSON）
"""

import json
import logging
from typing import Dict, Any, List
from pathlib import Path

from config import STIX_OUTPUT_DIR
from .stix_utils import (
    STIXProcessor,
    get_external_id,
    get_external_url,
    safe_timestamp,
    extract_kill_chain_phases,
)

logger = logging.getLogger(__name__)


class STIXToJSONLoader:
    """将 STIX bundle 转换为结构化 JSON（不依赖数据库）"""
    
    def __init__(self, bundle: Dict[str, Any], domain: str):
        self.processor = STIXProcessor(bundle)
        self.domain = domain
        self.results = {
            "domain": domain,
            "version": bundle.get("spec_version", "2.1"),
            "tactics": [],
            "techniques": [],
            "groups": [],
            "software": [],
            "campaigns": [],
            "mitigations": [],
            "datasources": [],
            "relationships": {
                "technique_tactic": [],
                "group_technique": [],
                "software_technique": [],
                "technique_mitigation": [],
            }
        }
    
    def load_all(self) -> Dict[str, Any]:
        """加载所有数据"""
        logger.info(f"Loading STIX data for domain: {self.domain}")
        
        self.load_tactics()
        self.load_techniques()
        self.load_groups()
        self.load_software()
        self.load_campaigns()
        self.load_mitigations()
        self.load_datasources()
        self.load_relationships()
        
        logger.info(f"Loaded {len(self.results['techniques'])} techniques, "
                   f"{len(self.results['groups'])} groups, "
                   f"{len(self.results['software'])} software")
        
        return self.results
    
    def load_tactics(self):
        """加载战术"""
        for tac in self.processor.tactics:
            tactic_id = get_external_id(tac)
            if not tactic_id:
                continue
            
            self.results["tactics"].append({
                "id": tactic_id,
                "stix_id": tac["id"],
                "domain": self.domain,
                "short_name": tac.get("x_mitre_shortname"),
                "name": tac["name"],
                "description": tac.get("description"),
                "url": get_external_url(tac),
                "created": safe_timestamp(tac.get("created")),
                "modified": safe_timestamp(tac.get("modified")),
            })
    
    def load_techniques(self):
        """加载技术"""
        for tech in self.processor.techniques:
            tech_id = get_external_id(tech)
            if not tech_id:
                continue
            
            # 查找父技术
            parent_id = None
            if tech.get("x_mitre_is_subtechnique"):
                parent_ref = tech.get("x_mitre_deprecated_parent_technique_ref") or \
                            tech.get("x_mitre_parent_technique_ref")
                if parent_ref:
                    parent_obj = self.processor.id_map.get(parent_ref)
                    if parent_obj:
                        parent_id = get_external_id(parent_obj)
            
            technique_data = {
                "id": tech_id,
                "stix_id": tech["id"],
                "domain": self.domain,
                "name": tech["name"],
                "description": tech.get("description"),
                "is_subtechnique": bool(tech.get("x_mitre_is_subtechnique")),
                "parent_technique_id": parent_id,
                "platforms": tech.get("x_mitre_platforms", []),
                "permissions_required": tech.get("x_mitre_permissions_required", []),
                "defense_bypassed": tech.get("x_mitre_defense_bypassed", []),
                "url": get_external_url(tech),
                "created": safe_timestamp(tech.get("created")),
                "modified": safe_timestamp(tech.get("modified")),
                "kill_chain_phases": extract_kill_chain_phases(tech),
            }
            
            self.results["techniques"].append(technique_data)
    
    def load_groups(self):
        """加载组织"""
        for group in self.processor.groups:
            group_id = get_external_id(group)
            if not group_id:
                continue
            
            self.results["groups"].append({
                "id": group_id,
                "stix_id": group["id"],
                "name": group["name"],
                "aliases": group.get("aliases", []),
                "description": group.get("description"),
                "url": get_external_url(group),
                "created": safe_timestamp(group.get("created")),
                "modified": safe_timestamp(group.get("modified")),
            })
    
    def load_software(self):
        """加载软件（malware + tool）"""
        for sw in self.processor.malware + self.processor.tools:
            sw_id = get_external_id(sw)
            if not sw_id:
                continue
            
            self.results["software"].append({
                "id": sw_id,
                "stix_id": sw["id"],
                "name": sw["name"],
                "type": sw["type"],  # malware or tool
                "aliases": sw.get("x_mitre_aliases", []),
                "platforms": sw.get("x_mitre_platforms", []),
                "description": sw.get("description"),
                "url": get_external_url(sw),
                "created": safe_timestamp(sw.get("created")),
                "modified": safe_timestamp(sw.get("modified")),
            })
    
    def load_campaigns(self):
        """加载活动"""
        for camp in self.processor.campaigns:
            camp_id = get_external_id(camp)
            if not camp_id:
                continue
            
            self.results["campaigns"].append({
                "id": camp_id,
                "stix_id": camp["id"],
                "name": camp["name"],
                "description": camp.get("description"),
                "first_seen": camp.get("first_seen"),
                "last_seen": camp.get("last_seen"),
                "url": get_external_url(camp),
                "created": safe_timestamp(camp.get("created")),
                "modified": safe_timestamp(camp.get("modified")),
            })
    
    def load_mitigations(self):
        """加载缓解措施"""
        for mit in self.processor.mitigations:
            mit_id = get_external_id(mit)
            if not mit_id:
                continue
            
            self.results["mitigations"].append({
                "id": mit_id,
                "stix_id": mit["id"],
                "domain": self.domain,
                "name": mit["name"],
                "description": mit.get("description"),
                "url": get_external_url(mit),
                "created": safe_timestamp(mit.get("created")),
                "modified": safe_timestamp(mit.get("modified")),
            })
    
    def load_datasources(self):
        """加载数据源"""
        for ds in self.processor.datasources:
            ds_id = get_external_id(ds)
            if not ds_id:
                continue
            
            self.results["datasources"].append({
                "id": ds_id,
                "stix_id": ds["id"],
                "domain": self.domain,
                "name": ds["name"],
                "description": ds.get("description"),
                "url": get_external_url(ds),
                "created": safe_timestamp(ds.get("created")),
                "modified": safe_timestamp(ds.get("modified")),
            })
    
    def load_relationships(self):
        """加载关系"""
        # 构建 stix_id -> attack_id 映射
        stix_to_attack = {}
        for item in (self.results["techniques"] + self.results["groups"] + 
                    self.results["software"] + self.results["mitigations"]):
            stix_to_attack[item["stix_id"]] = item["id"]
        
        for rel in self.processor.relationships:
            rel_type = rel.get("relationship_type")
            source_ref = rel.get("source_ref")
            target_ref = rel.get("target_ref")
            
            source_id = stix_to_attack.get(source_ref)
            target_id = stix_to_attack.get(target_ref)
            
            if not source_id or not target_id:
                continue
            
            # 根据关系类型分类
            if rel_type == "uses":
                # Group uses Technique 或 Software uses Technique
                source_obj = self.processor.id_map.get(source_ref)
                target_obj = self.processor.id_map.get(target_ref)
                
                if source_obj and target_obj:
                    if source_obj.get("type") == "intrusion-set":
                        self.results["relationships"]["group_technique"].append({
                            "group_id": source_id,
                            "technique_id": target_id,
                            "description": rel.get("description"),
                        })
                    elif source_obj.get("type") in ("malware", "tool"):
                        self.results["relationships"]["software_technique"].append({
                            "software_id": source_id,
                            "technique_id": target_id,
                            "description": rel.get("description"),
                        })
            
            elif rel_type == "mitigates":
                # Mitigation mitigates Technique
                self.results["relationships"]["technique_mitigation"].append({
                    "mitigation_id": source_id,
                    "technique_id": target_id,
                    "description": rel.get("description"),
                })
    
    def save_to_json(self, output_path: str):
        """保存为 JSON 文件"""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 自定义 JSON 编码器处理 datetime
        def json_serializer(obj):
            if hasattr(obj, 'isoformat'):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=json_serializer)
        
        logger.info(f"Saved to {output_file}")


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(level=logging.INFO)
    
    # 需要先运行 extract_stix.py 生成数据
    test_file = Path(STIX_OUTPUT_DIR) / "enterprise-attack-raw.json"
    if test_file.exists():
        with open(test_file, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        
        loader = STIXToJSONLoader(bundle, "enterprise")
        results = loader.load_all()
        loader.save_to_json(Path(STIX_OUTPUT_DIR) / "enterprise-attack-processed.json")
