# stix/stix_utils.py
"""
STIX 数据解析工具函数
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def filter_objects(bundle: Dict[str, Any], obj_type: str) -> List[Dict[str, Any]]:
    """
    从 STIX bundle 中过滤指定类型的对象
    
    Args:
        bundle: STIX bundle 字典
        obj_type: STIX 对象类型（如 'attack-pattern', 'x-mitre-tactic'）
    
    Returns:
        匹配的对象列表
    """
    return [obj for obj in bundle.get("objects", []) if obj.get("type") == obj_type]


def stix_id_map(objects: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    将 STIX 对象列表转换为 ID -> 对象的映射
    
    Args:
        objects: STIX 对象列表
    
    Returns:
        {stix_id: object} 字典
    """
    return {obj["id"]: obj for obj in objects if "id" in obj}


def get_external_id(obj: Dict[str, Any], source_name: str = "mitre-attack") -> Optional[str]:
    """
    从 STIX 对象的 external_references 中提取 ATT&CK ID
    
    Args:
        obj: STIX 对象
        source_name: 来源名称（默认 'mitre-attack'）
    
    Returns:
        ATT&CK ID（如 T1059, TA0001, G0016）或 None
    """
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref.get("external_id")
    return None


def get_external_url(obj: Dict[str, Any], source_name: str = "mitre-attack") -> Optional[str]:
    """
    从 STIX 对象的 external_references 中提取 URL
    """
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref.get("url")
    return None


def safe_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """
    安全地将 STIX 时间戳字符串转换为 datetime
    
    Args:
        ts_str: ISO 8601 时间戳字符串
    
    Returns:
        datetime 对象或 None
    """
    if not ts_str:
        return None
    try:
        # 移除 'Z' 并添加时区信息
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as e:
        logger.warning(f"Invalid timestamp: {ts_str} - {e}")
        return None


def extract_kill_chain_phases(obj: Dict[str, Any]) -> List[str]:
    """
    提取 kill_chain_phases 中的战术短名称
    
    Args:
        obj: STIX attack-pattern 对象
    
    Returns:
        战术短名称列表（如 ['initial-access', 'execution']）
    """
    phases = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            phases.append(phase.get("phase_name"))
    return phases


def build_relationships_map(relationships: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    构建关系映射（按 source_ref 分组）
    
    Args:
        relationships: STIX relationship 对象列表
    
    Returns:
        {source_ref: [relationship_objects]} 字典
    """
    rel_map = {}
    for rel in relationships:
        source = rel.get("source_ref")
        if source:
            rel_map.setdefault(source, []).append(rel)
    return rel_map


def parse_bundle_statistics(bundle: Dict[str, Any]) -> Dict[str, int]:
    """
    统计 STIX bundle 中各类型对象的数量
    
    Args:
        bundle: STIX bundle 字典
    
    Returns:
        {type: count} 字典
    """
    stats = {}
    for obj in bundle.get("objects", []):
        obj_type = obj.get("type", "unknown")
        stats[obj_type] = stats.get(obj_type, 0) + 1
    return stats


def get_mitre_version(bundle: Dict[str, Any]) -> Optional[str]:
    """
    从 STIX bundle 中提取 ATT&CK 版本号
    
    Returns:
        版本号字符串（如 '14.1'）或 None
    """
    # 查找 x-mitre-collection 对象
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version")
    return None


class STIXProcessor:
    """STIX 数据处理器"""
    
    def __init__(self, bundle: Dict[str, Any]):
        self.bundle = bundle
        self.objects = bundle.get("objects", [])
        self.id_map = stix_id_map(self.objects)
        
        # 按类型分类
        self.tactics = filter_objects(bundle, "x-mitre-tactic")
        self.techniques = filter_objects(bundle, "attack-pattern")
        self.groups = filter_objects(bundle, "intrusion-set")
        self.malware = filter_objects(bundle, "malware")
        self.tools = filter_objects(bundle, "tool")
        self.campaigns = filter_objects(bundle, "campaign")
        self.mitigations = filter_objects(bundle, "course-of-action")
        self.datasources = filter_objects(bundle, "x-mitre-data-source")
        self.relationships = filter_objects(bundle, "relationship")
        
        # 构建关系映射
        self.rel_map = build_relationships_map(self.relationships)
        
        logger.info(f"STIX Processor initialized: {len(self.objects)} objects")
    
    def get_statistics(self) -> Dict[str, int]:
        """获取统计信息"""
        return {
            "tactics": len(self.tactics),
            "techniques": len(self.techniques),
            "groups": len(self.groups),
            "malware": len(self.malware),
            "tools": len(self.tools),
            "campaigns": len(self.campaigns),
            "mitigations": len(self.mitigations),
            "datasources": len(self.datasources),
            "relationships": len(self.relationships),
        }
    
    def get_technique_tactics(self, technique_stix_id: str) -> List[str]:
        """获取技术所属的战术短名称列表"""
        tech_obj = self.id_map.get(technique_stix_id)
        if not tech_obj:
            return []
        return extract_kill_chain_phases(tech_obj)
    
    def get_related_objects(self, stix_id: str, relationship_type: str = None) -> List[Dict[str, Any]]:
        """
        获取与指定对象相关的对象
        
        Args:
            stix_id: STIX 对象 ID
            relationship_type: 关系类型过滤（如 'uses', 'mitigates'）
        """
        results = []
        for rel in self.rel_map.get(stix_id, []):
            if relationship_type and rel.get("relationship_type") != relationship_type:
                continue
            target_id = rel.get("target_ref")
            target_obj = self.id_map.get(target_id)
            if target_obj:
                results.append({
                    "object": target_obj,
                    "relationship": rel
                })
        return results


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(level=logging.INFO)
    
    test_bundle = {
        "objects": [
            {"id": "attack-pattern--123", "type": "attack-pattern", "name": "Test"},
            {"id": "x-mitre-tactic--456", "type": "x-mitre-tactic", "name": "Initial Access"},
        ]
    }
    
    processor = STIXProcessor(test_bundle)
    print(processor.get_statistics())
