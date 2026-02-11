"""
Evo-Pentest 多维度反思诊断器
基于失败分析结果,诊断查询问题并提供改写建议
"""

import logging
import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

from processors.failure_detector import FailureAnalysis, RetrievalResult
from processors.llm_client import DeepSeekClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EvoPentest.Diagnoser")


class DiagnosisType(Enum):
    """诊断类型枚举"""
    QUERY_DRIFT = "query_drift"  # 查询漂移
    GRANULARITY_IMBALANCE = "granularity_imbalance"  # 粒度失衡
    TERMINOLOGY_MISMATCH = "terminology_mismatch"  # 术语不匹配
    CONTEXT_MISSING = "context_missing"  # 上下文缺失
    OVERLY_SPECIFIC = "overly_specific"  # 过度具体
    OVERLY_GENERAL = "overly_general"  # 过度泛化


@dataclass
class DiagnosisResult:
    """诊断结果"""
    diagnosis_type: DiagnosisType
    confidence: float  # 诊断置信度 (0-1)
    description: str  # 问题描述
    evidence: List[str]  # 证据列表
    recommendations: List[str]  # 改写建议
    
    def __str__(self):
        evidence_str = "\n    ".join(self.evidence)
        recs_str = "\n    ".join(self.recommendations)
        return (
            f"[{self.diagnosis_type.value}] (confidence={self.confidence:.2f})\n"
            f"  Problem: {self.description}\n"
            f"  Evidence:\n    {evidence_str}\n"
            f"  Recommendations:\n    {recs_str}"
        )


class ReflectionDiagnoser:
    """
    多维度反思诊断器
    分析检索失败原因并提供查询改写建议
    """
    
    def __init__(self, llm_client=None):
        """
        Args:
            llm_client: LLM客户端(可选,用于深度诊断)
        """
        self.llm_client = llm_client
    
    def diagnose(self, 
                 query: str,
                 failure_analysis: FailureAnalysis,
                 results: List[RetrievalResult],
                 target_info: str = "",
                 **kwargs) -> List[DiagnosisResult]:
        """
        综合诊断查询问题
        
        Args:
            query: 原始查询
            failure_analysis: 失败分析结果
            results: 检索结果
            target_info: 目标系统信息
            **kwargs: 接收可能的额外参数（如 failure_signals）
        
        Returns:
            诊断结果列表(按置信度降序)
        """
        diagnoses = []
        
        # 维度1: 查询漂移检测
        drift_diag = self._diagnose_query_drift(query, results, failure_analysis)
        if drift_diag:
            diagnoses.append(drift_diag)
        
        # 维度2: 粒度失衡检测
        granularity_diag = self._diagnose_granularity(query, results, failure_analysis)
        if granularity_diag:
            diagnoses.append(granularity_diag)
        
        # 维度3: 术语不匹配检测
        terminology_diag = self._diagnose_terminology(query, results, target_info)
        if terminology_diag:
            diagnoses.append(terminology_diag)
        
        # 维度4: 上下文缺失检测
        context_diag = self._diagnose_context_missing(query, target_info)
        if context_diag:
            diagnoses.append(context_diag)
        
        # 维度5: LLM 深度诊断 (真实实现)
        if self.llm_client and isinstance(self.llm_client, DeepSeekClient):
            llm_diagnoses = self._llm_diagnosis(query, failure_analysis, results, target_info)
            diagnoses.extend(llm_diagnoses)

        # 按置信度排序
        diagnoses.sort(key=lambda d: d.confidence, reverse=True)
        
        return diagnoses
    
    def _llm_diagnosis(self, 
                     query: str,
                     failure_analysis: FailureAnalysis,
                     results: List[RetrievalResult],
                     target_info: str) -> List[DiagnosisResult]:
        """使用 LLM 进行深度诊断 (真实实现)"""
        try:
            summaries = [f"[{r.title}] {r.content[:200]}" for r in results[:3]]
            prompt = f"""As a cyber security expert, diagnose why the retrieval for query '{query}' failed.
Target Info: {target_info}
Failure Reasons: {failure_analysis.failure_reasons}
Top Documents:
{chr(10).join(summaries)}

Identify specific problems and provide recommendations.
Respond in JSON format:
{{
    "diagnoses": [
        {{
            "type": "query_drift|terminology_mismatch|granularity_imbalance|context_missing",
            "confidence": 0.0-1.0,
            "description": "problem description",
            "evidence": ["evidence1", ...],
            "recommendations": ["rec1", ...]
        }}
    ]
}}
"""
            response = self.llm_client.chat(prompt, system_prompt="You are an expert vulnerability researcher.")
            data = self.llm_client.extract_json(response)
            
            results = []
            for d in data.get("diagnoses", []):
                try:
                    diag_type = DiagnosisType(d["type"])
                    results.append(DiagnosisResult(
                        diagnosis_type=diag_type,
                        confidence=d["confidence"],
                        description=d["description"],
                        evidence=d["evidence"],
                        recommendations=d["recommendations"]
                    ))
                except (ValueError, KeyError):
                    continue
            return results
        except Exception as e:
            logger.error(f"LLM diagnosis failed: {e}")
            return []

    def _diagnose_query_drift(self, 
                             query: str, 
                             results: List[RetrievalResult],
                             failure_analysis: FailureAnalysis) -> DiagnosisResult:
        """
        检测查询漂移
        例如: 搜CVE编号但CVE未分配,应该搜产品名+特征词
        """
        evidence = []
        recommendations = []
        confidence = 0.0
        
        # 检查是否包含CVE编号
        cve_pattern = r'cve-\d{4}-\d+'
        cves_in_query = re.findall(cve_pattern, query.lower())
        
        if cves_in_query:
            # 检查返回文档中CVE出现频率
            cve_mentions = 0
            for doc in results[:5]:
                content = (doc.title + " " + doc.content).lower()
                if any(cve in content for cve in cves_in_query):
                    cve_mentions += 1
            
            # 如果CVE很少被提及,可能是漂移
            if cve_mentions < len(results[:5]) * 0.3:
                evidence.append(
                    f"Query contains CVE {cves_in_query[0]}, but only {cve_mentions}/{min(5, len(results))} docs mention it"
                )
                recommendations.append(
                    f"Try product name + vulnerability type instead of CVE number"
                )
                recommendations.append(
                    f"Example: 'WebLogic XML deserialization RCE' instead of '{cves_in_query[0]}'"
                )
                confidence += 0.4
        
        # 检查是否查询过于抽象
        abstract_terms = ['vulnerability', 'exploit', 'attack', 'security', 'pentest']
        abstract_count = sum(1 for term in abstract_terms if term in query.lower())
        
        if abstract_count >= 2 and len(query.split()) <= 5:
            evidence.append(
                f"Query uses {abstract_count} abstract terms with few specifics"
            )
            recommendations.append(
                "Add specific product version or attack vector details"
            )
            confidence += 0.3
        
        # 检查是否缺少动作词
        action_verbs = ['exploit', 'bypass', 'execute', 'inject', 'escalate', 'dump']
        has_action = any(verb in query.lower() for verb in action_verbs)
        
        if not has_action and failure_analysis.diagnostic_details.get('actionable_docs', 0) == 0:
            evidence.append(
                "Query lacks action verbs, may not target executable content"
            )
            recommendations.append(
                "Add action-oriented keywords: 'exploit payload', 'RCE execution', 'bypass authentication'"
            )
            confidence += 0.2
        
        if confidence > 0.0:
            return DiagnosisResult(
                diagnosis_type=DiagnosisType.QUERY_DRIFT,
                confidence=min(1.0, confidence),
                description="Query may be searching for wrong information type",
                evidence=evidence,
                recommendations=recommendations
            )
        
        return None
    
    def _diagnose_granularity(self, 
                             query: str, 
                             results: List[RetrievalResult],
                             failure_analysis: FailureAnalysis) -> DiagnosisResult:
        """
        检测粒度失衡
        """
        evidence = []
        recommendations = []
        confidence = 0.0
        
        query_words = query.split()
        
        # 检测过于泛化 (查询词过少且分数低)
        if len(query_words) <= 3:
            avg_score = failure_analysis.diagnostic_details.get('avg_score', 0)
            if avg_score < 0.5:
                evidence.append(
                    f"Short query ({len(query_words)} words) yields low relevance (avg={avg_score:.2f})"
                )
                recommendations.append(
                    "Add more specific constraints: version numbers, API names, or error messages"
                )
                recommendations.append(
                    "Example: Add '10.3.6.0' or 'XMLDecoder' to narrow scope"
                )
                confidence += 0.5
                
                return DiagnosisResult(
                    diagnosis_type=DiagnosisType.OVERLY_GENERAL,
                    confidence=confidence,
                    description="Query is too general, needs more specific details",
                    evidence=evidence,
                    recommendations=recommendations
                )
        
        # 检测过于具体 (查询词过多且无结果)
        if len(query_words) >= 10:
            doc_count = failure_analysis.diagnostic_details.get('doc_count', 0)
            if doc_count < 3:
                evidence.append(
                    f"Long query ({len(query_words)} words) retrieves few docs ({doc_count})"
                )
                recommendations.append(
                    "Simplify query by removing minor details or version-specific terms"
                )
                recommendations.append(
                    "Focus on core vulnerability type and affected component"
                )
                confidence += 0.6
                
                return DiagnosisResult(
                    diagnosis_type=DiagnosisType.OVERLY_SPECIFIC,
                    confidence=confidence,
                    description="Query is too specific, may be over-constrained",
                    evidence=evidence,
                    recommendations=recommendations
                )
        
        # 检测粒度不匹配 (关键词重叠低)
        keyword_overlap = failure_analysis.diagnostic_details.get('keyword_overlap', 0)
        if keyword_overlap < 0.3:
            evidence.append(
                f"Low keyword overlap ({keyword_overlap:.1%}) between query and docs"
            )
            recommendations.append(
                "Adjust terminology to match documentation style"
            )
            recommendations.append(
                "Try using technical jargon or vendor-specific terms"
            )
            confidence += 0.4
            
            return DiagnosisResult(
                diagnosis_type=DiagnosisType.GRANULARITY_IMBALANCE,
                confidence=confidence,
                description="Query granularity doesn't match available documents",
                evidence=evidence,
                recommendations=recommendations
            )
        
        return None
    
    def _diagnose_terminology(self, 
                             query: str, 
                             results: List[RetrievalResult],
                             target_info: str) -> DiagnosisResult:
        """
        检测术语不匹配
        """
        evidence = []
        recommendations = []
        confidence = 0.0
        
        # 渗透测试常见术语映射
        terminology_variants = {
            'rce': ['remote code execution', 'command injection', 'code exec'],
            'sqli': ['sql injection', 'database injection'],
            'xss': ['cross-site scripting', 'script injection'],
            'lfi': ['local file inclusion', 'file read'],
            'rfi': ['remote file inclusion'],
            'ssrf': ['server-side request forgery'],
            'xxe': ['xml external entity'],
            'deserialization': ['unserialize', 'pickle', 'object injection'],
        }
        
        query_lower = query.lower()
        
        # 检查是否使用缩写但文档使用全称
        for abbr, full_terms in terminology_variants.items():
            if abbr in query_lower:
                # 检查文档中是否更多使用全称
                full_term_mentions = 0
                abbr_mentions = 0
                
                for doc in results[:5]:
                    content = (doc.title + " " + doc.content).lower()
                    for term in full_terms:
                        if term in content:
                            full_term_mentions += 1
                    if abbr in content:
                        abbr_mentions += 1
                
                if full_term_mentions > abbr_mentions * 2:
                    evidence.append(
                        f"Query uses abbreviation '{abbr}', but docs prefer full terms"
                    )
                    recommendations.append(
                        f"Try using: {full_terms[0]}"
                    )
                    confidence += 0.3
        
        # 检查是否缺少产品特定术语
        if target_info:
            target_lower = target_info.lower()
            if 'weblogic' in target_lower and 'weblogic' not in query_lower:
                evidence.append(
                    "Target is WebLogic but query doesn't mention it"
                )
                recommendations.append(
                    "Add 'WebLogic' to query for better precision"
                )
                confidence += 0.4
        
        if confidence > 0.0:
            return DiagnosisResult(
                diagnosis_type=DiagnosisType.TERMINOLOGY_MISMATCH,
                confidence=min(1.0, confidence),
                description="Query terminology doesn't match document vocabulary",
                evidence=evidence,
                recommendations=recommendations
            )
        
        return None
    
    def _diagnose_context_missing(self, 
                                  query: str, 
                                  target_info: str) -> DiagnosisResult:
        """
        检测上下文缺失
        """
        evidence = []
        recommendations = []
        confidence = 0.0
        
        # 检查是否缺少版本信息
        version_pattern = r'\d+\.\d+(\.\d+)?'
        has_version = re.search(version_pattern, query)
        
        if not has_version and target_info:
            target_version = re.search(version_pattern, target_info)
            if target_version:
                evidence.append(
                    f"Query lacks version info, but target is {target_version.group()}"
                )
                recommendations.append(
                    f"Add version number: {target_version.group()}"
                )
                confidence += 0.4
        
        # 检查是否缺少平台信息
        platforms = ['linux', 'windows', 'unix', 'macos']
        has_platform = any(p in query.lower() for p in platforms)
        
        if not has_platform and target_info:
            target_platform = next((p for p in platforms if p in target_info.lower()), None)
            if target_platform:
                evidence.append(
                    f"Query lacks platform info, target runs on {target_platform}"
                )
                recommendations.append(
                    f"Add platform: {target_platform}"
                )
                confidence += 0.3
        
        if confidence > 0.0:
            return DiagnosisResult(
                diagnosis_type=DiagnosisType.CONTEXT_MISSING,
                confidence=min(1.0, confidence),
                description="Query is missing important contextual information",
                evidence=evidence,
                recommendations=recommendations
            )
        
        return None


if __name__ == "__main__":
    # 测试诊断器
    from processors.failure_detector import FailureAnalysis, RetrievalResult
    
    diagnoser = ReflectionDiagnoser()
    
    # 测试用例1: CVE查询漂移
    query1 = "CVE-2017-10271 exploit"
    failure1 = FailureAnalysis(
        is_failed=True,
        confidence=0.8,
        failure_reasons=["Low relevance scores"],
        diagnostic_details={
            "avg_score": 0.35,
            "keyword_overlap": 0.15,
            "actionable_docs": 0
        }
    )
    results1 = [
        RetrievalResult(
            title="WebLogic Security Overview",
            content="General information about WebLogic security features...",
            score=0.4
        )
    ]
    
    diagnoses1 = diagnoser.diagnose(query1, failure1, results1, "WebLogic 10.3.6.0")
    
    logger.info("=" * 80)
    logger.info("Test Case 1: CVE Query Drift")
    logger.info("=" * 80)
    for diag in diagnoses1:
        logger.info(f"\n{diag}")
    
    # 测试用例2: 过于泛化
    query2 = "WebLogic exploit"
    failure2 = FailureAnalysis(
        is_failed=True,
        confidence=0.7,
        failure_reasons=["Too many short documents"],
        diagnostic_details={
            "avg_score": 0.45,
            "keyword_overlap": 0.25,
            "doc_count": 10
        }
    )
    results2 = []
    
    diagnoses2 = diagnoser.diagnose(query2, failure2, results2)
    
    logger.info("\n" + "=" * 80)
    logger.info("Test Case 2: Overly General Query")
    logger.info("=" * 80)
    for diag in diagnoses2:
        logger.info(f"\n{diag}")
