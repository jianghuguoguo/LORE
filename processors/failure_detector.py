"""
Evo-Pentest 检索失败检测器
基于LLM的文档质量评估,判断检索结果是否能支撑攻击方案生成
"""

import logging
from typing import List, Dict, Tuple
from dataclasses import dataclass
import re

from processors.evo_config import config
from processors.llm_client import DeepSeekClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EvoPentest.FailureDetector")


@dataclass
class RetrievalResult:
    """单个检索结果"""
    title: str
    content: str
    score: float  # 相关度分数
    source: str = ""


@dataclass
class FailureAnalysis:
    """失败分析结果"""
    is_failed: bool  # 是否检索失败
    confidence: float  # 失败判断置信度 (0-1)
    failure_reasons: List[str]  # 失败原因列表
    diagnostic_details: Dict[str, any]  # 诊断详情
    
    def __str__(self):
        if not self.is_failed:
            return "✓ Retrieval Success"
        reasons_str = "\n  - ".join(self.failure_reasons)
        return f"✗ Retrieval Failed (confidence={self.confidence:.2f})\n  - {reasons_str}"


class FailureDetector:
    """
    检索失败检测器
    基于多维度启发式规则 + LLM判断的混合策略
    """
    
    def __init__(self, 
                 llm_client=None,
                 top_k: int = 5,
                 min_useful_docs: int = 2,
                 min_content_length: int = 100):
        """
        Args:
            llm_client: LLM客户端(可选,用于深度判断)
            top_k: 检查前K个文档
            min_useful_docs: 最少有用文档数
            min_content_length: 有效文档最小长度
        """
        self.llm_client = llm_client
        self.top_k = top_k
        self.min_useful_docs = min_useful_docs
        self.min_content_length = min_content_length
    
    def detect(self, 
               query: str, 
               results: List[RetrievalResult],
               target_info: str = "") -> FailureAnalysis:
        """
        综合检测检索是否失败
        
        Args:
            query: 原始查询
            results: 检索结果列表
            target_info: 目标系统信息(可选,用于更精准判断)
        
        Returns:
            FailureAnalysis对象
        """
        if not results:
            return FailureAnalysis(
                is_failed=True,
                confidence=1.0,
                failure_reasons=["No documents retrieved"],
                diagnostic_details={"result_count": 0}
            )
        
        # 多维度启发式检测
        heuristic_analysis = self._heuristic_detection(query, results, target_info)
        
        # 如果启发式判断明确失败,直接返回
        if heuristic_analysis.is_failed and heuristic_analysis.confidence > 0.8:
            return heuristic_analysis
        
        # 如果有LLM,进行深度判断
        if self.llm_client:
            llm_analysis = self._llm_detection(query, results, target_info)
            # 融合两种判断
            return self._merge_analysis(heuristic_analysis, llm_analysis)
        
        return heuristic_analysis
    
    def _heuristic_detection(self, 
                            query: str, 
                            results: List[RetrievalResult],
                            target_info: str) -> FailureAnalysis:
        """
        基于启发式规则的快速检测
        """
        top_docs = results[:self.top_k]
        failure_reasons = []
        diagnostic_details = {}
        
        # 规则1: 检查文档数量
        if len(top_docs) < self.min_useful_docs:
            failure_reasons.append(
                f"Insufficient documents: {len(top_docs)} < {self.min_useful_docs}"
            )
        
        # 规则2: 检查平均内容长度
        avg_content_len = sum(len(d.content) for d in top_docs) / len(top_docs) if top_docs else 0
        if avg_content_len < 50:
            failure_reasons.append(
                f"Average document length too short: {avg_content_len:.1f} < 50"
            )
        
        # 规则3: 检查效用分数分布 (Top-3 平均分)
        top3_docs = top_docs[:3]
        avg_utility_score = sum(d.score for d in top3_docs) / len(top3_docs) if top3_docs else 0.0
        if avg_utility_score < 0.4:
            failure_reasons.append(
                f"Average utility score of Top-3 too low: {avg_utility_score:.3f} < 0.4"
            )
        
        diagnostic_details.update({
            "doc_count": len(top_docs),
            "avg_utility_score": avg_utility_score,
            "top1_score": top_docs[0].score if top_docs else 0.0,
            "avg_content_len": avg_content_len
        })
        
        # 规则4: 检查查询-文档关键词重叠
        query_keywords = set(self._extract_keywords(query))
        overlap_scores = []
        
        for doc in top_docs:
            doc_keywords = set(self._extract_keywords(doc.title + " " + doc.content))
            overlap = len(query_keywords & doc_keywords) / max(len(query_keywords), 1)
            overlap_scores.append(overlap)
        
        avg_overlap = sum(overlap_scores) / len(overlap_scores) if overlap_scores else 0
        if avg_overlap < 0.2:  # 关键词重叠率过低
            failure_reasons.append(
                f"Low keyword overlap: {avg_overlap:.2%}"
            )
        diagnostic_details["keyword_overlap"] = avg_overlap
        
        # 规则5: 渗透测试特定检查 - 是否包含可执行信息
        actionable_count = self._count_actionable_docs(top_docs)
        if actionable_count == 0:
            failure_reasons.append(
                "No actionable content (exploits, payloads, or POCs)"
            )
        diagnostic_details["actionable_docs"] = actionable_count
        
        # 优化策略 3: 预执行语法校验 (Pre-execution Validation)
        # 防止“高分低能”文档（匹配度高但代码有语法错误）
        if actionable_count > 0:
            valid_actionable_count = self._validate_code_syntax(top_docs)
            diagnostic_details["valid_code_docs"] = valid_actionable_count
            if valid_actionable_count == 0:
                failure_reasons.append(
                    "Actionable content found but failed syntax validation (broken code)"
                )
        
        # 计算失败置信度
        is_failed = len(failure_reasons) >= 2  # 至少2个失败指标
        confidence = min(1.0, len(failure_reasons) * 0.25)  # 每个原因贡献0.25
        
        return FailureAnalysis(
            is_failed=is_failed,
            confidence=confidence,
            failure_reasons=failure_reasons,
            diagnostic_details=diagnostic_details
        )
    
    def _llm_detection(self, 
                      query: str, 
                      results: List[RetrievalResult],
                      target_info: str) -> FailureAnalysis:
        """
        基于LLM的深度判断
        构造提示让LLM评估文档是否能支撑攻击方案生成
        """
        top_docs = results[:self.top_k]
        
        # 构造文档摘要
        doc_summaries = []
        for i, doc in enumerate(top_docs, 1):
            content_preview = doc.content[:300] + "..." if len(doc.content) > 300 else doc.content
            doc_summaries.append(
                f"[Doc {i}] {doc.title}\n{content_preview}\n(Score: {doc.score:.3f})"
            )
        
        prompt = f"""You are a penetration testing expert. Evaluate if the retrieved documents can support generating an attack plan.

Query: {query}
Target: {target_info or 'Unknown'}

Retrieved Documents:
{'=' * 60}
{chr(10).join(doc_summaries)}
{'=' * 60}

Analyze whether these documents contain:
1. Specific exploit code or payloads
2. Technical details about the vulnerability
3. Step-by-step exploitation procedures

Respond in JSON format:
{{
    "is_failed": true/false,
    "confidence": 0.0-1.0,
    "failure_reasons": ["reason1", "reason2", ...],
    "actionable_info_found": true/false,
    "recommendation": "suggestion for better query"
}}
"""
        
        try:
            # 真实实现：格式化文档摘要
            summaries = []
            for i, doc in enumerate(top_docs):
                summaries.append(f"Doc {i+1}: [{doc.title}] {doc.content[:300]}...")
            
            prompt = f"""Evaluate if the following retrieval results for query '{query}' are useful for creating a pentest plan or exploit.
Target Context: {target_info}

Documents:
{chr(10).join(summaries)}

Respond in JSON format:
{{
    "is_failed": true/false,
    "confidence": 0.0-1.0,
    "failure_reasons": ["reason1", "reason2", ...],
    "actionable_info_found": true/false,
    "recommendation": "suggestion for better query"
}}
"""
            # 使用 DeepSeek 进行真实判断
            if isinstance(self.llm_client, DeepSeekClient):
                response = self.llm_client.chat(prompt, system_prompt="You are a RAG quality evaluator.")
                analysis = self.llm_client.extract_json(response)
                
                return FailureAnalysis(
                    is_failed=analysis.get("is_failed", False),
                    confidence=analysis.get("confidence", 0.5),
                    failure_reasons=analysis.get("failure_reasons", []),
                    diagnostic_details={
                        "llm_recommendation": analysis.get("recommendation"),
                        "actionable_info": analysis.get("actionable_info_found")
                    }
                )
            
            # Fallback
            return FailureAnalysis(
                is_failed=False,
                confidence=0.0,
                failure_reasons=[],
                diagnostic_details={"method": "llm_skipped"}
            )
        
        except Exception as e:
            logger.error(f"Real LLM detection failed: {e}")
            return FailureAnalysis(
                is_failed=False,
                confidence=0.0,
                failure_reasons=[],
                diagnostic_details={"error": str(e)}
            )
    
    def _merge_analysis(self, 
                       heuristic: FailureAnalysis, 
                       llm: FailureAnalysis) -> FailureAnalysis:
        """
        融合启发式和LLM两种判断
        采用加权平均策略
        """
        # LLM权重更高(0.7),启发式权重0.3
        merged_confidence = 0.3 * heuristic.confidence + 0.7 * llm.confidence
        
        # 合并失败原因
        merged_reasons = list(set(heuristic.failure_reasons + llm.failure_reasons))
        
        # 只要一方判断失败且置信度>0.5,就认为失败
        is_failed = (
            (heuristic.is_failed and heuristic.confidence > 0.5) or
            (llm.is_failed and llm.confidence > 0.5)
        )
        
        merged_details = {
            **heuristic.diagnostic_details,
            **llm.diagnostic_details,
            "fusion_method": "weighted_average"
        }
        
        return FailureAnalysis(
            is_failed=is_failed,
            confidence=merged_confidence,
            failure_reasons=merged_reasons,
            diagnostic_details=merged_details
        )
    
    def _extract_keywords(self, text: str) -> List[str]:
        """
        提取关键词(简单版本,基于正则)
        """
        # 移除特殊字符,转小写
        text = text.lower()
        
        # 提取CVE编号
        cves = re.findall(r'cve-\d{4}-\d+', text)
        
        # 提取技术关键词(3-15个字符的单词)
        words = re.findall(r'\b[a-z0-9]{3,15}\b', text)
        
        # 过滤常见停用词
        stopwords = {'the', 'is', 'at', 'which', 'on', 'and', 'or', 'but', 'in', 'with', 'to', 'for'}
        keywords = [w for w in words if w not in stopwords]
        
        return cves + keywords
    
    def _count_actionable_docs(self, docs: List[RetrievalResult]) -> int:
        """
        统计包含可执行信息的文档数量
        """
        actionable_patterns = [
            r'exploit',
            r'payload',
            r'poc',
            r'proof.of.concept',
            r'attack.vector',
            r'code.*execution',
            r'<?php',  # PHP代码
            r'import\s+\w+',  # Python导入
            r'curl\s+-',  # curl命令
            r'wget\s+',  # wget命令
            r'#!/',  # shell脚本
            r'<\?xml',  # XML payload
        ]
        
        count = 0
        for doc in docs:
            content = (doc.title + " " + doc.content).lower()
            if any(re.search(pattern, content) for pattern in actionable_patterns):
                count += 1
        
        return count

    def _validate_code_syntax(self, docs: List[RetrievalResult]) -> int:
        """
        验证文档中代码块的语法(Dry Run)
        """
        valid_count = 0
        for doc in docs:
            # 找到代码块 (```lang ... ```)
            code_blocks = re.findall(r'```(?:python|xml|bash|php|js)?\n(.*?)```', doc.content, re.DOTALL)
            
            if not code_blocks:
                # 即使没有 markdown 代码块，也检查是否有明显的 payload 特征
                if '<?xml' in doc.content and '</object>' in doc.content:
                    # 简单的 XML 均衡性检查
                    if doc.content.count('<') == doc.content.count('>'):
                        valid_count += 1
                        continue
                
                # 如果完全没找到代码块，且判定为 actionable，则默认通过
                valid_count += 1
                continue

            for code in code_blocks:
                is_valid = True
                # 简单语法规则：括号/引号匹配，非截断
                if code.count('(') != code.count(')'): is_valid = False
                if code.count('{') != code.count('}'): is_valid = False
                if code.count('[') != code.count(']'): is_valid = False
                
                # 渗透测试专属：检查是否有占位符未填充 (例如 "<target_ip>")
                if re.search(r'<target_|\[ip\]|\{IP\}', code):
                    # 这类文档有效用，但需要提示
                    pass
                
                if is_valid: 
                    valid_count += 1
                    break # 只要有一个有效的代码块即可
        
        return valid_count


if __name__ == "__main__":
    # 测试失败检测器
    detector = FailureDetector(top_k=5, min_useful_docs=2)
    
    # 测试用例1: 成功检索
    good_results = [
        RetrievalResult(
            title="CVE-2017-10271 WebLogic RCE Exploit",
            content="This exploit allows remote code execution via XML deserialization. Payload: <?xml version='1.0'?>...",
            score=0.95
        ),
        RetrievalResult(
            title="WebLogic T3 Protocol Analysis",
            content="Detailed technical breakdown of T3 protocol vulnerabilities and exploitation techniques...",
            score=0.87
        ),
    ]
    
    analysis1 = detector.detect(
        query="WebLogic CVE-2017-10271 exploit",
        results=good_results,
        target_info="WebLogic 10.3.6.0"
    )
    
    logger.info("Test Case 1 - Good Retrieval:")
    logger.info(analysis1)
    logger.info(f"Details: {analysis1.diagnostic_details}\n")
    
    # 测试用例2: 失败检索(内容不足)
    bad_results = [
        RetrievalResult(
            title="WebLogic Overview",
            content="Short intro",
            score=0.45
        ),
        RetrievalResult(
            title="General Security",
            content="Basic concepts",
            score=0.32
        ),
    ]
    
    analysis2 = detector.detect(
        query="WebLogic CVE-2017-10271 exploit payload",
        results=bad_results
    )
    
    logger.info("Test Case 2 - Failed Retrieval:")
    logger.info(analysis2)
    logger.info(f"Details: {analysis2.diagnostic_details}")
