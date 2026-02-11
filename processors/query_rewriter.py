"""
Evo-Pentest 查询改写器
基于诊断结果生成3个不同维度的变体查询,实现探索-利用平衡
"""

import logging
import re
from typing import List, Dict, Tuple, Set, Optional
from dataclasses import dataclass
from enum import Enum

from processors.reflection_diagnoser import DiagnosisResult, DiagnosisType
from processors.llm_client import DeepSeekClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EvoPentest.QueryRewriter")


class RewriteStrategy(Enum):
    """改写策略枚举"""
    EXPLOITATION = "exploitation"  # 利用策略：基于当前查询优化
    EXPLORATION_BROAD = "exploration_broad"  # 探索策略1：扩大范围
    EXPLORATION_SPECIFIC = "exploration_specific"  # 探索策略2：聚焦细节


@dataclass
class RewrittenQuery:
    """改写后的查询"""
    query: str
    strategy: RewriteStrategy
    confidence: float  # 改写质量置信度
    rationale: str  # 改写理由
    source_diagnosis: str  # 来源的诊断类型
    
    def __str__(self):
        return (
            f"[{self.strategy.value}] {self.query}\n"
            f"  Confidence: {self.confidence:.2f}\n"
            f"  Rationale: {self.rationale}\n"
            f"  Source: {self.source_diagnosis}"
        )


class QueryRewriter:
    """
    查询改写器
    实现探索-利用平衡的多样化查询生成
    """
    
    def __init__(self, llm_client=None):
        """
        Args:
            llm_client: LLM客户端(可选,用于高级改写)
        """
        self.llm_client = llm_client
        
        # 渗透测试领域词汇库
        self.attack_verbs = [
            'exploit', 'bypass', 'execute', 'inject', 'escalate',
            'dump', 'extract', 'abuse', 'leverage', 'trigger'
        ]
        
        self.vulnerability_types = [
            'RCE', 'SQL injection', 'XSS', 'SSRF', 'XXE',
            'deserialization', 'command injection', 'path traversal'
        ]
        
        self.technical_terms = {
            'weblogic': ['T3 protocol', 'XMLDecoder', 'JNDI', 'JMS'],
            'java': ['deserialization', 'JNDI injection', 'EL injection'],
            'web': ['session fixation', 'CSRF', 'clickjacking'],
        }

    def rewrite(self, 
                original_query: str,
                diagnoses: List[DiagnosisResult],
                target_info: str = "",
                num_variants: int = 3) -> List[RewrittenQuery]:
        """
        生成多样化的改写查询
        """
        # 尝试使用 LLM 进行高动态改写
        if self.llm_client and isinstance(self.llm_client, DeepSeekClient):
            llm_rewrites = self._llm_rewrite(original_query, diagnoses, target_info, num_variants)
            if llm_rewrites:
                return llm_rewrites

        # 降级到启发式改写
        rewritten_queries = []
        
        if not diagnoses:
            rewritten_queries = self._default_rewrites(original_query, target_info)
        else:
            # 策略1: 利用策略(修正当前失败) - 基于最高置信度诊断
            exploit_query = self._exploitation_rewrite(
                original_query, diagnoses[0], target_info
            )
            if exploit_query:
                rewritten_queries.append(exploit_query)
            
            # 策略2: 探索策略(扩大范围) - 上位概念
            broad_query = self._exploration_broad_rewrite(
                original_query, diagnoses, target_info
            )
            if broad_query:
                rewritten_queries.append(broad_query)
            
            # 策略3: 探索策略(细节聚焦) - 下位概念
            specific_query = self._exploration_specific_rewrite(
                original_query, diagnoses, target_info
            )
            if specific_query:
                rewritten_queries.append(specific_query)
        
        # 去重
        seen_queries = set()
        unique_queries = []
        for rq in rewritten_queries:
            if rq.query.lower() not in seen_queries:
                seen_queries.add(rq.query.lower())
                unique_queries.append(rq)
        
        # 按置信度排序
        unique_queries.sort(key=lambda q: q.confidence, reverse=True)
        
        return unique_queries[:num_variants]

    def _extract_anchors(self, query: str, target_info: str) -> Set[str]:
        """提取不可修改的核心实体(如产品名、CVE、端口)"""
        anchors = set()
        # 提取CVE
        cve = re.search(r'cve-\d{4}-\d+', query.lower())
        if cve: anchors.add(cve.group())
        
        # 提取版本号样式的字符串
        version = re.search(r'\d+\.\d+(\.\d+)?', query)
        if version: anchors.add(version.group())

        # 提取已知产品关键词
        products = ['weblogic', 'druid', 'couchdb', 'apache', 'nginx', 'struts']
        for p in products:
            if p in query.lower() or (target_info and p in target_info.lower()):
                anchors.add(p)
        
        return anchors

    def _validate_anchors(self, rewritten_query: str, anchors: Set[str]) -> bool:
        """验证改写后的查询是否保留了足够的锚点"""
        if not anchors:
            return True
            
        hit_count = 0
        hit_anchors = []
        for anchor in anchors:
            if anchor.lower() in rewritten_query.lower():
                hit_count += 1
                hit_anchors.append(anchor)
        
        # 优化逻辑：如果命中率 >= 50%，或者命中了任何一个 Hard Anchor (CVE/Version)
        is_hit_hard = any(re.search(r'cve-\d{4}-\d+|\d+\.\d+', a.lower()) for a in hit_anchors)
        
        if is_hit_hard or hit_count / len(anchors) >= 0.5:
            return True
            
        return False

    def rewrite_with_anchors(self, 
                original_query: str,
                diagnoses: List[DiagnosisResult],
                target_info: str = "",
                num_variants: int = 3) -> List[RewrittenQuery]:
        """增强版改写：包含实体锚点校验"""
        # 优化策略 2: 提取核心实体锚点 (Entity Anchoring)
        anchors = self._extract_anchors(original_query, target_info)
        logger.info(f"⚓ Entity Anchors: {anchors}")
        
        # 调用原始的 rewrite 逻辑
        candidates = self.rewrite(original_query, diagnoses, target_info, num_variants + 5)
        
        # 过滤掉丢失锚点的变体 (Semantic Drift Risk Mitigation)
        validated = []
        for cand in candidates:
            if self._validate_anchors(cand.query, anchors):
                validated.append(cand)
            else:
                logger.warning(f"⚠️ Dropping drift candidate: '{cand.query}' (Missing anchors: {anchors})")
        
        return validated[:num_variants]
    
    def _exploitation_rewrite(self, 
                             query: str,
                             top_diagnosis: DiagnosisResult,
                             target_info: str) -> RewrittenQuery:
        """
        利用策略：基于诊断建议优化查询
        """
        new_query = query
        rationale = []
        confidence = top_diagnosis.confidence
        
        # 根据诊断类型应用不同改写规则
        if top_diagnosis.diagnosis_type == DiagnosisType.QUERY_DRIFT:
            # CVE号 -> 产品名+漏洞类型
            cve_match = re.search(r'cve-\d{4}-\d+', query.lower())
            if cve_match:
                # 提取目标产品
                product = self._extract_product(target_info or query)
                vuln_type = self._infer_vulnerability_type(query)
                
                new_query = f"{product} {vuln_type} exploit payload"
                rationale.append(f"Replaced CVE with product+type: {product} {vuln_type}")
        
        elif top_diagnosis.diagnosis_type == DiagnosisType.OVERLY_GENERAL:
            # 添加具体化细节
            additions = []
            
            # 添加版本号
            if target_info:
                version = re.search(r'\d+\.\d+(\.\d+)?', target_info)
                if version and version.group() not in query:
                    additions.append(version.group())
                    rationale.append(f"Added version: {version.group()}")
            
            # 添加动作词
            if not any(verb in query.lower() for verb in self.attack_verbs):
                additions.append('exploit')
                rationale.append("Added action verb: exploit")
            
            # 添加技术细节
            product_key = self._extract_product(query).lower()
            if product_key in self.technical_terms:
                tech_term = self.technical_terms[product_key][0]
                if tech_term.lower() not in query.lower():
                    additions.append(tech_term)
                    rationale.append(f"Added technical term: {tech_term}")
            
            new_query = f"{query} {' '.join(additions)}".strip()
        
        elif top_diagnosis.diagnosis_type == DiagnosisType.OVERLY_SPECIFIC:
            # 简化查询
            words = query.split()
            # 保留关键词：产品名、CVE、核心动词
            important_words = []
            for word in words:
                if (any(verb in word.lower() for verb in self.attack_verbs) or
                    'cve' in word.lower() or
                    len(word) > 5):  # 长词通常更重要
                    important_words.append(word)
            
            new_query = ' '.join(important_words[:8])  # 限制最多8个词
            rationale.append(f"Simplified from {len(words)} to {len(important_words)} words")
        
        elif top_diagnosis.diagnosis_type == DiagnosisType.TERMINOLOGY_MISMATCH:
            # 替换术语
            # 缩写 -> 全称
            replacements = {
                'rce': 'remote code execution',
                'sqli': 'SQL injection',
                'xss': 'cross-site scripting',
                'lfi': 'local file inclusion',
                'ssrf': 'server-side request forgery',
            }
            
            new_query = query
            for abbr, full in replacements.items():
                if abbr in query.lower() and full not in query.lower():
                    new_query = re.sub(
                        rf'\b{abbr}\b', full, new_query, flags=re.IGNORECASE
                    )
                    rationale.append(f"Expanded {abbr} to {full}")
        
        elif top_diagnosis.diagnosis_type == DiagnosisType.CONTEXT_MISSING:
            # 添加上下文
            context_additions = []
            
            if target_info:
                # 添加平台
                platforms = ['linux', 'windows', 'unix']
                for platform in platforms:
                    if platform in target_info.lower() and platform not in query.lower():
                        context_additions.append(platform)
                        rationale.append(f"Added platform: {platform}")
                        break
                
                # 添加版本
                version = re.search(r'\d+\.\d+(\.\d+)?', target_info)
                if version and version.group() not in query:
                    context_additions.append(version.group())
                    rationale.append(f"Added version: {version.group()}")
            
            new_query = f"{query} {' '.join(context_additions)}".strip()
        
        if not rationale:
            rationale.append("Applied top diagnosis recommendation")
        
        return RewrittenQuery(
            query=new_query,
            strategy=RewriteStrategy.EXPLOITATION,
            confidence=confidence,
            rationale="; ".join(rationale),
            source_diagnosis=top_diagnosis.diagnosis_type.value
        )
    
    def _exploration_broad_rewrite(self, 
                                  query: str,
                                  diagnoses: List[DiagnosisResult],
                                  target_info: str) -> RewrittenQuery:
        """
        探索策略(扩大范围)：使用上位概念
        """
        # 提取核心实体
        product = self._extract_product(query)
        
        # 移除具体版本号
        broad_query = re.sub(r'\d+\.\d+(\.\d+)?', '', query)
        
        # 替换为更泛化的术语
        broad_query = re.sub(r'\bcve-\d{4}-\d+\b', 'vulnerability', broad_query, flags=re.IGNORECASE)
        
        # 添加泛化的攻击类型
        if product:
            broad_query = f"{product} vulnerabilities exploitation techniques"
        
        rationale = "Broadened scope by removing specifics and using general terms"
        
        return RewrittenQuery(
            query=broad_query,
            strategy=RewriteStrategy.EXPLORATION_BROAD,
            confidence=0.6,  # 探索策略置信度适中
            rationale=rationale,
            source_diagnosis="exploration"
        )
    
    def _exploration_specific_rewrite(self, 
                                     query: str,
                                     diagnoses: List[DiagnosisResult],
                                     target_info: str) -> RewrittenQuery:
        """
        探索策略(细节聚焦)：深入技术细节
        """
        product = self._extract_product(query).lower()
        
        # 添加技术细节
        technical_additions = []
        
        # 从词汇库添加具体技术术语
        if product in self.technical_terms:
            tech_terms = self.technical_terms[product]
            # 选择第一个未在查询中的术语
            for term in tech_terms:
                if term.lower() not in query.lower():
                    technical_additions.append(term)
                    break
        
        # 添加具体的攻击载荷术语
        payload_terms = ['payload', 'POC', 'working example', 'code']
        for term in payload_terms:
            if term.lower() not in query.lower():
                technical_additions.append(term)
                break
        
        specific_query = f"{query} {' '.join(technical_additions)}".strip()
        
        rationale = f"Added technical specifics: {', '.join(technical_additions)}"
        
        return RewrittenQuery(
            query=specific_query,
            strategy=RewriteStrategy.EXPLORATION_SPECIFIC,
            confidence=0.7,
            rationale=rationale,
            source_diagnosis="exploration"
        )
    
    def _llm_rewrite(self, 
                    original_query: str, 
                    diagnoses: List[DiagnosisResult], 
                    target_info: str, 
                    num_variants: int) -> List[RewrittenQuery]:
        """使用 LLM 生成改写查询 (真实实现)"""
        try:
            diag_str = "\n".join([str(d) for d in diagnoses])
            prompt = f"""As a cyber security researcher, rewrite the search query to yield better pentest documentation.
Original Query: {original_query}
Target Info: {target_info}
Diagnoses:
{diag_str}

Generate {num_variants} diverse search queries using different strategies (Exploitation, Exploration).
Respond in JSON format:
{{
    "rewrites": [
        {{
            "query": "new query string",
            "strategy": "exploitation|exploration_broad|exploration_specific",
            "confidence": 0.0-1.0,
            "rationale": "why this rewrite helps"
        }}
    ]
}}
"""
            response = self.llm_client.chat(prompt, system_prompt="You are a senior penetration tester.")
            data = self.llm_client.extract_json(response)
            
            results = []
            for r in data.get("rewrites", []):
                try:
                    # 将字符串策略转为枚举
                    strategy = RewriteStrategy(r.get("strategy", "exploitation").lower())
                    results.append(RewrittenQuery(
                        query=r["query"],
                        strategy=strategy,
                        confidence=r.get("confidence", 0.8),
                        rationale=r.get("rationale", "LLM reasoning"),
                        source_diagnosis=r.get("source_diagnosis", diagnoses[0].diagnosis_type.value if diagnoses else "manual")
                    ))
                except (ValueError, KeyError):
                    continue
            return results
        except Exception as e:
            logger.error(f"LLM rewrite failed: {e}")
            return []

    def _default_rewrites(self, query: str, target_info: str) -> List[RewrittenQuery]:
        """
        默认改写策略(当没有诊断结果时)
        """
        variants = []
        
        # 变体1: 添加 "exploit payload"
        variant1 = f"{query} exploit payload"
        variants.append(RewrittenQuery(
            query=variant1,
            strategy=RewriteStrategy.EXPLOITATION,
            confidence=0.5,
            rationale="Added exploit+payload keywords",
            source_diagnosis="default"
        ))
        
        # 变体2: 产品名 + 泛化
        product = self._extract_product(query)
        if product:
            variant2 = f"{product} vulnerabilities exploitation"
            variants.append(RewrittenQuery(
                query=variant2,
                strategy=RewriteStrategy.EXPLORATION_BROAD,
                confidence=0.4,
                rationale="Broadened to product vulnerabilities",
                source_diagnosis="default"
            ))
        
        # 变体3: 添加技术细节
        variant3 = f"{query} POC working example"
        variants.append(RewrittenQuery(
            query=variant3,
            strategy=RewriteStrategy.EXPLORATION_SPECIFIC,
            confidence=0.6,
            rationale="Added POC+example for specificity",
            source_diagnosis="default"
        ))
        
        return variants
    
    def _extract_product(self, text: str) -> str:
        """
        从文本中提取产品名
        """
        # 常见产品名列表
        products = [
            'WebLogic', 'Tomcat', 'JBoss', 'Jenkins', 'Struts',
            'Apache', 'Nginx', 'IIS', 'MySQL', 'PostgreSQL',
            'Redis', 'MongoDB', 'CouchDB', 'Elasticsearch'
        ]
        
        text_lower = text.lower()
        for product in products:
            if product.lower() in text_lower:
                return product
        
        # 如果没找到,返回第一个大写词
        words = text.split()
        for word in words:
            if word[0].isupper() and len(word) > 3:
                return word
        
        return "target"
    
    def _infer_vulnerability_type(self, query: str) -> str:
        """
        推断漏洞类型
        """
        query_lower = query.lower()
        
        type_keywords = {
            'deserialization': ['deserial', 'unserialize', 'pickle'],
            'RCE': ['rce', 'remote code', 'command injection'],
            'SQL injection': ['sqli', 'sql injection'],
            'XML': ['xml', 'xxe', 'xmldecoder'],
        }
        
        for vuln_type, keywords in type_keywords.items():
            if any(kw in query_lower for kw in keywords):
                return vuln_type
        
        return 'vulnerability'


if __name__ == "__main__":
    # 测试查询改写器
    from processors.reflection_diagnoser import DiagnosisResult, DiagnosisType
    
    rewriter = QueryRewriter()
    
    # 测试用例1: CVE查询漂移
    logger.info("=" * 80)
    logger.info("Test Case 1: CVE Query Drift")
    logger.info("=" * 80)
    
    diagnosis1 = DiagnosisResult(
        diagnosis_type=DiagnosisType.QUERY_DRIFT,
        confidence=0.8,
        description="Query uses CVE but docs don't mention it",
        evidence=["CVE-2017-10271 mentioned only in 1/5 docs"],
        recommendations=["Try product name + vulnerability type"]
    )
    
    rewrites1 = rewriter.rewrite(
        original_query="CVE-2017-10271 exploit",
        diagnoses=[diagnosis1],
        target_info="WebLogic 10.3.6.0"
    )
    
    for i, rw in enumerate(rewrites1, 1):
        logger.info(f"\nVariant {i}:")
        logger.info(rw)
    
    # 测试用例2: 过于泛化
    logger.info("\n" + "=" * 80)
    logger.info("Test Case 2: Overly General")
    logger.info("=" * 80)
    
    diagnosis2 = DiagnosisResult(
        diagnosis_type=DiagnosisType.OVERLY_GENERAL,
        confidence=0.7,
        description="Query too short and vague",
        evidence=["Only 2 words", "Low avg score"],
        recommendations=["Add version", "Add technical details"]
    )
    
    rewrites2 = rewriter.rewrite(
        original_query="WebLogic exploit",
        diagnoses=[diagnosis2],
        target_info="WebLogic 10.3.6.0"
    )
    
    for i, rw in enumerate(rewrites2, 1):
        logger.info(f"\nVariant {i}:")
        logger.info(rw)
    
    # 测试用例3: 无诊断结果(默认策略)
    logger.info("\n" + "=" * 80)
    logger.info("Test Case 3: Default Strategy")
    logger.info("=" * 80)
    
    rewrites3 = rewriter.rewrite(
        original_query="WebLogic deserialization",
        diagnoses=[],
        target_info="WebLogic 12.1.3"
    )
    
    for i, rw in enumerate(rewrites3, 1):
        logger.info(f"\nVariant {i}:")
        logger.info(rw)
