"""
Deterministic AI Reasoning Engine for SupplyGuard AI.
Synthesizes structured security findings and correlated risk chains into
an executive summary, prioritized risks, potential impacts, and actionable remediations.
100% offline, zero-network, zero-subprocess, hallucination-free.
"""

from typing import Dict, Any, List, Optional, Set

from core.ai.base import SecurityReasoner
from core.models import (
    SecurityFinding,
    RiskChain,
    AIAnalysisResult,
    ProjectContext,
    FindingCategory,
    SeverityLevel,
)

SEVERITY_ORDER: Dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFO: 1,
}

CATEGORY_FRIENDLY_NAMES: Dict[FindingCategory, str] = {
    FindingCategory.EXPOSED_SECRET: "credential exposure",
    FindingCategory.INSTALL_HOOK: "installation lifecycle hooks",
    FindingCategory.DANGEROUS_EXECUTION: "dangerous code execution patterns",
    FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK: "dependency reproducibility risks",
    FindingCategory.CONFIG_ISSUE: "configuration issues",
}


class DeterministicReasoner(SecurityReasoner):
    """
    Offline deterministic reasoner that analyzes structured security findings.
    Operates without LLM hallucination: all claims, impacts, and remediations
    are derived directly from verified scanner evidence and correlation rules.
    """

    def generate_assessment(
        self,
        findings: List[SecurityFinding],
        risk_chains: List[RiskChain],
        project_context: Optional[ProjectContext] = None,
    ) -> AIAnalysisResult:
        if not findings and not risk_chains:
            return AIAnalysisResult(
                executive_summary=(
                    "No findings were detected by the current rule set. "
                    "The current static analysis rules identified no matching supply-chain risk patterns."
                ),
                priority_risks=[],
                remediation_order=[
                    "Continue maintaining security hygiene by pinning dependencies and avoiding hardcoded secrets."
                ],
                correlated_risks=[],
                potential_impacts=[],
                remediation_priorities=[],
                evidence_references=[],
                provider_used="deterministic-offline",
            )

        # 1. Rank Priority Risks
        ranked_chains = sorted(
            risk_chains,
            key=lambda c: (
                SEVERITY_ORDER.get(c.composite_severity, 0),
                c.risk_priority_score,
                len(c.finding_ids),
                c.id,
            ),
            reverse=True,
        )

        priority_risks: List[Dict[str, Any]] = []
        for c in ranked_chains:
            priority_risks.append({
                "chain_id": c.id,
                "title": c.title,
                "severity": c.composite_severity.value,
                "score": c.risk_priority_score,
                "explanation": c.rationale or c.description,
                "finding_ids": list(c.finding_ids),
            })

        # 2. Correlated Risks Narrative
        correlated_risks: List[Dict[str, Any]] = []
        for c in ranked_chains:
            correlated_risks.append({
                "chain_id": c.id,
                "rule_id": c.rule_id,
                "title": c.title,
                "attack_vector": c.attack_vector,
                "explanation": (
                    f"The engine correlated {len(c.finding_ids)} finding(s) under rule '{c.rule_id}'. {c.rationale}"
                ),
                "finding_ids": list(c.finding_ids),
            })

        # 3. Potential Impacts (strictly conditional wording)
        potential_impacts: List[Dict[str, Any]] = []
        categories_present = set(f.category for f in findings)
        rule_ids_present = set(c.rule_id for c in risk_chains)

        if "INSTALL_REMOTE_EXECUTION" in rule_ids_present:
            matching_chains = [c for c in risk_chains if c.rule_id == "INSTALL_REMOTE_EXECUTION"]
            potential_impacts.append({
                "risk_type": "Remote Execution during Installation",
                "impact": (
                    "Potential impact includes execution of externally obtained content during dependency "
                    "installation if unverified commands or downloads are triggered."
                ),
                "traceable_chain_ids": [c.id for c in matching_chains],
            })

        if "INSTALL_CREDENTIAL_ACCESS" in rule_ids_present:
            matching_chains = [c for c in risk_chains if c.rule_id == "INSTALL_CREDENTIAL_ACCESS"]
            potential_impacts.append({
                "risk_type": "Installation Credential Exposure",
                "impact": (
                    "Potential impact includes exposure of credentials available through environment variables "
                    "or local files if the installation behavior is compromised or executed in an untrusted context."
                ),
                "traceable_chain_ids": [c.id for c in matching_chains],
            })

        if FindingCategory.EXPOSED_SECRET in categories_present:
            sec_findings = [f for f in findings if f.category == FindingCategory.EXPOSED_SECRET]
            potential_impacts.append({
                "risk_type": "Credential Exposure",
                "impact": (
                    "If detected values are valid and accessible to an unauthorized party, they could potentially "
                    "be used to access the associated external service or data repository."
                ),
                "traceable_finding_ids": [f.id for f in sec_findings],
            })

        if (
            FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK in categories_present
            or "DEPENDENCY_REPRODUCIBILITY" in rule_ids_present
            or "INSTALL_REPRODUCIBILITY" in rule_ids_present
        ):
            potential_impacts.append({
                "risk_type": "Reduced Build Reproducibility",
                "impact": (
                    "Potential impact is non-deterministic dependency resolution across installations, which could "
                    "allow unvetted package updates to alter build outputs."
                ),
                "traceable_finding_ids": [
                    f.id for f in findings if f.category == FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK
                ],
            })

        # 4. Remediation Priorities (Actionable, Category-Driven)
        remediation_priorities: List[Dict[str, Any]] = []
        remediation_order: List[str] = []

        if FindingCategory.EXPOSED_SECRET in categories_present:
            sec_ids = [f.id for f in findings if f.category == FindingCategory.EXPOSED_SECRET]
            remediation_priorities.append({
                "priority_level": "Immediate",
                "target": "Exposed Credentials",
                "action": "Rotate any exposed keys, remove hardcoded credentials from source files, and add sensitive files to .gitignore.",
                "traceable_finding_ids": sec_ids,
            })
            remediation_order.append(
                "Rotate any genuine credentials identified in source control and migrate them to secure environment storage."
            )

        if any(c.rule_id in {"INSTALL_REMOTE_EXECUTION", "INSTALL_CREDENTIAL_ACCESS"} for c in risk_chains):
            install_chain_ids = [
                c.id for c in risk_chains if c.rule_id in {"INSTALL_REMOTE_EXECUTION", "INSTALL_CREDENTIAL_ACCESS"}
            ]
            remediation_priorities.append({
                "priority_level": "High",
                "target": "Installation Lifecycle Hooks",
                "action": "Audit or remove automatic lifecycle scripts in package.json that execute network or shell commands.",
                "traceable_chain_ids": install_chain_ids,
            })
            remediation_order.append(
                "Audit package.json lifecycle scripts to ensure installation does not invoke arbitrary shell or download commands."
            )

        if FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK in categories_present:
            dep_ids = [f.id for f in findings if f.category == FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK]
            remediation_priorities.append({
                "priority_level": "Medium",
                "target": "Dependency Reproducibility",
                "action": "Generate and commit a package-lock.json and pin version ranges to ensure deterministic installation.",
                "traceable_finding_ids": dep_ids,
            })
            remediation_order.append(
                "Commit a package-lock.json and constrain dependency versions to guarantee reproducible builds."
            )

        # 5. Executive Summary
        cat_names = [
            CATEGORY_FRIENDLY_NAMES.get(c, c.value)
            for c in sorted(categories_present, key=lambda x: x.value)
        ]
        cats_str = ", ".join(cat_names) if cat_names else "general code structure"

        if ranked_chains:
            top_chain = ranked_chains[0]
            summary = (
                f"The scan identified {len(findings)} security finding(s) across {cats_str}. "
                f"{len(ranked_chains)} correlated risk chain(s) were identified, including "
                f"'{top_chain.title}' (Priority Score: {top_chain.risk_priority_score}/10)."
            )
        else:
            summary = (
                f"The scan identified {len(findings)} security finding(s) across {cats_str}. "
                "No multi-signal risk chains met the correlation threshold."
            )

        # 6. All Traceable Evidence References
        evidence_refs = sorted(list(set(f.id for f in findings)))

        return AIAnalysisResult(
            executive_summary=summary,
            priority_risks=priority_risks,
            remediation_order=remediation_order,
            correlated_risks=correlated_risks,
            potential_impacts=potential_impacts,
            remediation_priorities=remediation_priorities,
            evidence_references=evidence_refs,
            provider_used="deterministic-offline",
        )
