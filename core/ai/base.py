"""
Abstract Base Interface for SupplyGuard AI Reasoning Layer.
Pluggable contract allowing the deterministic heuristic reasoner to be swapped
with local on-device inference (e.g., Qualcomm/Snapdragon NPU or local endpoints)
without changing scanners, correlation logic, or data models.
Operates exclusively on structured security findings — never raw source code.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from core.models import SecurityFinding, RiskChain, AIAnalysisResult, ProjectContext


class SecurityReasoner(ABC):
    """
    Pluggable reasoning interface for synthesizing security explanations
    from structured findings and correlated risk chains.
    """

    @abstractmethod
    def generate_assessment(
        self,
        findings: List[SecurityFinding],
        risk_chains: List[RiskChain],
        project_context: Optional[ProjectContext] = None,
    ) -> AIAnalysisResult:
        """
        Generates a structured, evidence-grounded security assessment.
        Input is strictly structured findings and chains; no raw source code is passed.
        """
        pass
