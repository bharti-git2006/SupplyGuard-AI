"""
On-Device / Local Model Reasoning Interface (Architecture Placeholder).
This module defines the integration point for future on-device local models,
such as Qualcomm/Snapdragon NPU accelerated small language models (SLMs),
Ollama, or local OpenAI-compatible inference runtimes.

The architecture ensures that local inference can be connected by simply
implementing the SecurityReasoner protocol without altering the scanner pipeline,
correlation engine, or dashboard presentation.
"""

from typing import List, Optional

from core.ai.base import SecurityReasoner
from core.models import SecurityFinding, RiskChain, AIAnalysisResult, ProjectContext


class LocalLLMReasoner(SecurityReasoner):
    """
    Extensible stub for future on-device model deployment.
    Accepts ONLY structured finding JSON / metadata to preserve data privacy
    and minimize token usage on embedded or edge neural accelerators.
    """

    def __init__(self, endpoint_url: str = "http://localhost:11434"):
        self.endpoint_url = endpoint_url

    def generate_assessment(
        self,
        findings: List[SecurityFinding],
        risk_chains: List[RiskChain],
        project_context: Optional[ProjectContext] = None,
    ) -> AIAnalysisResult:
        raise NotImplementedError(
            "LocalLLMReasoner is an extensible integration stub. "
            "Use DeterministicReasoner for the current offline MVP."
        )
