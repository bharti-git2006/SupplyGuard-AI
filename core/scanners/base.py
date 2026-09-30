"""
Base scanner interface for SupplyGuard AI.
Standardizes scanner execution using pure Python standard library.
"""

from abc import ABC, abstractmethod
from typing import List
from core.models import ProjectContext, SecurityFinding


class BaseScanner(ABC):
    """Abstract base class for all SupplyGuard AI local static scanners."""

    @abstractmethod
    def scan(self, context: ProjectContext) -> List[SecurityFinding]:
        """
        Executes scanner against project files in context.
        Must return a list of standardized SecurityFinding objects.
        """
        pass
