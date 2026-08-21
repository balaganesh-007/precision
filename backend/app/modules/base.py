from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseModule(ABC):
    """Abstract base class for all model security scanner analysis modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the module (e.g., 'weight_engine')."""
        pass

    @abstractmethod
    def scan(self, filepath: str, format: str) -> List[Dict[str, Any]]:
        """
        Execute static, read-only analysis on a model file.
        Returns a list of finding dictionaries.
        """
        pass
