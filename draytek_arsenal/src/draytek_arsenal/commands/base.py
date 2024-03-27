from abc import ABC, abstractmethod
from typing import Any, Dict, List

class Command(ABC):
    @staticmethod
    @abstractmethod
    def name() -> str:
        ...

    @staticmethod
    @abstractmethod
    def args() -> List[Dict[str, Any]]:
        ...

    @staticmethod
    @abstractmethod
    def description() -> str:
        ...
