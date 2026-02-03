"""
Base generator class - foundation for all shellcode generators
LEGAL: Authorized security research and testing only
"""

from abc import ABC, abstractmethod
from ..config import ShellcodeConfig
from ..models import GenerationResult


class BaseGenerator(ABC):
    """Abstract base class for shellcode generators"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.supported_architectures = []
        self.supported_platforms = []
        self.supported_payloads = []
    
    @abstractmethod
    def generate(self, config: ShellcodeConfig) -> bytes:
        """Generate shellcode based on configuration"""
        pass
    
    def create_result(self, shellcode: bytes, config: ShellcodeConfig, 
                     success: bool = True, warnings: list = None,
                     errors: list = None) -> GenerationResult:
        """Create a GenerationResult object"""
        return GenerationResult(
            success=success,
            shellcode=shellcode,
            config=config,
            metadata={'generator': self.name},
            statistics={'size': len(shellcode)},
            warnings=warnings or [],
            errors=errors or []
        )
