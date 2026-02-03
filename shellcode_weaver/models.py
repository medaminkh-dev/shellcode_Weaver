"""
Result models - GenerationResult and MutationResult from original w5.py
LEGAL: Authorized security research and testing only
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, List
import base64
from .config import ShellcodeConfig


@dataclass
class GenerationResult:
    """Result of shellcode generation"""
    success: bool
    shellcode: bytes
    config: ShellcodeConfig
    metadata: Dict[str, Any]
    statistics: Dict[str, Any]
    warnings: List[str]
    errors: List[str]
    
    def to_dict(self) -> Dict:
        """Convert to JSON serializable dictionary"""
        data = asdict(self)
        data['shellcode'] = base64.b64encode(self.shellcode).decode()
        data['config'] = self.config.to_dict()
        return data


@dataclass
class MutationResult:
    """Enhanced mutation result"""
    original_size: int
    mutated_size: int
    techniques_applied: List[str]
    detection_score: float
    entropy: float
    entropy_delta: float
    hash_md5: str
    hash_sha256: str
    hash_sha3_512: str
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        """Convert to JSON serializable dictionary"""
        return asdict(self)
