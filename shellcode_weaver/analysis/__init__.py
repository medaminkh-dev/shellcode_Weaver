"""
Shellcode analysis tools - from original w5.py
LEGAL: Authorized security research and testing only
"""

from ..utils import EnhancedUtils
from ..models import MutationResult


class ShellcodeAnalyzer:
    """Analyze shellcode characteristics"""
    
    def __init__(self):
        self.utils = EnhancedUtils()
    
    def analyze(self, shellcode: bytes) -> dict:
        """Perform comprehensive analysis"""
        return {
            'size': len(shellcode),
            'entropy': self.utils.calculate_entropy(shellcode),
            'hash_md5': self.utils.hash_md5(shellcode),
            'hash_sha256': self.utils.hash_sha256(shellcode),
            'hash_sha3_512': self.utils.hash_sha3_512(shellcode),
            'null_bytes': shellcode.count(b'\x00'),
            'nop_count': shellcode.count(b'\x90'),
        }
    
    def detect_signatures(self, shellcode: bytes) -> list:
        """Detect common shellcode signatures"""
        signatures = []
        
        if b'\x48\x31\xc0' in shellcode:
            signatures.append('x64_xor_rax')
        if b'\x31\xc0' in shellcode:
            signatures.append('x86_xor_eax')
        if b'\x0f\x05' in shellcode:
            signatures.append('x64_syscall')
        if b'\xcd\x80' in shellcode:
            signatures.append('x86_int80')
        
        return signatures
