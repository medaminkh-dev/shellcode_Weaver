"""
Polymorphic mutation engine - from original w5.py
LEGAL: Authorized security research and testing only
"""

import random
from typing import Dict, List, Optional, Callable
from ..config import ShellcodeConfig, EncoderType
from ..models import MutationResult
from ..utils import EnhancedUtils


class PolymorphicEngine:
    """Polymorphic mutation and encoding engine"""
    
    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.utils = EnhancedUtils()
    
    def mutate(self, shellcode: bytes, config: ShellcodeConfig) -> MutationResult:
        """Apply polymorphic mutations"""
        original = shellcode
        techniques_applied = []
        mutated = shellcode
        
        # Apply junk code insertion
        if config.junk_code:
            mutated = self._insert_junk_code(mutated)
            techniques_applied.append('junk_code_insertion')
        
        # Apply NOP sled
        if config.nop_sled:
            mutated = self._insert_nop_sled(mutated, config.nop_sled_size)
            techniques_applied.append('nop_insertion')
        
        # Apply encoding
        if config.encoder:
            mutated = self._apply_encoder(mutated, config.encoder)
            techniques_applied.append(f'encoder_{config.encoder.value}')
        
        # Calculate statistics
        entropy = self.utils.calculate_entropy(mutated)
        orig_entropy = self.utils.calculate_entropy(original)
        
        return MutationResult(
            original_size=len(original),
            mutated_size=len(mutated),
            techniques_applied=techniques_applied,
            detection_score=0.0,
            entropy=entropy,
            entropy_delta=entropy - orig_entropy,
            hash_md5=self.utils.hash_md5(mutated),
            hash_sha256=self.utils.hash_sha256(mutated),
            hash_sha3_512=self.utils.hash_sha3_512(mutated),
            metadata={}
        )
    
    def _insert_junk_code(self, shellcode: bytes) -> bytes:
        """Insert junk code/NOP padding"""
        result = bytearray(shellcode)
        junk_size = self.rng.randint(4, 16)
        junk = bytes([0x90] * junk_size)
        
        # Insert at random position
        insert_pos = self.rng.randint(0, len(result))
        result = result[:insert_pos] + junk + result[insert_pos:]
        return bytes(result)
    
    def _insert_nop_sled(self, shellcode: bytes, sled_size: int) -> bytes:
        """Insert NOP sled before shellcode"""
        nop_sled = bytes([0x90] * sled_size)
        return nop_sled + shellcode
    
    def _apply_encoder(self, shellcode: bytes, encoder_type: EncoderType) -> bytes:
        """Apply specified encoding"""
        if encoder_type == EncoderType.XOR:
            key = self.utils.generate_key(self.rng.randint(1, 8))
            return self.utils.xor_encode(shellcode, key)
        elif encoder_type == EncoderType.ADD_SUB:
            return self.utils.add_sub_encode(shellcode)
        elif encoder_type == EncoderType.ROL_ROR:
            return self.utils.rol_ror_encode(shellcode)
        elif encoder_type == EncoderType.BASE64:
            import base64
            return base64.b64encode(shellcode)
        else:
            return shellcode
