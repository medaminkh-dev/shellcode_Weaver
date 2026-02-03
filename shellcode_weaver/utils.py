"""
Utility functions extracted from original w5.py
LEGAL: Authorized security research and testing only
"""

import hashlib
import math
import random
import json
from typing import Dict, Any, Optional
from datetime import datetime


class EnhancedUtils:
    """Enhanced utility functions"""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of shellcode"""
        if len(data) == 0:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def hash_md5(data: bytes) -> str:
        """Compute MD5 hash"""
        return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def hash_sha256(data: bytes) -> str:
        """Compute SHA256 hash"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def hash_sha3_512(data: bytes) -> str:
        """Compute SHA3-512 hash"""
        return hashlib.sha3_512(data).hexdigest()
    
    @staticmethod
    def generate_key(size: int) -> bytes:
        """Generate random key of specified size"""
        return bytes(random.randint(0, 255) for _ in range(size))
    
    @staticmethod
    def get_timestamp() -> str:
        """Get current timestamp"""
        return datetime.now().isoformat()
    
    @staticmethod
    def safe_serialize(obj: Any) -> Dict:
        """Convert dataclass-like objects to JSON-serializable dicts"""
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return {'value': str(obj)}
    
    @staticmethod
    def write_json_file(path: str, data: Dict) -> None:
        """Write JSON data to file"""
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def read_json_file(path: str) -> Dict:
        """Read JSON data from file"""
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    @staticmethod
    def xor_encode(data: bytes, key: bytes) -> bytes:
        """XOR encode data with key"""
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
    
    @staticmethod
    def add_sub_encode(data: bytes) -> bytes:
        """ADD/SUB encoding"""
        encoded = bytearray()
        for byte in data:
            encoded.append((byte + 0x42) & 0xFF)
        return bytes(encoded)
    
    @staticmethod
    def rol_ror_encode(data: bytes) -> bytes:
        """ROL/ROR encoding"""
        encoded = bytearray()
        for byte in data:
            encoded.append(((byte << 1) | (byte >> 7)) & 0xFF)
        return bytes(encoded)
