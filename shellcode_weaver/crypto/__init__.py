"""
Cryptographic engine - from original w5.py
LEGAL: Authorized security research and testing only
"""

import os
from typing import Optional, Dict, Any

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class CryptoEngine:
    """Cryptographic operations engine"""
    
    def __init__(self):
        self.has_crypto = HAS_CRYPTO
    
    def xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption"""
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
    
    def xor_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR decryption (same as encryption)"""
        return self.xor_encrypt(data, key)
    
    def rc4_ksa(self, key: bytes) -> list:
        """RC4 Key Scheduling Algorithm"""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S
    
    def rc4_prga(self, S: list, length: int) -> bytes:
        """RC4 Pseudo-Random Generation Algorithm"""
        i = j = 0
        result = bytearray()
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            result.append(K)
        return bytes(result)
    
    def rc4_encrypt(self, data: bytes, key: bytes) -> bytes:
        """RC4 encryption"""
        S = self.rc4_ksa(key)
        return bytes(a ^ b for a, b in zip(data, self.rc4_prga(S, len(data))))
    
    def rc4_decrypt(self, data: bytes, key: bytes) -> bytes:
        """RC4 decryption (same as encryption)"""
        return self.rc4_encrypt(data, key)
    
    def aes_encrypt(self, plaintext: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
        """AES-128-CBC encryption"""
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library not available")
        
        if iv is None:
            iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
        encryptor = cipher.encryptor()
        # Add PKCS7 padding
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return iv + ciphertext
    
    def aes_decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """AES-128-CBC decryption"""
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library not available")
        
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        # Remove PKCS7 padding
        pad_len = plaintext[-1]
        return plaintext[:-pad_len]
    
    def chacha20_encrypt(self, plaintext: bytes, key: bytes, nonce: Optional[bytes] = None) -> bytes:
        """ChaCha20 encryption"""
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library not available")
        
        if nonce is None:
            nonce = os.urandom(12)
        
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def chacha20_decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """ChaCha20 decryption"""
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library not available")
        
        nonce = ciphertext[:12]
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ciphertext[12:], None)
        return plaintext
