"""
Unit tests for Shellcode Weaver package
LEGAL: Authorized security research and testing only
"""

import unittest
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shellcode_weaver.config import (
    Architecture, Platform, PayloadType, EncoderType,
    EvasionLevel, OutputFormat, ShellcodeConfig
)
from shellcode_weaver.models import GenerationResult, MutationResult
from shellcode_weaver.utils import EnhancedUtils
from shellcode_weaver.generators.linux import LinuxGenerator
from shellcode_weaver.generators.windows import WindowsGenerator
from shellcode_weaver.polymorphic import PolymorphicEngine
from shellcode_weaver.analysis import ShellcodeAnalyzer
from shellcode_weaver.crypto import CryptoEngine


class TestEnums(unittest.TestCase):
    """Test enum classes"""
    
    def test_architecture_values(self):
        self.assertEqual(str(Architecture.X86_64), "x64")
        self.assertEqual(str(Architecture.X86_32), "x86")
        self.assertEqual(str(Architecture.ARM64), "arm64")
    
    def test_platform_values(self):
        self.assertEqual(str(Platform.LINUX), "linux")
        self.assertEqual(str(Platform.WINDOWS), "windows")
        self.assertEqual(str(Platform.MACOS), "macos")
    
    def test_payload_type_values(self):
        self.assertEqual(str(PayloadType.EXECVE), "execve")
        self.assertEqual(str(PayloadType.REVERSE_TCP), "reverse_tcp")
        self.assertEqual(str(PayloadType.BIND_TCP), "bind_tcp")


class TestConfig(unittest.TestCase):
    """Test ShellcodeConfig"""
    
    def test_config_creation(self):
        config = ShellcodeConfig()
        self.assertEqual(config.architecture, Architecture.X86_64)
        self.assertEqual(config.platform, Platform.LINUX)
        self.assertEqual(config.payload_type, PayloadType.REVERSE_TCP)
    
    def test_config_to_dict(self):
        config = ShellcodeConfig(lhost="127.0.0.1", lport=4444)
        d = config.to_dict()
        self.assertEqual(d['lhost'], "127.0.0.1")
        self.assertEqual(d['lport'], 4444)
        self.assertEqual(d['architecture'], "x64")
    
    def test_config_from_dict(self):
        original = ShellcodeConfig(lhost="127.0.0.1", lport=8888)
        d = original.to_dict()
        restored = ShellcodeConfig.from_dict(d)
        self.assertEqual(restored.lhost, "127.0.0.1")
        self.assertEqual(restored.lport, 8888)


class TestUtils(unittest.TestCase):
    """Test utility functions"""
    
    def test_entropy_calculation(self):
        utils = EnhancedUtils()
        # High entropy for random data
        random_data = os.urandom(256)
        entropy = utils.calculate_entropy(random_data)
        self.assertGreater(entropy, 7.0)
        
        # Low entropy for repetitive data
        repetitive_data = b'\x00' * 256
        entropy = utils.calculate_entropy(repetitive_data)
        self.assertEqual(entropy, 0.0)
    
    def test_hash_functions(self):
        utils = EnhancedUtils()
        data = b"test data"
        
        md5 = utils.hash_md5(data)
        self.assertEqual(len(md5), 32)  # MD5 hex is 32 chars
        
        sha256 = utils.hash_sha256(data)
        self.assertEqual(len(sha256), 64)  # SHA256 hex is 64 chars
    
    def test_xor_encode(self):
        utils = EnhancedUtils()
        plaintext = b"HELLO"
        key = b"\x42"
        ciphertext = utils.xor_encode(plaintext, key)
        decrypted = utils.xor_encode(ciphertext, key)
        self.assertEqual(decrypted, plaintext)


class TestGenerators(unittest.TestCase):
    """Test shellcode generators"""
    
    def test_linux_generator_x64(self):
        gen = LinuxGenerator()
        config = ShellcodeConfig(
            platform=Platform.LINUX,
            architecture=Architecture.X86_64,
            payload_type=PayloadType.TEST
        )
        shellcode = gen.generate(config)
        self.assertIsInstance(shellcode, bytes)
        self.assertGreater(len(shellcode), 0)
    
    def test_linux_generator_x86(self):
        gen = LinuxGenerator()
        config = ShellcodeConfig(
            platform=Platform.LINUX,
            architecture=Architecture.X86_32,
            payload_type=PayloadType.TEST
        )
        shellcode = gen.generate(config)
        self.assertIsInstance(shellcode, bytes)
        self.assertGreater(len(shellcode), 0)
    
    def test_windows_generator_x64(self):
        gen = WindowsGenerator()
        config = ShellcodeConfig(
            platform=Platform.WINDOWS,
            architecture=Architecture.X86_64,
            payload_type=PayloadType.CALC
        )
        shellcode = gen.generate(config)
        self.assertIsInstance(shellcode, bytes)
        self.assertGreater(len(shellcode), 0)


class TestPolymorphic(unittest.TestCase):
    """Test polymorphic mutations"""
    
    def test_mutation_junk_code(self):
        engine = PolymorphicEngine(seed=42)
        original = b'\x90' * 32
        config = ShellcodeConfig(junk_code=True)
        result = engine.mutate(original, config)
        
        self.assertGreater(result.mutated_size, result.original_size)
        self.assertIn('junk_code_insertion', result.techniques_applied)
    
    def test_mutation_nop_sled(self):
        engine = PolymorphicEngine(seed=42)
        original = b'\x90' * 16
        config = ShellcodeConfig(nop_sled=True, nop_sled_size=32)
        result = engine.mutate(original, config)
        
        self.assertEqual(result.original_size, 16)
        self.assertGreaterEqual(result.mutated_size, 48)  # At least 32 NOPs + 16 original
    
    def test_xor_encoding(self):
        engine = PolymorphicEngine(seed=42)
        original = b"test"
        config = ShellcodeConfig(encoder=EncoderType.XOR)
        result = engine.mutate(original, config)
        
        self.assertIn('encoder_xor', result.techniques_applied)


class TestAnalysis(unittest.TestCase):
    """Test shellcode analysis"""
    
    def test_analyze_simple_shellcode(self):
        analyzer = ShellcodeAnalyzer()
        shellcode = b'\x90' * 64
        analysis = analyzer.analyze(shellcode)
        
        self.assertEqual(analysis['size'], 64)
        self.assertEqual(analysis['nop_count'], 64)
        self.assertEqual(analysis['entropy'], 0.0)
    
    def test_detect_signatures(self):
        analyzer = ShellcodeAnalyzer()
        shellcode = b'\x48\x31\xc0' + b'\x90' * 32  # x64 xor rax
        signatures = analyzer.detect_signatures(shellcode)
        
        self.assertIn('x64_xor_rax', signatures)


class TestCrypto(unittest.TestCase):
    """Test cryptographic operations"""
    
    def test_rc4_roundtrip(self):
        engine = CryptoEngine()
        plaintext = b"Hello World"
        key = b"secret"
        
        ciphertext = engine.rc4_encrypt(plaintext, key)
        decrypted = engine.rc4_decrypt(ciphertext, key)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_xor_roundtrip(self):
        engine = CryptoEngine()
        plaintext = b"test data"
        key = b"key"
        
        ciphertext = engine.xor_encrypt(plaintext, key)
        decrypted = engine.xor_decrypt(ciphertext, key)
        
        self.assertEqual(decrypted, plaintext)


class TestResults(unittest.TestCase):
    """Test result dataclasses"""
    
    def test_generation_result_to_dict(self):
        config = ShellcodeConfig()
        result = GenerationResult(
            success=True,
            shellcode=b'\x90\x90',
            config=config,
            metadata={},
            statistics={'size': 2},
            warnings=[],
            errors=[]
        )
        d = result.to_dict()
        self.assertIn('shellcode', d)
        self.assertTrue(result.success)
    
    def test_mutation_result_to_dict(self):
        result = MutationResult(
            original_size=32,
            mutated_size=48,
            techniques_applied=['nop_insertion'],
            detection_score=0.0,
            entropy=7.5,
            entropy_delta=0.2,
            hash_md5="abc123",
            hash_sha256="def456",
            hash_sha3_512="ghi789",
            metadata={}
        )
        d = result.to_dict()
        self.assertEqual(d['original_size'], 32)
        self.assertEqual(d['mutated_size'], 48)


if __name__ == '__main__':
    unittest.main()
