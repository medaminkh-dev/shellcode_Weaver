"""
Windows shellcode generator - from original w5.py
LEGAL: Authorized security research and testing only
"""

import struct
from typing import Optional
from . import BaseGenerator
from ..config import Architecture, PayloadType, ShellcodeConfig


class WindowsGenerator(BaseGenerator):
    """Windows shellcode generator (x86/x64)"""
    
    def __init__(self):
        super().__init__()
        self.supported_architectures = [Architecture.X86_64, Architecture.X86_32]
        self.supported_platforms = ["windows"]
    
    def generate(self, config: ShellcodeConfig) -> bytes:
        """Generate Windows shellcode"""
        if config.architecture == Architecture.X86_64:
            return self._generate_x64(config)
        elif config.architecture == Architecture.X86_32:
            return self._generate_x86(config)
        return b''
    
    def _generate_x64(self, config: ShellcodeConfig) -> bytes:
        """Generate x86-64 Windows shellcode"""
        if config.payload_type == PayloadType.CALC:
            return self._x64_calc()
        elif config.payload_type == PayloadType.MESSAGEBOX:
            return self._x64_messagebox()
        elif config.payload_type == PayloadType.CMD:
            return self._x64_cmd()
        elif config.payload_type == PayloadType.REVERSE_TCP:
            return self._x64_reverse_tcp(config.lhost, config.lport)
        elif config.payload_type == PayloadType.TEST:
            return self._x64_test()
        return b''
    
    def _generate_x86(self, config: ShellcodeConfig) -> bytes:
        """Generate x86 Windows shellcode"""
        if config.payload_type == PayloadType.CALC:
            return self._x86_calc()
        elif config.payload_type == PayloadType.MESSAGEBOX:
            return self._x86_messagebox()
        elif config.payload_type == PayloadType.CMD:
            return self._x86_cmd()
        elif config.payload_type == PayloadType.REVERSE_TCP:
            return self._x86_reverse_tcp(config.lhost, config.lport)
        elif config.payload_type == PayloadType.TEST:
            return self._x86_test()
        return b''
    
    def _x64_calc(self) -> bytes:
        """Windows x64 calc.exe shellcode stub"""
        shellcode = bytearray([0x90] * 100)
        return bytes(shellcode)
    
    def _x64_messagebox(self) -> bytes:
        """Windows x64 MessageBox shellcode stub"""
        shellcode = bytearray([0x90] * 120)
        return bytes(shellcode)
    
    def _x64_cmd(self) -> bytes:
        """Windows x64 cmd.exe shellcode stub"""
        shellcode = bytearray([0x90] * 110)
        return bytes(shellcode)
    
    def _x64_test(self) -> bytes:
        """x64 NOP sled test"""
        return b'\x90' * 32
    
    def _x86_calc(self) -> bytes:
        """Windows x86 calc.exe shellcode stub"""
        shellcode = bytearray([0x90] * 80)
        return bytes(shellcode)
    
    def _x86_messagebox(self) -> bytes:
        """Windows x86 MessageBox shellcode stub"""
        shellcode = bytearray([0x90] * 100)
        return bytes(shellcode)
    
    def _x86_cmd(self) -> bytes:
        """Windows x86 cmd.exe shellcode stub"""
        shellcode = bytearray([0x90] * 90)
        return bytes(shellcode)
    
    def _x86_test(self) -> bytes:
        """x86 NOP sled test"""
        return b'\x90' * 16
    
    def _x64_reverse_tcp(self, lhost: Optional[str], lport: Optional[int]) -> bytes:
        """x64 reverse TCP shell stub"""
        shellcode = bytearray([0x90] * 150)
        return bytes(shellcode)
    
    def _x86_reverse_tcp(self, lhost: Optional[str], lport: Optional[int]) -> bytes:
        """x86 reverse TCP shell stub"""
        shellcode = bytearray([0x90] * 120)
        return bytes(shellcode)
