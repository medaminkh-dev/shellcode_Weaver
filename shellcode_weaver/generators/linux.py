"""
Linux shellcode generator - from original w5.py
LEGAL: Authorized security research and testing only
"""

import struct
import socket
from typing import Optional
from . import BaseGenerator
from ..config import Architecture, PayloadType, ShellcodeConfig


class LinuxGenerator(BaseGenerator):
    """Linux shellcode generator (x86/x64)"""
    
    def __init__(self):
        super().__init__()
        self.supported_architectures = [Architecture.X86_64, Architecture.X86_32]
        self.supported_platforms = ["linux"]
    
    def generate(self, config: ShellcodeConfig) -> bytes:
        """Generate Linux shellcode"""
        if config.architecture == Architecture.X86_64:
            return self._generate_x64(config)
        elif config.architecture == Architecture.X86_32:
            return self._generate_x86(config)
        return b''
    
    def _generate_x64(self, config: ShellcodeConfig) -> bytes:
        """Generate x86-64 Linux shellcode"""
        if config.payload_type == PayloadType.EXECVE:
            return self._x64_execve()
        elif config.payload_type == PayloadType.REVERSE_TCP:
            return self._x64_reverse_tcp(config.lhost, config.lport)
        elif config.payload_type == PayloadType.BIND_TCP:
            return self._x64_bind_tcp(config.lport)
        elif config.payload_type == PayloadType.TEST:
            return self._x64_test()
        return b''
    
    def _generate_x86(self, config: ShellcodeConfig) -> bytes:
        """Generate x86 Linux shellcode"""
        if config.payload_type == PayloadType.EXECVE:
            return self._x86_execve()
        elif config.payload_type == PayloadType.REVERSE_TCP:
            return self._x86_reverse_tcp(config.lhost, config.lport)
        elif config.payload_type == PayloadType.BIND_TCP:
            return self._x86_bind_tcp(config.lport)
        elif config.payload_type == PayloadType.TEST:
            return self._x86_test()
        return b''
    
    def _x64_execve(self) -> bytes:
        """x86-64 /bin/sh shellcode"""
        shellcode = bytearray([
            0x48, 0x31, 0xc0,  # xor rax, rax
            0x48, 0x31, 0xff,  # xor rdi, rdi
            0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,  # mov rdi, 1
            0xb8, 0x3c, 0x00, 0x00, 0x00,  # mov eax, 60
            0x0f, 0x05,  # syscall
        ])
        return bytes(shellcode)
    
    def _x64_test(self) -> bytes:
        """x86-64 NOP sled test"""
        return b'\x90' * 32
    
    def _x86_execve(self) -> bytes:
        """x86 /bin/sh shellcode"""
        shellcode = bytearray([
            0x31, 0xc0,  # xor eax, eax
            0x31, 0xdb,  # xor ebx, ebx
            0xb0, 0x0b,  # mov al, 11
            0xcd, 0x80,  # int 0x80
        ])
        return bytes(shellcode)
    
    def _x86_test(self) -> bytes:
        """x86 NOP sled test"""
        return b'\x90' * 16
    
    def _x64_reverse_tcp(self, lhost: Optional[str], lport: Optional[int]) -> bytes:
        """x86-64 reverse TCP shell (stub)"""
        shellcode = bytearray([0x90] * 128)
        return bytes(shellcode)
    
    def _x86_reverse_tcp(self, lhost: Optional[str], lport: Optional[int]) -> bytes:
        """x86 reverse TCP shell (stub)"""
        shellcode = bytearray([0x90] * 64)
        return bytes(shellcode)
    
    def _x64_bind_tcp(self, lport: Optional[int]) -> bytes:
        """x86-64 bind TCP shell (stub)"""
        shellcode = bytearray([0x90] * 128)
        return bytes(shellcode)
    
    def _x86_bind_tcp(self, lport: Optional[int]) -> bytes:
        """x86 bind TCP shell (stub)"""
        shellcode = bytearray([0x90] * 64)
        return bytes(shellcode)
