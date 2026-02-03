"""
Configuration module - All enums and config dataclasses from original w5.py
LEGAL: Authorized security research and testing only
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import base64


# ===================== ENUMERATIONS =====================

class Architecture(Enum):
    """Supported processor architectures"""
    X86_64 = "x64"
    X86_32 = "x86"
    ARM64 = "arm64"
    ARM = "arm"
    MIPS = "mips"
    MIPS64 = "mips64"
    PPC = "ppc"
    PPC64 = "ppc64"
    RISCV64 = "riscv64"
    
    def __str__(self):
        return self.value


class Platform(Enum):
    """Supported operating systems"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    BSD = "bsd"
    SOLARIS = "solaris"
    
    def __str__(self):
        return self.value


class PayloadType(Enum):
    """Enhanced payload types"""
    REVERSE_TCP = "reverse_tcp"
    REVERSE_UDP = "reverse_udp"
    REVERSE_HTTP = "reverse_http"
    REVERSE_HTTPS = "reverse_https"
    REVERSE_DNS = "reverse_dns"
    BIND_TCP = "bind_tcp"
    BIND_UDP = "bind_udp"
    EXECVE = "execve"
    SYSTEM = "system"
    POPEN = "popen"
    CALC = "calc"
    MESSAGEBOX = "messagebox"
    NOTEPAD = "notepad"
    CMD = "cmd"
    POWERSHELL = "powershell"
    WINEXEC = "winexec"
    CREATEPROCESS = "createprocess"
    PROCESS_HOLLOWING = "process_hollowing"
    REFLECTIVE_DLL = "reflective_dll"
    APC_INJECTION = "apc_injection"
    THREAD_HIJACK = "thread_hijack"
    METERPRETER_STAGE0 = "meterpreter_stage0"
    METERPRETER_STAGE1 = "meterpreter_stage1"
    COBALT_STRIKE = "cobalt_strike"
    SLIVER_STAGER = "sliver_stager"
    KEYLOGGER = "keylogger"
    SCREENSHOT = "screenshot"
    PERSISTENCE = "persistence"
    CREDENTIAL_DUMP = "credential_dump"
    TEST = "test"
    SLEEP = "sleep"
    NOP = "nop"
    
    def __str__(self):
        return self.value


class EncoderType(Enum):
    """Enhanced encoder types"""
    XOR = "xor"
    ADD_SUB = "add_sub"
    ROL_ROR = "rol_ror"
    NOT = "not"
    SHIKATA_GA_NAI = "shikata_ga_nai"
    ALPHA_NUMERIC = "alpha_numeric"
    UTF8 = "utf8"
    BASE64 = "base64"
    UUID = "uuid"
    IPV6 = "ipv6"
    AES_CBC = "aes_cbc"
    AES_CTR = "aes_ctr"
    AES_GCM = "aes_gcm"
    RC4 = "rc4"
    CHACHA20 = "chacha20"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    POLYMORPHIC = "polymorphic"
    CUSTOM = "custom"
    
    def __str__(self):
        return self.value


class EvasionLevel(Enum):
    """Enhanced evasion levels"""
    NONE = 0
    BASIC = 1
    MODERATE = 2
    ADVANCED = 3
    EXTREME = 4
    STEALTH = 5
    
    def __str__(self):
        return str(self.value)


class OutputFormat(Enum):
    """Output formats"""
    RAW = "raw"
    C = "c"
    PYTHON = "python"
    POWERSHELL = "powershell"
    CSHARP = "csharp"
    RUST = "rust"
    GOLANG = "golang"
    NIM = "nim"
    VBA = "vba"
    JAVASCRIPT = "javascript"
    HEX = "hex"
    BASE64 = "base64"
    UUENCODE = "uuencode"
    GZIP = "gzip"
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    DEX = "dex"
    SHELLSCRIPT = "shellscript"
    BATCH = "batch"
    
    def __str__(self):
        return self.value


# ===================== CONFIG DATACLASS =====================

@dataclass
class ShellcodeConfig:
    """Enhanced configuration for shellcode generation"""
    architecture: Architecture = Architecture.X86_64
    platform: Platform = Platform.LINUX
    payload_type: PayloadType = PayloadType.REVERSE_TCP
    lhost: Optional[str] = None
    lport: Optional[int] = None
    rhost: Optional[str] = None
    rport: Optional[int] = None
    badchars: List[int] = field(default_factory=list)
    encoder: Optional[EncoderType] = None
    iterations: int = 1
    evasion_level: EvasionLevel = EvasionLevel.BASIC
    output_format: OutputFormat = OutputFormat.RAW
    xor_key: Optional[str] = None
    aes_key: Optional[bytes] = None
    rc4_key: Optional[str] = None
    entropy_target: float = 7.5
    max_size: int = 4096
    staging: bool = False
    staged: bool = False
    stage_size: int = 512
    sleep_time: int = 0
    jitter: int = 0
    retries: int = 3
    timeout: int = 30
    user_agent: Optional[str] = None
    proxy: Optional[str] = None
    anti_debug: bool = True
    anti_vm: bool = True
    anti_sandbox: bool = True
    string_obfuscation: bool = True
    api_hashing: bool = False
    syscall_numbers: bool = False
    obfuscate_imports: bool = False
    randomize_registers: bool = True
    junk_code: bool = True
    nop_sled: bool = False
    nop_sled_size: int = 32
    
    def to_dict(self) -> Dict:
        """Convert to dictionary with JSON serializable values"""
        data = asdict(self)
        data['architecture'] = self.architecture.value
        data['platform'] = self.platform.value
        data['payload_type'] = self.payload_type.value
        data['evasion_level'] = self.evasion_level.value
        data['output_format'] = self.output_format.value
        if self.encoder:
            data['encoder'] = self.encoder.value
        if self.aes_key:
            data['aes_key'] = base64.b64encode(self.aes_key).decode()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ShellcodeConfig':
        """Create from dictionary"""
        if 'architecture' in data:
            data['architecture'] = Architecture(data['architecture'])
        if 'platform' in data:
            data['platform'] = Platform(data['platform'])
        if 'payload_type' in data:
            data['payload_type'] = PayloadType(data['payload_type'])
        if 'evasion_level' in data:
            data['evasion_level'] = EvasionLevel(data['evasion_level'])
        if 'output_format' in data:
            data['output_format'] = OutputFormat(data['output_format'])
        if 'encoder' in data and data['encoder']:
            data['encoder'] = EncoderType(data['encoder'])
        if 'aes_key' in data and data['aes_key']:
            data['aes_key'] = base64.b64decode(data['aes_key'])
        return cls(**data)
