"""
================================================================================
SHELLCODE WEAVER  - Ultimate Polymorphic Shellcode Engine
================================================================================

LEGAL NOTICE:
    This tool is for AUTHORIZED SECURITY RESEARCH AND TESTING ONLY.
    Unauthorized access to computer systems is illegal.
    Users are solely responsible for compliance with all applicable laws.
    
DISCLAIMER:
    - Use only on systems you own or have explicit written permission to test
    - Unauthorized use is a federal crime (Computer Fraud and Abuse Act)
    - The authors assume no responsibility for misuse
    - This is educational/research material for authorized professionals
    
RESPONSIBILITY:
    By using this tool, you acknowledge:
    1. You have explicit authorization to test target systems
    2. You understand and accept all legal consequences
    3. You will comply with all applicable laws and regulations
    4. You will not use this tool for malicious purposes

================================================================================
"""

__version__ = "4.0.0"
__author__ = "Security Research Team"
__license__ = "Educational/Research Use Only - See LICENSE file"

import sys
import warnings

# Legal warning
warnings.warn(
    "SHELLCODE WEAVER : This tool is for AUTHORIZED security testing only. "
    "Unauthorized use is illegal. See LICENSE file for full terms.",
    category=UserWarning,
    stacklevel=2
)

from .config import (
    Architecture, Platform, PayloadType, EncoderType, 
    EvasionLevel, OutputFormat, ShellcodeConfig
)
from .models import GenerationResult, MutationResult
from .utils import EnhancedUtils

__all__ = [
    "__version__",
    "Architecture",
    "Platform", 
    "PayloadType",
    "EncoderType",
    "EvasionLevel",
    "OutputFormat",
    "ShellcodeConfig",
    "GenerationResult",
    "MutationResult",
    "EnhancedUtils",
]
