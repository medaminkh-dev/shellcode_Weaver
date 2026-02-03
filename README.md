# 🎯 Shellcode Weaver v4.0 - Complete Learning Guide

Welcome! This is a **professional security research tool** for learning about shellcode generation, mutation, and analysis. Think of it as a **toolkit for understanding how security professionals test systems** they're authorized to work on.

---

## ⚠️ IMPORTANT LEGAL & SAFETY NOTICE

**PLEASE READ THIS FIRST!**

This tool is designed for **authorized security research ONLY**. Think of it like a lockpick set:
- ✅ **LEGAL**: Used by locksmiths on locks they own or are hired to work on
- ❌ **ILLEGAL**: Used to break into someone else's property

### Your Legal Responsibilities:

1. **You MUST have written permission** from the system owner before using this tool
2. **Unauthorized access is a federal crime** - Up to 10 years in prison + $250,000 fine
3. **You are completely responsible** for how you use this tool
4. **We (the authors) are NOT responsible** if you misuse this tool

### Before You Use This:
- ✅ Get written permission from the system owner
- ✅ Make sure you understand the laws in your area
- ✅ Know that your actions can be traced/logged
- ✅ Understand the consequences if something goes wrong

**If you're not 100% sure you have permission - DON'T USE THIS TOOL!**

---

## 🎓 What is Shellcode Weaver?

Think of this tool like a **learning lab for security professionals**. It helps you understand:

- 📚 **How shellcode works** - The low-level code that runs on computers
- 🔍 **How to test systems** - With permission, of course!
- 🛡️ **How to defend systems** - By understanding attack techniques
- 🧪 **How mutations work** - Making code look different each time

### Real-World Example:
Imagine you're a security company hired to test a bank's security:
- You need to understand how attackers might try to break in
- You create test code (shellcode) to verify security defenses work
- You analyze if your code would be detected by security systems
- You report your findings so the bank can improve their security

That's what this tool does!

---

## 📦 What's Inside?

### Components (Like a Toolbox):

**🔧 Core Tools:**
- Config System - Settings for what you want to generate
- Generators - Creates shellcode for different systems (Linux, Windows)
- Mutations - Changes code to look different
- Encryption - Scrambles your code so it's harder to detect
- Analysis - Examines code to show characteristics

**🎯 Access Methods:**
- CLI (Command Line) - Use from terminal
- Python API - Use in your Python programs
- Tests - 21 tests to verify everything works

---

## 🚀 Getting Started

### Installation

```bash
# Download the project
cd /home/kali/Desktop/project_arsenal

# Option 1: Direct usage (no install needed)
python3 -m shellcode_weaver.cli --help

# Option 2: Install as a package
pip install -e .

# Option 3: Install with extra features
pip install -e .[full,dev]
```

### Check It Works
```bash
# Quick test
python3 -m shellcode_weaver.cli --version
# Output: Shellcode Weaver v4.0.0
```

---

## 📖 Learning the Commands

### 1️⃣ GENERATE Command - Create Shellcode

**What it does:** Creates shellcode (low-level code) for different systems and architectures.

**When to use:** When you need test code for security research.

**Why use it:** To understand how different systems handle code execution.

**Basic syntax:**
```bash
python3 -m shellcode_weaver.cli generate --platform PLATFORM --arch ARCH --payload PAYLOAD
```

**Supported Platforms:**
- `linux` - Linux operating system
- `windows` - Windows operating system
- `macos` - Apple macOS

**Supported Architectures:**
- `x64` - 64-bit processors (modern computers)
- `x86` - 32-bit processors (older systems)
- `arm64` - Apple M1/M2 chips
- `arm` - 32-bit ARM processors
- `mips`, `mips64`, `ppc`, `ppc64`, `riscv64` - Other architectures

**Available Payloads:**
- `execve` - Execute a shell command (Linux)
- `test` - Simple test payload (NOP sled)
- `calc` - Launch calculator app (Windows)
- `messagebox` - Show message box (Windows)
- `cmd` - Open command prompt (Windows)
- `reverse_tcp` - Connect back to attacker (network testing)
- `bind_tcp` - Listen for connection (network testing)

### Example 1: Generate Basic Linux Shellcode
```bash
python3 -m shellcode_weaver.cli generate \
  --platform linux \
  --arch x64 \
  --payload execve \
  --format hex

# Output: 4831c04831ff48c7c701000000b83c0000000f05
# What it is: x86-64 assembly code that executes /bin/sh
```

**Why this is useful:**
- Understand how Linux system calls work
- See raw machine code up close
- Test security tools on real shellcode

### Example 2: Generate Windows Shellcode
```bash
python3 -m shellcode_weaver.cli generate \
  --platform windows \
  --arch x64 \
  --payload calc

# Output: 9090909090... (binary code)
# What it is: Code that would launch calc.exe on Windows
```

**Output Formats:**

Change how the shellcode is displayed with `--format`:

```bash
# Format 1: HEX - Raw hexadecimal
python3 -m shellcode_weaver.cli generate --platform linux --arch x64 --payload test --format hex
# Output: 90909090909090909090909090909090

# Format 2: PYTHON - Valid Python code
python3 -m shellcode_weaver.cli generate --platform linux --arch x64 --payload test --format python
# Output: shellcode = b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'

# Format 3: C - Valid C code
python3 -m shellcode_weaver.cli generate --platform linux --arch x64 --payload test --format c
# Output: unsigned char shellcode[] = "\x90\x90\x90\x90...";

# Format 4: BASE64 - Encoded format
python3 -m shellcode_weaver.cli generate --platform linux --arch x64 --payload test --format base64
# Output: kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkA==
```

**When to use each format:**
- **Hex**: When you want to see the raw bytes
- **Python**: When you're writing Python exploit code
- **C**: When you're writing C/C++ exploit code
- **Base64**: When you need to hide binary data in text
- **Raw**: When you need the actual binary file

### Example 3: Save to a File
```bash
# Save as binary file
python3 -m shellcode_weaver.cli generate \
  --platform linux \
  --arch x64 \
  --payload execve \
  --output /tmp/my_shellcode.bin

# The file is now ready to use in further testing
ls -la /tmp/my_shellcode.bin
# Output: -rw-rw-r-- 1 user user 20 Feb 3 12:00 /tmp/my_shellcode.bin
```

---

### 2️⃣ ANALYZE Command - Study Shellcode

**What it does:** Examines shellcode and shows you detailed information about it.

**When to use:** When you want to understand shellcode characteristics before using it.

**Why use it:** To see how detectable the code is, what signatures it has, etc.

**Basic syntax:**
```bash
python3 -m shellcode_weaver.cli analyze --input FILENAME
```

### Example: Analyze Shellcode
```bash
python3 -m shellcode_weaver.cli analyze --input /tmp/my_shellcode.bin

# Output (JSON format):
{
  "size": 20,                    # How many bytes
  "entropy": 3.11,               # How random (0=all same, 8=very random)
  "hash_md5": "fff1b12afd...",   # Fingerprint #1
  "hash_sha256": "cdac185b5...",  # Fingerprint #2
  "hash_sha3_512": "ffaa88ed...", # Fingerprint #3
  "null_bytes": 6,               # How many zero bytes (0x00)
  "nop_count": 0,                # How many NOP instructions
  "signatures": [
    "x64_xor_rax",               # Assembly pattern detected
    "x64_syscall"                # System call detected
  ]
}
```

**What each field means:**

| Field | What It Means | Why It Matters |
|-------|---------------|----------------|
| **size** | Shellcode length in bytes | Larger code might be easier to detect |
| **entropy** | How random the code is (0-8) | Higher = looks more random = harder to detect |
| **hash_md5/256/512** | Unique fingerprint | Security software uses these to identify code |
| **null_bytes** | How many 0x00 bytes | Can break some vulnerabilities that stop at nulls |
| **nop_count** | How many NOPs (do-nothing instructions) | Padding used to hide real code |
| **signatures** | Patterns detected | What assembly code was recognized |

**Real-world use:**
- Security researchers check if their test code would be flagged
- Defensive teams see what patterns to look for
- Students learn how code is analyzed

---

### 3️⃣ MUTATE Command - Change Shellcode

**What it does:** Modifies shellcode to make it look different.

**When to use:** When you want to test if security tools detect variations of the same code.

**Why use it:** Security systems often recognize patterns. Mutations help test robustness.

**Real-world analogy:** Like changing the colors of a car - it's still the same car, but looks different.

**Basic syntax:**
```bash
python3 -m shellcode_weaver.cli mutate --input FILENAME [options]
```

### Mutation Techniques:

**1. Junk Code (`--junk-code`)**
```bash
python3 -m shellcode_weaver.cli mutate \
  --input /tmp/my_shellcode.bin \
  --junk-code

# What it does: Adds useless code between real code
# Result: 
#   Original: 20 bytes
#   Mutated: 34 bytes (14 bytes of junk added)
# Why: Makes code harder to analyze
```

**2. NOP Sled (`--nop-sled SIZE`)**
```bash
python3 -m shellcode_weaver.cli mutate \
  --input /tmp/my_shellcode.bin \
  --nop-sled 64

# What it does: Adds a "sled" of NOP instructions before real code
# Result:
#   Original: 20 bytes
#   Mutated: 84 bytes (64 bytes of NOPs added)
# Why: NOPs are harmless but pad the code to throw off analysis
#      Like spray-painting a car to hide its real color
```

**3. XOR Encoding (`--encoder xor`)**
```bash
python3 -m shellcode_weaver.cli mutate \
  --input /tmp/my_shellcode.bin \
  --encoder xor

# What it does: Scrambles the code with XOR operation
# Result: Code that looks completely different but works the same
# Why: Security scanners looking for specific bytes won't find it
```

**4. Other Encoders**
```bash
# ADD/SUB encoding
python3 -m shellcode_weaver.cli mutate --input /tmp/my_shellcode.bin --encoder add_sub

# ROL/ROR encoding (bit rotation)
python3 -m shellcode_weaver.cli mutate --input /tmp/my_shellcode.bin --encoder rol_ror

# Base64 encoding
python3 -m shellcode_weaver.cli mutate --input /tmp/my_shellcode.bin --encoder base64
```

### Example: Combine Multiple Mutations
```bash
python3 -m shellcode_weaver.cli mutate \
  --input /tmp/my_shellcode.bin \
  --encoder xor \
  --junk-code \
  --nop-sled 32

# Result: Code is XOR encoded, has junk inserted, and 32 NOPs prepended
# Original: 20 bytes → Mutated: 100+ bytes
```

**Understanding the Output:**
```json
{
  "original_size": 20,
  "mutated_size": 34,
  "techniques_applied": ["junk_code_insertion", "encoder_xor"],
  "entropy": 3.74,                    # Increased entropy = harder to detect
  "entropy_delta": 0.63,              # How much entropy changed
  "hash_md5": "04a29c4d8dfe...",     # Now has different hash
  "detection_score": 0.0,             # How detectable (0=not detectable)
  "techniques_applied": [
    "junk_code_insertion",            # Applied junk code
    "encoder_xor"                     # Applied XOR encoding
  ]
}
```

---

### 4️⃣ VERSION Command - Check Software Version

**What it does:** Shows which version of Shellcode Weaver you're using.

**When to use:** When you need to verify you have the right version.

```bash
python3 -m shellcode_weaver.cli --version

# Output: Shellcode Weaver v4.0.0
```

---

## 🐍 Using Python API (Advanced)

Instead of the command line, you can use this as a Python library:

### Basic Example
```python
from shellcode_weaver.config import ShellcodeConfig, Platform, Architecture, PayloadType
from shellcode_weaver.generators.linux import LinuxGenerator

# Create configuration
config = ShellcodeConfig(
    platform=Platform.LINUX,
    architecture=Architecture.X86_64,
    payload_type=PayloadType.EXECVE
)

# Generate shellcode
generator = LinuxGenerator()
shellcode = generator.generate(config)

print(f"Generated {len(shellcode)} bytes of shellcode")
print(f"Hex: {shellcode.hex()}")
```

### Full Workflow Example
```python
from shellcode_weaver.config import ShellcodeConfig, Platform, Architecture, PayloadType, EncoderType
from shellcode_weaver.generators.windows import WindowsGenerator
from shellcode_weaver.polymorphic import PolymorphicEngine
from shellcode_weaver.analysis import ShellcodeAnalyzer

# Step 1: Generate
config = ShellcodeConfig(
    platform=Platform.WINDOWS,
    architecture=Architecture.X86_64,
    payload_type=PayloadType.CALC
)
gen = WindowsGenerator()
shellcode = gen.generate(config)
print(f"✅ Generated: {len(shellcode)} bytes")

# Step 2: Mutate
engine = PolymorphicEngine(seed=42)
mutation = engine.mutate(shellcode, config)
print(f"✅ Mutated: {mutation.original_size} → {mutation.mutated_size} bytes")
print(f"   Techniques: {mutation.techniques_applied}")

# Step 3: Analyze
analyzer = ShellcodeAnalyzer()
analysis = analyzer.analyze(shellcode)
print(f"✅ Analyzed: Entropy={analysis['entropy']:.2f}")
print(f"   Signatures: {analysis['signatures']}")
```

---

## 📁 Project Structure Explained

```
project_arsenal/
│
├── shellcode_weaver/          # Main package
│   ├── config.py              # Settings & options (enums)
│   ├── models.py              # Data structures for results
│   ├── utils.py               # Helper functions (hashing, entropy, etc.)
│   ├── cli.py                 # Command-line interface
│   │
│   ├── generators/            # Shellcode creators
│   │   ├── linux.py          # Linux shellcode (x64, x86)
│   │   └── windows.py        # Windows shellcode (x64, x86)
│   │
│   ├── polymorphic/           # Mutation engine
│   │   └── __init__.py       # Junk code, NOP sleds, encoders
│   │
│   ├── crypto/                # Encryption tools
│   │   └── __init__.py       # XOR, RC4, AES, ChaCha20
│   │
│   └── analysis/              # Analysis tools
│       └── __init__.py       # Entropy, signatures, hashes
│
├── tests/                     # Quality assurance
│   └── test_complete.py      # 21 tests verifying everything works
│
├── README.md                  # This file!
├── LICENSE                    # Legal terms
├── setup.py                   # Installation instructions
└── requirements.txt           # Dependencies needed
```

---

## 🧪 Testing (Verifying It Works)

### Run All Tests
```bash
python3 -m unittest discover -s tests -v

# You should see:
# ✅ 21 tests pass
# ✅ 0 failures
# ✅ 0 errors
```

### Run Specific Tests
```bash
# Test only generators
python3 -m unittest tests.test_complete.TestGenerators -v

# Test only mutations
python3 -m unittest tests.test_complete.TestPolymorphic -v

# Test encryption
python3 -m unittest tests.test_complete.TestCrypto -v
```

---

## 🎓 Common Use Cases

### Use Case 1: Security Testing (With Authorization!)
```bash
# Red team testing a Windows system they're authorized to test
python3 -m shellcode_weaver.cli generate \
  --platform windows \
  --arch x64 \
  --payload calc

# They inject this into a test system to verify security works
```

**Why:** Test if the security team can detect code injection.

### Use Case 2: IDS/IPS Testing (Intrusion Detection Systems)
```bash
# Security engineer testing their firewall/IDS
python3 -m shellcode_weaver.cli generate \
  --platform linux \
  --arch x64 \
  --payload execve

python3 -m shellcode_weaver.cli mutate \
  --input shellcode.bin \
  --encoder xor \
  --junk-code

# Does the IDS detect both versions?
```

**Why:** Ensure security tools catch mutations, not just known patterns.

### Use Case 3: Educational Learning
```bash
# Computer science student learning assembly
python3 -m shellcode_weaver.cli generate \
  --platform linux \
  --arch x64 \
  --payload execve \
  --format hex

# Analyze the hex to understand how system calls work
```

**Why:** Hands-on learning of low-level programming.

### Use Case 4: Vulnerability Research
```bash
# Researcher examining how systems handle code
python3 -m shellcode_weaver.cli generate --platform linux --arch x64 --payload test
python3 -m shellcode_weaver.cli analyze --input shellcode.bin

# Study how code is detected/analyzed
```

**Why:** Understanding attack/defense mechanics.

---

## 📊 Understanding Entropy

Entropy is a number (0-8) that shows how "random" code is:

```
Entropy 0-2:   Very predictable (mostly same bytes)
Entropy 2-4:   Somewhat random (recognizable patterns)
Entropy 4-6:   More random (harder to recognize)
Entropy 6-8:   Very random (looks like noise)
```

**Security Perspective:**
- Low entropy = security software recognizes it easily
- High entropy = looks like random data, might evade detection

**Example:**
```bash
python3 -m shellcode_weaver.cli analyze --input shellcode.bin

# Output shows:
# "entropy": 3.11
# This means it's somewhat random but still has recognizable patterns
```

---

## 🔐 Understanding Hashing

Hashes are like fingerprints - each unique input produces a unique output:

```
MD5:       32 characters (older, not secure)
SHA256:    64 characters (standard, secure)
SHA3-512: 128 characters (newest, most secure)
```

**Why it matters:**
- Security software uses hashes to identify known malware
- Different code = different hash
- Same code = same hash (always)

**Example:**
```bash
# Generate shellcode
python3 -m shellcode_weaver.cli generate --platform linux --arch x64 --payload test > sc1.bin

# Analyze it
python3 -m shellcode_weaver.cli analyze --input sc1.bin
# SHA256: abc123def456...

# Mutate it
python3 -m shellcode_weaver.cli mutate --input sc1.bin --encoder xor > sc2.bin

# Analyze mutated version
python3 -m shellcode_weaver.cli analyze --input sc2.bin
# SHA256: xyz789abc123... (DIFFERENT!)
# This is why mutations work - new code = new hash
```

---

## 🛠️ Troubleshooting

### Problem: "ModuleNotFoundError: No module named 'shellcode_weaver'"
**Solution:**
```bash
cd /home/kali/Desktop/project_arsenal
export PYTHONPATH=.:$PYTHONPATH
python3 -m shellcode_weaver.cli --version
```

### Problem: "Permission denied" on Windows detection test
**Solution:**
- Windows detection is simulated - not actually launching programs
- The tool is designed for authorized testing only

### Problem: Tests fail
**Solution:**
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Run tests again
python3 -m unittest discover -s tests -v
```

### Problem: Command not found
**Solution:**
```bash
# Use the full Python module path
python3 -m shellcode_weaver.cli --help
# Instead of just:
# shellcode-weaver --help
```

---

## 📚 Learning Resources

### Inside This Project:
- `tests/test_complete.py` - 21 working examples
- `shellcode_weaver/generators/linux.py` - How Linux code is generated
- `shellcode_weaver/polymorphic/__init__.py` - How mutations work
- `shellcode_weaver/crypto/__init__.py` - How encryption works

### External Resources:
- **x86 Assembly**: https://en.wikibooks.org/wiki/X86_Assembly
- **Shellcode Basics**: https://en.wikipedia.org/wiki/Shellcode
- **Security Testing**: https://owasp.org/

---

## 🚀 Quick Reference

```bash
# View help
python3 -m shellcode_weaver.cli --help

# Generate
python3 -m shellcode_weaver.cli generate --platform linux --arch x64 --payload execve --format hex

# Analyze
python3 -m shellcode_weaver.cli analyze --input shellcode.bin

# Mutate
python3 -m shellcode_weaver.cli mutate --input shellcode.bin --encoder xor --junk-code

# Version
python3 -m shellcode_weaver.cli --version

# Run tests
python3 -m unittest discover -s tests -v
```

---

## 💡 Tips for Success

1. **Always use with permission** - This is not negotiable!
2. **Start with `generate`** - Understand basic usage first
3. **Then use `analyze`** - See what characteristics you created
4. **Experiment with mutations** - Try different combinations
5. **Read test examples** - They show real usage patterns
6. **Document your learning** - Keep notes on what works

---

## 🎉 Summary

Shellcode Weaver is a **learning and testing tool** for security professionals. It helps you:
- Generate test code for different systems
- Analyze code characteristics
- Understand how code can be modified
- Test security system detection

**Use it responsibly, legally, and ethically!**

---

## 📞 Support & Quick Help

**Command Help:**
```bash
python3 -m shellcode_weaver.cli --help
```

**Generate Help:**
```bash
python3 -m shellcode_weaver.cli generate --help
```

**Analyze Help:**
```bash
python3 -m shellcode_weaver.cli analyze --help
```

**Mutate Help:**
```bash
python3 -m shellcode_weaver.cli mutate --help
```

---

## ⚖️ Final Legal Reminder

By using this tool, you agree that:
- ✅ You have explicit written authorization
- ✅ You understand it's a federal crime without permission
- ✅ You accept all legal responsibility
- ✅ You will use it ethically

**If you're unsure about authorization - STOP and ask first!**

---

**Remember: With great power comes great responsibility. Use this knowledge ethically and legally.**

⚖️ **AUTHORIZED USE ONLY** ⚖️
