"""
Command-line interface - from original w5.py
LEGAL: Authorized security research and testing only
"""

import argparse
import sys
import json

from shellcode_weaver.config import (
    ShellcodeConfig, Platform, Architecture, PayloadType, 
    EncoderType, EvasionLevel, OutputFormat
)
from shellcode_weaver.generators.linux import LinuxGenerator
from shellcode_weaver.generators.windows import WindowsGenerator
from shellcode_weaver.polymorphic import PolymorphicEngine
from shellcode_weaver.analysis import ShellcodeAnalyzer
from shellcode_weaver.utils import EnhancedUtils


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        prog="shellcode-weaver",
        description="Shellcode Weaver  - Ultimate Polymorphic Shellcode Engine\n"
                    "⚠️  LEGAL NOTICE: For authorized security testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
LEGAL DISCLAIMER:
  - Use only on systems you own or have explicit written permission to test
  - Unauthorized access is illegal
  - The authors assume no responsibility for misuse

Examples:
  shellcode-weaver generate --platform linux --arch x64 --payload execve
  shellcode-weaver mutate --input shellcode.bin --encoder xor
  shellcode-weaver analyze --input shellcode.bin
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Generate command
    gen = subparsers.add_parser("generate", help="Generate shellcode")
    gen.add_argument("--platform", "-p", required=True, 
                     choices=["linux", "windows", "macos"],
                     help="Target platform")
    gen.add_argument("--arch", "-a", required=True,
                     choices=["x64", "x86", "arm64", "arm"],
                     help="Target architecture")
    gen.add_argument("--payload", "-t", required=True,
                     help="Payload type (execve, calc, reverse_tcp, bind_tcp, test, ...)")
    gen.add_argument("--lhost", help="Local host for reverse shells")
    gen.add_argument("--lport", type=int, help="Local port for reverse shells")
    gen.add_argument("--output", "-o", help="Output file")
    gen.add_argument("--format", "-f", default="raw",
                     choices=["raw", "hex", "python", "c", "base64"],
                     help="Output format")
    
    # Mutate command
    mut = subparsers.add_parser("mutate", help="Mutate shellcode")
    mut.add_argument("--input", "-i", required=True, help="Input shellcode file")
    mut.add_argument("--output", "-o", help="Output file")
    mut.add_argument("--encoder", "-e", choices=["xor", "add_sub", "rol_ror", "base64"],
                     help="Encoder type")
    mut.add_argument("--junk-code", action="store_true", help="Add junk code")
    mut.add_argument("--nop-sled", type=int, help="Add NOP sled of size N")
    
    # Analyze command
    ana = subparsers.add_parser("analyze", help="Analyze shellcode")
    ana.add_argument("--input", "-i", required=True, help="Input shellcode file")
    ana.add_argument("--output", "-o", help="Output JSON file")
    
    # Version
    parser.add_argument("--version", "-v", action="store_true", help="Show version")
    
    return parser


def _handle_generate(args) -> int:
    """Handle generate command"""
    try:
        # Parse platform and architecture
        platform = Platform.LINUX if args.platform == "linux" else \
                  Platform.WINDOWS if args.platform == "windows" else \
                  Platform.MACOS
        
        arch = Architecture.X86_64 if args.arch == "x64" else \
               Architecture.X86_32 if args.arch == "x86" else \
               Architecture.ARM64 if args.arch == "arm64" else \
               Architecture.ARM
        
        # Create config
        config = ShellcodeConfig(
            platform=platform,
            architecture=arch,
            payload_type=PayloadType(args.payload) if hasattr(PayloadType, args.payload.upper()) else PayloadType.TEST,
            lhost=args.lhost,
            lport=args.lport,
        )
        
        # Select generator
        if args.platform == "linux":
            gen = LinuxGenerator()
        elif args.platform == "windows":
            gen = WindowsGenerator()
        else:
            print("[-] macOS generator not yet implemented", file=sys.stderr)
            return 1
        
        # Generate
        shellcode = gen.generate(config)
        
        # Format output
        if args.format == "hex":
            output = shellcode.hex()
        elif args.format == "python":
            output = "shellcode = " + repr(shellcode)
        elif args.format == "c":
            hex_str = "".join(f"\\x{b:02x}" for b in shellcode)
            output = f'unsigned char shellcode[] = "{hex_str}";'
        elif args.format == "base64":
            import base64
            output = base64.b64encode(shellcode).decode()
        else:
            output = shellcode.decode('latin1') if args.output else shellcode.hex()
        
        # Save or print
        if args.output:
            if args.format in ["raw"]:
                with open(args.output, 'wb') as f:
                    f.write(shellcode)
            else:
                with open(args.output, 'w') as f:
                    f.write(output)
            print(f"[+] Shellcode written to {args.output}")
        else:
            print(output)
        
        return 0
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1


def _handle_mutate(args) -> int:
    """Handle mutate command"""
    try:
        # Read input
        with open(args.input, 'rb') as f:
            shellcode = f.read()
        
        # Create config
        config = ShellcodeConfig(
            encoder=EncoderType(args.encoder) if args.encoder else None,
            junk_code=args.junk_code,
            nop_sled=args.nop_sled is not None,
            nop_sled_size=args.nop_sled or 32,
        )
        
        # Mutate
        engine = PolymorphicEngine()
        result = engine.mutate(shellcode, config)
        
        # Save or print
        utils = EnhancedUtils()
        data = result.to_dict()
        
        if args.output:
            if args.output.endswith('.json'):
                utils.write_json_file(args.output, data)
            else:
                # TODO: Save mutated shellcode
                pass
            print(f"[+] Mutation result written to {args.output}")
        else:
            print(json.dumps(data, indent=2))
        
        return 0
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1


def _handle_analyze(args) -> int:
    """Handle analyze command"""
    try:
        # Read input
        with open(args.input, 'rb') as f:
            shellcode = f.read()
        
        # Analyze
        analyzer = ShellcodeAnalyzer()
        analysis = analyzer.analyze(shellcode)
        signatures = analyzer.detect_signatures(shellcode)
        
        analysis['signatures'] = signatures
        
        # Output
        if args.output:
            utils = EnhancedUtils()
            utils.write_json_file(args.output, analysis)
            print(f"[+] Analysis written to {args.output}")
        else:
            print(json.dumps(analysis, indent=2))
        
        return 0
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1


def main(args=None) -> int:
    """Main CLI entry point"""
    parser = create_parser()
    parsed = parser.parse_args(args)
    
    if parsed.version:
        from shellcode_weaver import __version__
        print(f"Shellcode Weaver v{__version__}")
        return 0
    
    if not parsed.command:
        parser.print_help()
        return 1
    
    if parsed.command == "generate":
        return _handle_generate(parsed)
    elif parsed.command == "mutate":
        return _handle_mutate(parsed)
    elif parsed.command == "analyze":
        return _handle_analyze(parsed)
    
    return 1


if __name__ == "__main__":
    sys.exit(main())
