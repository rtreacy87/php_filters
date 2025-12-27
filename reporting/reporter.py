from pathlib import Path
from typing import List
from php_filters.core.colors import Colors
from php_filters.core.models import ExtractResult, SecretFinding

class Reporter:
    def __init__(self, url: str, param: str, output_dir: str = "php_sources"):
        self.url = url
        self.param = param
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results: List[ExtractResult] = []
        self.secrets_found: List[SecretFinding] = []

    def banner(self):
        print(f"{Colors.BLUE}╔════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║     PHP Filter Source Code Disclosure Tool            ║{Colors.NC}")
        print(f"{Colors.BLUE}║     Automated PHP Source Extraction via LFI           ║{Colors.NC}")
        print(f"{Colors.BLUE}╚════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        print(f"{Colors.YELLOW}[*] Target URL: {self.url}{Colors.NC}")
        print(f"{Colors.YELLOW}[*] Parameter: {self.param}{Colors.NC}")
        print(f"{Colors.YELLOW}[*] Output Directory: {self.output_dir}{Colors.NC}")
        print()

    def save_source(self, filename: str, source_code: str) -> str:
        out = self.output_dir / f"{filename.replace('/', '_')}.php"
        out.write_text(source_code)
        print(f"{Colors.GREEN}  [✓] Saved to: {out}{Colors.NC}")
        return str(out)

    def add_result(self, result: ExtractResult):
        self.results.append(result)
        self.secrets_found.extend(result.secrets)

    def report(self):
        print()
        print(f"{Colors.BLUE}╔════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║                    FINAL REPORT                        ║{Colors.NC}")
        print(f"{Colors.BLUE}╚════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        print(f"{Colors.BOLD}Summary:{Colors.NC}")
        print(f"  Files extracted: {len(self.results)}")
        print(f"  Secrets found: {len(self.secrets_found)}")
        print()
        if self.secrets_found:
            print(f"{Colors.RED}{Colors.BOLD}[!] SENSITIVE INFORMATION DISCOVERED:{Colors.NC}")
            print()
            by_type = {}
            for s in self.secrets_found:
                by_type.setdefault(s.type, []).append(s)
            for t, items in by_type.items():
                print(f"{Colors.YELLOW}{t}:{Colors.NC}")
                for s in items:
                    print(f"  File: {s.file} (line {s.line})")
                    print(f"  Value: {Colors.RED}{s.value}{Colors.NC}")
                    print()
        report_file = self.output_dir / "report.txt"
        with open(report_file, 'w') as f:
            f.write("PHP Source Code Disclosure Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Target: {self.url}\n")
            f.write(f"Parameter: {self.param}\n\n")
            f.write(f"Files Extracted: {len(self.results)}\n")
            f.write(f"Secrets Found: {len(self.secrets_found)}\n\n")
            if self.secrets_found:
                f.write("SENSITIVE INFORMATION:\n")
                f.write("-" * 60 + "\n\n")
                by_type = {}
                for s in self.secrets_found:
                    by_type.setdefault(s.type, []).append(s)
                for t, items in by_type.items():
                    f.write(f"{t}:\n")
                    for s in items:
                        f.write(f"  File: {s.file} (line {s.line})\n")
                        f.write(f"  Value: {s.value}\n\n")
        print(f"{Colors.GREEN}[+] Report saved to: {report_file}{Colors.NC}")
