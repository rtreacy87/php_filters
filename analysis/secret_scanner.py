import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Pattern
from php_filters.core.models import SecretFinding

class SecretScanner:
    def __init__(self, patterns_path: Optional[str] = None):
        self.patterns: Dict[str, List[str]] = self._load_patterns(patterns_path)
        self.compiled: Dict[str, List[Pattern]] = self._compile_patterns(self.patterns)

    def scan(self, source_code: str, filename: str) -> List[SecretFinding]:
        findings: List[SecretFinding] = []
        for secret_type, regexes in self.compiled.items():
            findings.extend(self._scan_category(regexes, source_code, filename, secret_type))
        return findings

    def _load_patterns(self, patterns_path: Optional[str]) -> Dict[str, List[str]]:
        default_path = Path(__file__).with_name('patterns.json')
        path = Path(patterns_path) if patterns_path else default_path
        if path.exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {k: list(v) for k, v in data.items() if isinstance(v, list)}
            except Exception:
                pass
        # Fallback built-in patterns
        return {
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

    def _compile_patterns(self, patterns: Dict[str, List[str]]) -> Dict[str, List[Pattern]]:
        compiled: Dict[str, List[Pattern]] = {}
        for secret_type, regex_list in patterns.items():
            compiled[secret_type] = [re.compile(p, re.IGNORECASE) for p in regex_list]
        return compiled

    def _scan_category(self, regexes: List[Pattern], source_code: str, filename: str, secret_type: str) -> List[SecretFinding]:
        results: List[SecretFinding] = []
        for regex in regexes:
            results.extend(self._find_matches(regex, source_code, filename, secret_type))
        return results

    def _find_matches(self, regex: Pattern, source_code: str, filename: str, secret_type: str) -> List[SecretFinding]:
        matches: List[SecretFinding] = []
        for m in regex.finditer(source_code):
            matches.append(self._build_finding(m, source_code, filename, secret_type))
        return matches

    def _build_finding(self, match: re.Match, source_code: str, filename: str, secret_type: str) -> SecretFinding:
        line = source_code[:match.start()].count('\n') + 1
        value = match.group(1)
        return SecretFinding(type=secret_type, value=value, line=line, file=filename)
