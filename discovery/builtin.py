from typing import List
import requests

class BuiltinDiscovery:
    def discover(self, url: str, param: str, wordlist: str) -> List[str]:
        php_files: List[str] = []
        base_url = url.split('?')[0]
        try:
            with open(wordlist, 'r') as f:
                filenames = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []
        for filename in filenames:
            test_url = f"{base_url}?{param}={filename}"
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200 and len(resp.content) > 0:
                    php_files.append(filename)
            except Exception:
                continue
        return php_files
