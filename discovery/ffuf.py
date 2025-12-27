import json
import subprocess
from typing import List

class FFufDiscovery:
    def discover(self, url: str, param: str, wordlist: str) -> List[str]:
        base_url = url.split('?')[0]
        cmd = [
            'ffuf', '-w', wordlist + ':FUZZ',
            '-u', f'{base_url}?{param}=FUZZ',
            '-mc', '200',
            '-o', 'ffuf_results.json',
            '-of', 'json',
            '-s'
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            with open('ffuf_results.json', 'r') as f:
                results = json.load(f)
            php_files = []
            for result in results.get('results', []):
                url_result = result.get('url', '')
                if param in url_result:
                    value = url_result.split(f'{param}=')[1].split('&')[0]
                    php_files.append(value)
            return php_files
        except FileNotFoundError:
            return []
        except Exception:
            return []
