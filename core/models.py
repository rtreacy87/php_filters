from dataclasses import dataclass
from typing import List, Optional

@dataclass
class SecretFinding:
    type: str
    value: str
    line: int
    file: str

@dataclass
class ExtractResult:
    filename: str
    source_code: str
    secrets: List[SecretFinding]
    output_file: Optional[str] = None
