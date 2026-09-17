from dataclasses import dataclass, field
from typing import Any, Dict, List
@dataclass(frozen=True)
class CanonicalResponseContext:
    submitted_url: str
    normalized_url: str
    final_url: str
    status_code: int|None
    headers: Dict[str,str] = field(default_factory=dict)
    set_cookie_headers: List[str] = field(default_factory=list)
    bounded_body: str = ''
    content_type: str = ''
    redirect_chain: List[str] = field(default_factory=list)
    redirect_count: int = 0
    is_https: bool = False
    timing_ms: float = 0
    tls_info: Dict[str,Any] = field(default_factory=dict)
