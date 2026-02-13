from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from dnssec.models import Finding


@dataclass
class DCVResult:
    """
    DCV results for a given hostname/zone.

    Note: We store results for a single "name" (target hostname).
    Callers may choose to run this on apex, www, etc.
    """
    target: str
    overall: str = "unknown"  # ok | warning | broken | unknown
    findings: List[Finding] = field(default_factory=list)

    # Optional structured outputs the UI can show inline
    http01: Dict[str, Any] = field(default_factory=dict)
    dns01: Dict[str, Any] = field(default_factory=dict)
    alpn01: Dict[str, Any] = field(default_factory=dict)
    website_change: Dict[str, Any] = field(default_factory=dict)
    reverse_dns: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "overall": self.overall,
            "http01": self.http01,
            "dns01": self.dns01,
            "alpn01": self.alpn01,
            "website_change": self.website_change,
            "reverse_dns": self.reverse_dns,
            "findings": [f.__dict__ for f in self.findings],
        }
