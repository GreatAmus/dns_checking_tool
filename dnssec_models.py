# dnssec_models.py
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class Finding:
    zone: str
    issue: str
    severity: str = "info"
    server: Optional[str] = None
    repro: Optional[str] = None
    detail: str = ""
    recommendation: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    # compatibility for older/newer reporter code
    detail_head: Optional[str] = None
    detail_tail: Optional[str] = None


@dataclass
class ZoneResult:
    zone: str
    overall: str = "unknown"
    nameservers: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "zone": self.zone,
            "overall": self.overall,
            "nameservers": self.nameservers,
            "findings": [f.__dict__ for f in self.findings],
        }
