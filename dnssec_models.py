from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

@dataclass
class Finding:
    zone: str
    server: str
    issue: str
    repro: str = ""
    detail_tail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ZoneResult:
    zone: str
    overall: str
    nameservers: List[str]
    findings: List[Finding]
    ns_consistency: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "zone": self.zone,
            "overall": self.overall,
            "nameservers": self.nameservers,
            "ns_consistency": self.ns_consistency or {},
            "findings": [f.to_dict() for f in self.findings],
        }
