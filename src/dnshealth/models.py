from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from dnssec.models import Finding


@dataclass
class DNSHealthResult:
    """
    Result for DNS health checks.

    We reuse the shared Finding model from dnssec.models so the assembler can merge
    findings uniformly across modules.
    """

    zone: str
    overall: str = "unknown"  # ok | warning | broken | unknown
    nameservers: List[str] = field(default_factory=list)  # delegation NS hostnames
    nameserver_ips: Dict[str, List[str]] = field(default_factory=dict)  # ns -> [ip]
    observations: Dict[str, Any] = field(default_factory=dict)  # debug/telemetry
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "zone": self.zone,
            "overall": self.overall,
            "nameservers": self.nameservers,
            "nameserver_ips": self.nameserver_ips,
            "observations": self.observations,
            "findings": [f.__dict__ for f in self.findings],
        }
