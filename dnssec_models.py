from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    zone: str
    issue: str
    severity: str = "warning"  # info|warning|error
    server: Optional[str] = None
    repro: Optional[str] = None
    detail: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ZoneResult:
    zone: str
    overall: str = "unknown"  # pass|warn|fail|unknown
    nameservers: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    ns_consistency: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

    def finalize_overall(self) -> None:
        # simple roll-up: any error => fail, else any warning => warn, else pass
        severities = {f.severity for f in self.findings}
        if "error" in severities:
            self.overall = "fail"
        elif "warning" in severities:
            self.overall = "warn"
        elif self.findings:
            self.overall = "pass"
        else:
            self.overall = "pass"
