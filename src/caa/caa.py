# caa.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple

from ca_resolver import DNSQueryResult  # make sure this import matches your project


DIGICERT_ALLOWED_CAA_VALUES = {
    "www.digicert.com",
    "digicert.com",
    "digicert.ne.jp",
    "cybertrust.ne.jp",
    "thawte.com",
    "geotrust.com",
    "rapidssl.com",
    "symantec.com",
    "volusion.digitalcertvalidation.com",
    "stratossl.digitalcertvalidation.com",
    "intermediatecertificate.digitalcertvalidation.com",
    "1and1.digitalcertvalidation.com",
    "amazon.com",
    "amazontrust.com",
    "awstrust.com",
    "amazonaws.com",
    "digitalcertvalidation.com",
    "quovadisglobal.com",
    "pkioverheid.nl",
}


class DNSResolver(Protocol):
    # Updated: allow checking_disabled flag (CD bit) for "show records even if validation fails"
    def query(self, qname: str, qtype: str, *, checking_disabled: bool = False) -> DNSQueryResult:
        ...


@dataclass
class CAAResult:
    zone: str
    effective_domain: str
    inherited: bool

    # Raw CAA rdata strings (what UI shows)
    records: List[str] = field(default_factory=list)
    # Parsed entries: {"flag","tag","value"}
    parsed: List[Dict[str, str]] = field(default_factory=list)

    # Metadata about the validated lookup attempt (CD=0)
    lookup: Dict[str, Any] = field(default_factory=dict)

    # If validation fails, we optionally include what we observed with CD=1
    observed_unvalidated: bool = False
    observed_lookup: Optional[Dict[str, Any]] = None

    allows_any_issuance: bool = True
    allows_wildcards: bool = True
    allows_digicert_nonwild: bool = True
    allows_digicert_wild: bool = True

    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "zone": self.zone,
            "effective_domain": self.effective_domain,
            "inherited": self.inherited,
            "records": self.records,
            "parsed": self.parsed,
            "lookup": self.lookup,
            "observed_unvalidated": self.observed_unvalidated,
            "observed_lookup": self.observed_lookup,
            "allows_any_issuance": self.allows_any_issuance,
            "allows_wildcards": self.allows_wildcards,
            "allows_digicert_nonwild": self.allows_digicert_nonwild,
            "allows_digicert_wild": self.allows_digicert_wild,
            "findings": self.findings,
        }


class CAAChecker:
    def __init__(self, resolver: DNSResolver, max_labels: int = 10) -> None:
        self.resolver = resolver
        self.max_labels = int(max_labels)

    @staticmethod
    def _normalize_name(name: str) -> str:
        return name.strip().rstrip(".").lower()

    @staticmethod
    def _parse_caa_rdata(rdata_text: str) -> Optional[Dict[str, str]]:
        parts = rdata_text.split(None, 2)
        if len(parts) < 3:
            return None
        flag = parts[0].strip()
        tag = parts[1].strip().lower()
        value = parts[2].strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        return {"flag": flag, "tag": tag, "value": value}

    @staticmethod
    def _issuer_domain(value: str) -> str:
        v = (value or "").strip()
        # CAA can carry ';' params (e.g., accounturi=) — ignore for issuer match
        if ";" in v:
            v = v.split(";", 1)[0].strip()
        return v.lower()

    def _query_caa(
        self, fqdn: str, *, checking_disabled: bool = False
    ) -> Tuple[DNSQueryResult, List[str], List[Dict[str, str]]]:
        qr = self.resolver.query(fqdn, "CAA", checking_disabled=checking_disabled)
        records = list(qr.answers or [])
        parsed = [p for p in (self._parse_caa_rdata(x) for x in records) if p]
        return qr, records, parsed

    def _effective_caa(
        self, zone: str
    ) -> Tuple[
        str,
        DNSQueryResult,
        List[str],
        List[Dict[str, str]],
        bool,
        Optional[DNSQueryResult],
        List[str],
        List[Dict[str, str]],
    ]:
        """
        Walk up labels and return first RRset with any CAA entries.

        CA-like behavior:
          - The CD=0 (validated) lookup is authoritative for issuance decisions.
          - If CD=0 fails (SERVFAIL/TIMEOUT/ERROR/REFUSED), we ALSO try CD=1 once
            so we can still display the observed CAA policy to the user.
        """
        z = self._normalize_name(zone)
        labels = [x for x in z.split(".") if x]

        last_qr = DNSQueryResult(qname=z + ".", qtype="CAA", rcode="unknown", answers=[], validated=False)

        # If validation fails, we capture what we observed with CD=1
        observed_unvalidated = False
        observed_qr: Optional[DNSQueryResult] = None
        observed_records: List[str] = []
        observed_parsed: List[Dict[str, str]] = []

        for i in range(0, min(len(labels), self.max_labels)):
            name = ".".join(labels[i:]) + "."

            qr, records, parsed = self._query_caa(name, checking_disabled=False)
            last_qr = qr
            rcode = str(qr.rcode).upper()

            # If validated lookup fails, do ONE fallback for visibility (CD=1), then stop.
            if rcode in ("TIMEOUT", "ERROR", "SERVFAIL", "REFUSED"):
                observed_qr, observed_records, observed_parsed = self._query_caa(
                    name, checking_disabled=True
                )
                observed_unvalidated = True
                return (
                    name.rstrip("."),
                    qr,
                    [],  # validated records not trustworthy for issuance (it failed)
                    [],
                    observed_unvalidated,
                    observed_qr,
                    observed_records,
                    observed_parsed,
                )

            if parsed:
                # Validated lookup succeeded and has entries
                return (
                    name.rstrip("."),
                    qr,
                    records,
                    parsed,
                    False,
                    None,
                    [],
                    [],
                )

        # No CAA found anywhere in chain (validated)
        return (
            z,
            last_qr,
            [],
            [],
            False,
            None,
            [],
            [],
        )

    @staticmethod
    def _all_empty_issuers(entries: List[Dict[str, str]]) -> bool:
        if not entries:
            return False
        return all(CAAChecker._issuer_domain(p.get("value", "")) == "" for p in entries)

    @staticmethod
    def _any_allowed_issuer(entries: List[Dict[str, str]], allowed: set[str]) -> bool:
        for p in entries:
            issuer = CAAChecker._issuer_domain(p.get("value", ""))
            if issuer in allowed:
                return True
        return False

    @staticmethod
    def _lookup_meta(qr: DNSQueryResult, resolver: Any) -> Dict[str, Any]:
        return {
            "qname": qr.qname,
            "qtype": qr.qtype,
            "rcode": qr.rcode,
            "validated": bool(getattr(qr, "validated", False)),
            "error": getattr(qr, "error", None),
            "resolver_mode": getattr(resolver, "mode", None),
        }

    def check_zone(self, zone: str) -> CAAResult:
        (
            eff_domain,
            eff_qr,
            records,
            parsed,
            observed_unvalidated,
            observed_qr,
            observed_records,
            observed_parsed,
        ) = self._effective_caa(zone)

        inherited = self._normalize_name(eff_domain) != self._normalize_name(zone)
        rcode = str(eff_qr.rcode or "").upper()

        lookup_meta = self._lookup_meta(eff_qr, self.resolver)
        observed_meta = self._lookup_meta(observed_qr, self.resolver) if observed_qr else None

        # If we couldn't complete validated lookup, CA-style behavior = HARD STOP.
        # But we still show observed CAA (CD=1) if we captured it.
        if rcode in ("TIMEOUT", "ERROR", "SERVFAIL", "REFUSED"):
            findings: List[Dict[str, Any]] = [
                {
                    "issue": "CAA_LOOKUP_FAILED",
                    "severity": "high",
                    "title": "CAA lookup failed (cannot determine issuance authorization)",
                    "detail": (
                        f"CAA lookup failed while checking {eff_domain}. "
                        f"rcode={rcode}, validated={bool(eff_qr.validated)}, error={eff_qr.error or ''}. "
                        "This must not be treated as permission to issue."
                    ),
                    "check": "caa",
                }
            ]

            # Add an informational note if we still observed records with CD=1
            if observed_unvalidated and observed_parsed:
                findings.append(
                    {
                        "issue": "CAA_OBSERVED_UNVALIDATED",
                        "severity": "info",
                        "title": "CAA policy observed (unvalidated)",
                        "detail": (
                            f"CAA records were observed at {eff_domain} when DNSSEC checking was disabled (CD=1). "
                            "These records are shown for visibility only; issuance authorization could not be "
                            "confirmed with DNSSEC validation."
                        ),
                        "check": "caa",
                    }
                )

            # Show observed records if we have them (better UX), but issuance flags are false.
            return CAAResult(
                zone=self._normalize_name(zone),
                effective_domain=eff_domain,
                inherited=inherited,
                records=observed_records if observed_unvalidated else [],
                parsed=observed_parsed if observed_unvalidated else [],
                lookup=lookup_meta,
                observed_unvalidated=observed_unvalidated,
                observed_lookup=observed_meta,
                allows_any_issuance=False,
                allows_wildcards=False,
                allows_digicert_nonwild=False,
                allows_digicert_wild=False,
                findings=findings,
            )

        # ---- Validated lookup succeeded: apply normal CAA policy evaluation ----

        issue = [p for p in parsed if p.get("tag") == "issue"]
        issuewild = [p for p in parsed if p.get("tag") == "issuewild"]

        has_any_caa = bool(parsed)
        has_tls_tags = bool(issue or issuewild)

        allows_any_issuance = True
        allows_wildcards = True

        if has_any_caa and not has_tls_tags:
            allows_any_issuance = False
            allows_wildcards = False
        else:
            if has_any_caa:
                if issue:
                    if self._all_empty_issuers(issue):
                        allows_any_issuance = False
                else:
                    allows_any_issuance = False

            if has_any_caa:
                if issuewild:
                    if self._all_empty_issuers(issuewild):
                        allows_wildcards = False
                else:
                    if issue:
                        if self._all_empty_issuers(issue):
                            allows_wildcards = False
                    else:
                        allows_wildcards = False

        allows_digicert_nonwild = True
        if has_any_caa:
            allows_digicert_nonwild = self._any_allowed_issuer(issue, DIGICERT_ALLOWED_CAA_VALUES) if issue else False

        allows_digicert_wild = True
        if has_any_caa:
            if issuewild:
                allows_digicert_wild = self._any_allowed_issuer(issuewild, DIGICERT_ALLOWED_CAA_VALUES)
            else:
                allows_digicert_wild = self._any_allowed_issuer(issue, DIGICERT_ALLOWED_CAA_VALUES) if issue else False

        findings: List[Dict[str, Any]] = []
        if has_any_caa:
            findings.append(
                {
                    "issue": "CAA_PRESENT",
                    "severity": "info",
                    "title": "CAA policy detected",
                    "detail": f"CAA records were found at {eff_domain}" + (" (inherited from parent)." if inherited else "."),
                    "check": "caa",
                }
            )
        else:
            findings.append(
                {
                    "issue": "CAA_NONE",
                    "severity": "info",
                    "title": "No CAA records found",
                    "detail": "No CAA records were found at the domain or its parent chain. Issuance is not restricted by CAA.",
                    "check": "caa",
                }
            )

        if has_any_caa and not allows_any_issuance:
            findings.append(
                {
                    "issue": "CAA_BLOCKS_ISSUANCE",
                    "severity": "high",
                    "title": "CAA policy blocks certificate issuance",
                    "detail": f"Effective CAA policy at {eff_domain} does not authorize non-wildcard issuance.",
                    "check": "caa",
                }
            )

        if has_any_caa and not allows_wildcards:
            findings.append(
                {
                    "issue": "CAA_BLOCKS_WILDCARDS",
                    "severity": "medium",
                    "title": "CAA policy restricts wildcard issuance",
                    "detail": f"Effective CAA policy at {eff_domain} does not authorize wildcard issuance.",
                    "check": "caa",
                }
            )

        if has_any_caa and allows_any_issuance and not allows_digicert_nonwild:
            findings.append(
                {
                    "issue": "CAA_DIGICERT_NOT_ALLOWED",
                    "severity": "medium",
                    "title": "CAA policy does not permit DigiCert (non-wildcard)",
                    "detail": f"Effective CAA policy at {eff_domain} does not include a DigiCert-accepted issuer in the 'issue' set.",
                    "check": "caa",
                }
            )

        if has_any_caa and allows_wildcards and not allows_digicert_wild:
            findings.append(
                {
                    "issue": "CAA_DIGICERT_WILDCARD_NOT_ALLOWED",
                    "severity": "medium",
                    "title": "CAA policy does not permit DigiCert (wildcard)",
                    "detail": f"Effective CAA policy at {eff_domain} does not include a DigiCert-accepted issuer in the wildcard authorization set.",
                    "check": "caa",
                }
            )

        return CAAResult(
            zone=self._normalize_name(zone),
            effective_domain=eff_domain,
            inherited=inherited,
            records=records,
            parsed=parsed,
            lookup=lookup_meta,
            observed_unvalidated=False,
            observed_lookup=None,
            allows_any_issuance=allows_any_issuance,
            allows_wildcards=allows_wildcards,
            allows_digicert_nonwild=allows_digicert_nonwild,
            allows_digicert_wild=allows_digicert_wild,
            findings=findings,
        )
