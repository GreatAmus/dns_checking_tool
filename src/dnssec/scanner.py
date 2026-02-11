# dnssec_scanner.py
from __future__ import annotations

from .checks import DNSSECChecks
from .models import ZoneResult


class DNSSECScanner:
    def __init__(
        self,
        timeout: float = 8.0,
        include_unsigned_finding: bool = False,
        strict_dnssec: bool = False,
    ):
        self.checks = DNSSECChecks(timeout=timeout, strict_dnssec=strict_dnssec)
        self.include_unsigned_finding = bool(include_unsigned_finding)

    def scan_zone(self, zone: str) -> ZoneResult:
        zone = zone.strip().rstrip(".")
        z = zone + "."
        zr = ZoneResult(zone=zone)

        # nameservers (best effort)
        try:
            zr.nameservers = self.checks._resolve_ns_names(z)
        except Exception:
            zr.nameservers = []

        # Delegation / DS
        delegation, f = self.checks.get_delegation_ds(zone)

        # Optionally suppress the "unsigned delegation" informational finding
        if not self.include_unsigned_finding:
            f = [x for x in f if x.issue not in ("DNSSEC_NOT_ENABLED", "PARENT_UNSIGNED")]

        zr.findings.extend(f)

        # If unsigned delegation, skip the rest (this avoids bogus DNSKEY/RRSIG failures)
        if not delegation.ds_present:
            zr.finalize_overall()
            return zr

        # DS <-> DNSKEY match
        zr.findings.extend(self.checks.check_ds_matches_dnskey(zone, delegation.ds_records))

        # If DNSKEY query failed, no point continuing with signature validation
        if any(x.issue == "DNSKEY_QUERY_FAILED" for x in zr.findings):
            zr.finalize_overall()
            return zr

        # Validate critical apex RRsets
        zr.findings.extend(self.checks.validate_rrsig_for_rrset(zone, "DNSKEY"))
        zr.findings.extend(self.checks.validate_rrsig_for_rrset(zone, "SOA"))
        zr.findings.extend(self.checks.validate_rrsig_for_rrset(zone, "NS"))

        # Denial of existence checks
        zr.findings.extend(self.checks.validate_denial_of_existence(zone))

        zr.finalize_overall()
        return zr
