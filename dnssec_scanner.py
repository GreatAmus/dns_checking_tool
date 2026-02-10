from __future__ import annotations

from typing import List

from dnssec_checks import DNSSECChecks
from dnssec_models import Finding, ZoneResult


class DNSSECScanner:
    def __init__(self, timeout: float = 8.0):
        self.checks = DNSSECChecks(timeout=timeout)

    def scan_zone(self, zone: str) -> ZoneResult:
        zone = zone.strip().rstrip(".")
        zr = ZoneResult(zone=zone)

        # nameservers (best effort)
        try:
            zr.nameservers = self.checks._resolve_ns(zone + ".")
        except Exception:
            zr.nameservers = []

        # 1) delegation / DS
        delegation, f = self.checks.check_parent_signed_and_ds(zone)
        zr.findings.extend(f)

        # If parent is unsigned, we can still do “zone-signed” checks, but chain-of-trust isn’t required.
        # If parent is signed and DS is missing/error, chain checks will show failures; still continue with local checks.

        # 2) if DS exists, ensure it matches DNSKEY
        if delegation.parent_signed and delegation.ds_records:
            zr.findings.extend(self.checks.check_ds_matches_dnskey(zone, delegation.ds_records))

        # 3) validate signatures for critical rrsets
        # DNSKEY self-sign + SOA are the most important
        zr.findings.extend(self.checks.validate_rrsig_for_rrset(zone, "DNSKEY"))
        zr.findings.extend(self.checks.validate_rrsig_for_rrset(zone, "SOA"))
        zr.findings.extend(self.checks.validate_rrsig_for_rrset(zone, "NS"))

        # 4) denial of existence (basic)
        zr.findings.extend(self.checks.validate_denial_of_existence(zone))

        zr.finalize_overall()
        return zr
