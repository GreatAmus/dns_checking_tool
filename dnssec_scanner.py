"""
DNSSEC scanning logic (policy-aware).

Key behavior:
- Determine whether a child zone is REQUIRED to be DNSSEC-signed:
    - If parent zone is unsigned -> child is not required (PASS, no warnings)
    - If parent zone is signed:
        - If parent publishes DS for child -> child SHOULD be signed (run DNSKEY checks)
        - If parent does NOT publish DS for child -> child is not required (PASS, no warnings)
- Avoid false warnings caused by UDP truncation / EDNS issues by using TCP for DS/DNSKEY probes.
- Only emit DNSKEY-related findings when DS exists (i.e., child should be signed).
"""

import re
from typing import Dict, List, Optional, Tuple, Any

from dnssec_runner import CommandRunner
from dnssec_models import Finding, ZoneResult


class DnssecScanner:
    """DNSSEC scanning logic (dig + delv)."""

    def __init__(
        self,
        runner: Optional[CommandRunner] = None,
        dns_resolver_for_ds: str = "8.8.8.8",  # kept for compatibility; not relied on for policy
        cmd_timeout_seconds: int = 20,
        include_unsigned_finding: bool = False,  # default false to avoid noise
    ):
        self.runner = runner or CommandRunner(timeout_seconds=cmd_timeout_seconds)
        self.dns_resolver_for_ds = dns_resolver_for_ds
        self.include_unsigned_finding = include_unsigned_finding

    # ---- low-level helpers ----
    def dig(self, args: List[str]) -> str:
        return self.runner.dig(args).output

    def delv(self, args: List[str]) -> str:
        return self.runner.delv(args).output

    def dig_ns(self, zone: str) -> List[str]:
        out = self.dig(["+short", zone, "NS"])
        return [l.strip().rstrip(".") for l in out.splitlines() if l.strip()]

    # Always use TCP for DS/DNSKEY checks to avoid truncation/EDNS false negatives
    def dig_answer_tcp(self, server: str, name: str, rtype: str) -> str:
        return self.dig(
            [f"@{server}", name, rtype, "+dnssec", "+tcp", "+norecurse", "+noall", "+answer", "+comments"]
        )

    def dig_dnssec_sections_tcp(self, server: str, name: str, rtype: str) -> str:
        return self.dig(
            [f"@{server}", name, rtype, "+dnssec", "+tcp", "+norecurse", "+noall", "+answer", "+authority", "+comments"]
        )

    # ---- delegation helpers ----
    def _parent_zone(self, zone: str) -> str:
        z = zone.rstrip(".") + "."
        parts = z.split(".")
        if len(parts) <= 2:
            return "."
        return ".".join(parts[1:])

    @staticmethod
    def _looks_like_query_failure(text: str) -> Optional[str]:
        low = (text or "").lower()
        if (text or "").startswith("[timeout") or "no servers could be reached" in low or "connection timed out" in low:
            return "NS_UNREACHABLE"
        if "refused" in low:
            return "NS_REFUSED"
        return None

    def _zone_has_dnskey(self, zone: str) -> bool:
        """Treat zone as signed if any authoritative returns DNSKEY in ANSWER (TCP)."""
        z = zone.rstrip(".") + "."
        for ns in self.dig_ns(z):
            out = (self.dig_answer_tcp(ns, z, "DNSKEY") or "").strip()
            if re.search(r"\sDNSKEY\s", out):
                return True
        return False

    def _parent_ds_status(self, parent: str, child: str) -> Tuple[Optional[bool], Dict[str, str], Dict[str, str]]:
        """
        Query the parent authoritatives for child's DS using TCP.

        Returns (has_ds, per_ns_raw, failures):
          has_ds = True  -> at least one successful response contained DS
          has_ds = False -> at least one successful response, none contained DS
          has_ds = None  -> no successful responses (all failures)
        """
        p = parent.rstrip(".") + "."
        c = child.rstrip(".") + "."

        per: Dict[str, str] = {}
        failures: Dict[str, str] = {}

        saw_success = False
        saw_ds = False

        for pns in self.dig_ns(p):
            out = (self.dig_answer_tcp(pns, c, "DS") or "").strip()
            per[pns] = out

            fail = self._looks_like_query_failure(out)
            if fail:
                failures[pns] = fail
                continue

            saw_success = True
            if re.search(r"\sDS\s", out):
                saw_ds = True

        if not saw_success:
            return None, per, failures
        return (True if saw_ds else False), per, failures

    # ---- delv probe ----
    def delv_probe(self, qname: str, qtype: str, server: Optional[str] = None) -> Dict[str, Any]:
        cmd = ["+rtrace", qname, qtype]
        if server:
            cmd.append(f"@{server}")
        out = self.delv(cmd)
        low = out.lower()

        if "validation failure" in low or "bogus" in low:
            status = "bogus"
        elif "fully validated" in low or "validated" in low:
            status = "secure"
        elif "insecure" in low:
            status = "insecure"
        else:
            status = "unknown"

        return {
            "qname": qname,
            "qtype": qtype,
            "status": status,
            "detail": "\n".join(out.splitlines()[-80:]),
            "repro_cmd": "delv +rtrace {} {}{}".format(qname, qtype, f" @{server}" if server else ""),
        }

    # ---- DNSKEY normalization + consistency ----
    @staticmethod
    def _normalize_dnskey_rrset(ans: str) -> str:
        lines: List[str] = []
        for ln in (ans or "").splitlines():
            if " DNSKEY " not in ln.upper():
                continue
            ln = re.sub(r"\s+", " ", ln.strip())
            parts = ln.split(" ")
            # Keep stable "DNSKEY <flags> <proto> <alg> <key...>"
            if len(parts) >= 6 and parts[2].upper() == "IN" and parts[3].upper() == "DNSKEY":
                ln = " ".join([parts[3]] + parts[4:])
            lines.append(ln)
        return "\n".join(sorted(lines))

    def compare_dnskey_across_ns(self, zone: str) -> Dict[str, Any]:
        ns = self.dig_ns(zone)
        per_ns: Dict[str, str] = {}
        normalized: Dict[str, str] = {}
        failures: Dict[str, str] = {}

        for s in ns:
            ans = (self.dig_answer_tcp(s, zone, "DNSKEY") or "").strip()
            per_ns[s] = ans

            fail = self._looks_like_query_failure(ans)
            if fail:
                failures[s] = fail
                continue

            norm = self._normalize_dnskey_rrset(ans)
            if norm:
                normalized[s] = norm

        if len(normalized) == 0:
            consistent = None
        else:
            consistent = (len(set(normalized.values())) == 1)

        return {
            "zone": zone,
            "nameservers": ns,
            "consistent_dnskey_rrset": consistent,  # True / False / None
            "per_ns": per_ns,
            "failures": failures,
            "normalized": normalized,
        }

    # ---- Per-authoritative checks (only called when DS exists) ----
    def check_authoritative_ns(self, server: str, zone: str) -> List[Finding]:
        findings: List[Finding] = []

        out = self.dig_dnssec_sections_tcp(server, zone, "DNSKEY")
        low = out.lower()

        fail = self._looks_like_query_failure(out)
        if fail:
            findings.append(
                Finding(
                    zone=zone,
                    server=server,
                    issue=fail,
                    repro=f"dig +dnssec +tcp @{server} {zone} DNSKEY +norecurse +noall +answer +authority",
                    detail_tail="\n".join(out.splitlines()[-60:]),
                )
            )
            return findings

        # DS exists => DNSKEY expected
        if " dnskey " not in low:
            findings.append(
                Finding(
                    zone=zone,
                    server=server,
                    issue="DNSKEY_NODATA",
                    repro=f"dig +dnssec +tcp @{server} {zone} DNSKEY +norecurse +noall +answer +authority +comments",
                    detail_tail="\n".join(out.splitlines()[-60:]),
                )
            )
            return findings

        findings.append(
            Finding(
                zone=zone,
                server=server,
                issue="OK",
                repro=f"dig +dnssec +tcp @{server} {zone} DNSKEY +norecurse +noall +answer",
                detail_tail="",
            )
        )
        return findings

    # ---- Zone scan ----
    def scan_zone(self, zone: str) -> ZoneResult:
        z = zone.rstrip(".") + "."
        ns = self.dig_ns(z)
        findings: List[Finding] = []

        # Validator probe (only flags bogus)
        v = self.delv_probe(z, "SOA")
        if v.get("status") == "bogus":
            findings.append(
                Finding(
                    zone=z,
                    server="(validator path)",
                    issue="DNSSEC_BOGUS",
                    repro=v.get("repro_cmd", ""),
                    detail_tail=v.get("detail", ""),
                )
            )

        parent = self._parent_zone(z)
        parent_signed = self._zone_has_dnskey(parent)

        # If parent isn't signed, child is not required. No warnings.
        if not parent_signed:
            if self.include_unsigned_finding:
                findings.append(
                    Finding(
                        zone=z,
                        server="(parent)",
                        issue="PARENT_UNSIGNED",
                        repro=f"dig +dnssec +tcp @<parent-ns> {parent} DNSKEY +norecurse +noall +answer",
                        detail_tail=f"Parent {parent} has no DNSKEY; not requiring DNSSEC for {z}.",
                    )
                )
            overall = "fail" if any(f.issue not in {"PARENT_UNSIGNED", "OK"} for f in findings) else "pass"
            return ZoneResult(zone=z, overall=overall, nameservers=ns, findings=findings, ns_consistency={})

        # Parent is signed -> check DS for child at parent
        has_ds, _ds_per_ns, ds_failures = self._parent_ds_status(parent, z)

        # If we can't determine DS, treat as infra error (fail)
        if has_ds is None:
            findings.append(
                Finding(
                    zone=z,
                    server="(parent authoritatives)",
                    issue="PARENT_DS_QUERY_FAILED",
                    repro=f"dig +dnssec +tcp @<parent-ns> {z} DS +norecurse +noall +answer +comments",
                    detail_tail=f"Could not query DS for {z} at parent {parent}. failures={ds_failures}",
                )
            )
            return ZoneResult(zone=z, overall="fail", nameservers=ns, findings=findings, ns_consistency={})

        # No DS => NOT required to be signed. No warnings.
        if has_ds is False:
            if self.include_unsigned_finding:
                findings.append(
                    Finding(
                        zone=z,
                        server="(parent authoritatives)",
                        issue="DNSSEC_UNSIGNED",
                        repro=f"dig +dnssec +tcp @<parent-ns> {z} DS +norecurse +noall +answer",
                        detail_tail=f"No DS at parent {parent}; {z} is not required to be DNSSEC-signed.",
                    )
                )
            overall = "fail" if any(f.issue not in {"DNSSEC_UNSIGNED", "OK"} for f in findings) else "pass"
            return ZoneResult(zone=z, overall=overall, nameservers=ns, findings=findings, ns_consistency={})

        # DS exists => child SHOULD be signed. Run DNSKEY checks.
        ns_consistency = self.compare_dnskey_across_ns(z)
        if ns_consistency.get("nameservers") and ns_consistency.get("consistent_dnskey_rrset") is False:
            findings.append(
                Finding(
                    zone=z,
                    server="(authoritatives)",
                    issue="DNSKEY_INCONSISTENT",
                    repro=f"dig +dnssec +tcp @<ns> {z} DNSKEY +norecurse +noall +answer",
                    detail_tail="DNSKEY differs across NS; see ns_consistency['per_ns'] for raw answers.",
                )
            )

        for s in ns:
            findings.extend(self.check_authoritative_ns(s, z))

        informational = {"OK"}
        has_error = any(f.issue not in informational for f in findings)
        overall = "fail" if has_error else "pass"

        return ZoneResult(zone=z, overall=overall, nameservers=ns, findings=findings, ns_consistency=ns_consistency)
