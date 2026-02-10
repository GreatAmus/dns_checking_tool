"""
DNSSEC scanning logic.
High-level behavior:
- Determine whether a zone is DNSSEC-signed (presence of DS record via a recursive resolver).
- If unsigned: do not run DNSKEY checks (prevents false positives).
- If signed: query each authoritative server for DNSKEY-related signals and run basic consistency checks.

Important semantics:
- "DNSKEY_MISSING" should only be used when we *expect* DNSKEY (signed delegation) and the query
  succeeds but returns no DNSKEY records.
- If the query fails (timeout/refused): record the failure instead of claiming missing.
- "DNSKEY_INCONSISTENT" is only emitted when ≥2 authoritative servers returned DNSKEY RRsets
  and those RRsets differ after normalization/sorting.
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
        dns_resolver_for_ds: str = "8.8.8.8",
        cmd_timeout_seconds: int = 20,
        include_unsigned_finding: bool = True,
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

    def dig_answer(self, server: str, name: str, rtype: str) -> str:
        return self.dig([f"@{server}", name, rtype, "+dnssec", "+noall", "+answer"])

    def dig_dnssec_sections(self, server: str, name: str, rtype: str) -> str:
        return self.dig([f"@{server}", name, rtype, "+dnssec", "+noall", "+answer", "+authority", "+comments"])

    # ---- DNSSEC signed/unsigned gate ----
    def is_dnssec_signed(self, zone: str) -> bool:
        z = zone.strip()
        if not z.endswith("."):
            z += "."
        out = self.dig([f"@{self.dns_resolver_for_ds}", z, "DS", "+dnssec", "+noall", "+answer"])
        return bool(re.search(r"\sDS\s", out))

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
            # Strip owner/ttl/class; keep stable "DNSKEY <flags> <proto> <alg> <key...>"
            if len(parts) >= 6 and parts[2].upper() == "IN" and parts[3].upper() == "DNSKEY":
                ln = " ".join([parts[3]] + parts[4:])
            lines.append(ln)
        return "\n".join(sorted(lines))

    @staticmethod
    def _looks_like_query_failure(ans: str) -> Optional[str]:
        low = (ans or "").lower()
        if (ans or "").startswith("[timeout") or "no servers could be reached" in low or "connection timed out" in low:
            return "NS_UNREACHABLE"
        if "refused" in low:
            return "NS_REFUSED"
        return None

    def compare_dnskey_across_ns(self, zone: str) -> Dict[str, Any]:
        ns = self.dig_ns(zone)
        per_ns: Dict[str, str] = {}
        normalized: Dict[str, str] = {}
        failures: Dict[str, str] = {}

        for s in ns:
            ans = (self.dig_answer(s, zone, "DNSKEY") or "").strip()
            per_ns[s] = ans

            fail = self._looks_like_query_failure(ans)
            if fail:
                failures[s] = fail
                continue

            norm = self._normalize_dnskey_rrset(ans)
            if norm:
                normalized[s] = norm

        # If nobody returned DNSKEY lines, don't claim inconsistency
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

    # ---- Per-authoritative checks ----
    def check_authoritative_ns(self, server: str, zone: str) -> List[Finding]:
        findings: List[Finding] = []

        out = self.dig_dnssec_sections(server, zone, "DNSKEY")
        low = out.lower()

        # classify query failure FIRST
        if out.startswith("[timeout") or "no servers could be reached" in low or "connection timed out" in low:
            findings.append(Finding(
                zone=zone, server=server, issue="NS_UNREACHABLE",
                repro=f"dig +dnssec @{server} {zone} DNSKEY +noall +answer +authority",
                detail_tail="\n".join(out.splitlines()[-60:]),
            ))
            return findings

        if "refused" in low:
            findings.append(Finding(
                zone=zone, server=server, issue="NS_REFUSED",
                repro=f"dig +dnssec @{server} {zone} DNSKEY +noall +answer +authority",
                detail_tail="\n".join(out.splitlines()[-60:]),
            ))
            return findings

        # If we didn't get any DNSKEY lines, this is NODATA (common for unsigned zones, but those should be gated out)
        if " dnskey " not in low:
            findings.append(Finding(
                zone=zone, server=server, issue="DNSKEY_NODATA",
                repro=f"dig +dnssec @{server} {zone} DNSKEY +noall +answer +authority +comments",
                detail_tail="\n".join(out.splitlines()[-60:]),
            ))
            return findings

        # If DNSKEY exists, we consider it OK for presence
        findings.append(Finding(
            zone=zone, server=server, issue="OK",
            repro=f"dig +dnssec @{server} {zone} DNSKEY +noall +answer",
            detail_tail="",
        ))
        return findings

    # ---- Zone scan ----
    def scan_zone(self, zone: str) -> ZoneResult:
        z = zone.rstrip(".") + "."
        ns = self.dig_ns(z)
        findings: List[Finding] = []

        # Validator probe
        v = self.delv_probe(z, "SOA")
        if v.get("status") == "bogus":
            findings.append(Finding(
                zone=z, server="(validator path)", issue="DNSSEC_BOGUS",
                repro=v.get("repro_cmd", ""), detail_tail=v.get("detail", "")
            ))

        # Gate DNSKEY checks for unsigned zones
        if not self.is_dnssec_signed(z):
            if self.include_unsigned_finding:
                findings.append(Finding(
                    zone=z, server="(resolver)", issue="DNSSEC_UNSIGNED",
                    repro=f"dig @{self.dns_resolver_for_ds} {z} DS +dnssec +noall +answer",
                    detail_tail="No DS returned by resolver; zone is not DNSSEC-signed. Skipping DNSKEY checks."
                ))
            overall = "fail" if any(f.issue not in {"DNSSEC_UNSIGNED", "OK"} for f in findings) else "pass"
            return ZoneResult(zone=z, overall=overall, nameservers=ns, findings=findings, ns_consistency={})

        ns_consistency = self.compare_dnskey_across_ns(z)
        if ns_consistency.get("nameservers") and ns_consistency.get("consistent_dnskey_rrset") is False:
            findings.append(Finding(
                zone=z, server="(authoritatives)", issue="DNSKEY_INCONSISTENT",
                repro=f"dig +dnssec @<ns> {z} DNSKEY +noall +answer",
                detail_tail="DNSKEY differs across NS; see ns_consistency['per_ns'] for raw answers.",
            ))

        for s in ns:
            findings.extend(self.check_authoritative_ns(s, z))

        informational = {"DNSSEC_UNSIGNED", "OK"}
        has_error = any(f.issue not in informational for f in findings)
        overall = "fail" if has_error else "pass"

        return ZoneResult(zone=z, overall=overall, nameservers=ns, findings=findings, ns_consistency=ns_consistency)
