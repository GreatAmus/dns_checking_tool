# dnssec_checks.py
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rcode
import dns.resolver

from dnssec_models import Finding


@dataclass
class DelegationInfo:
    parent: str
    ds_present: bool
    ds_records: List[Dict[str, Any]]
    ds_rrset_text: Optional[str] = None


class DNSSECChecks:
    """
    DNSSEC checks designed to report legitimate DNSSEC issues.

    Key behaviors:
      - DS is fetched from the parent zone's authoritative servers and may appear in ANSWER or AUTHORITY.
      - DNSKEY is fetched from the child zone's authoritative servers (by IP) using EDNS+DO + TCP fallback.
      - DNSKEY results are cached to avoid duplicate/ repeated failures.
      - DS mismatch is computed using *KSKs only* (DNSKEY with SEP bit set).
      - RRSIG validation failures (dns.dnssec.ValidationFailure) are reported as *_RRSIG_INVALID (not "unexpected error").
      - Missing 'cryptography' becomes VALIDATION_UNAVAILABLE (environment issue, not DNS misconfig).
    """

    def __init__(self, timeout: float = 8.0, strict_dnssec: bool = False):
        self.timeout = float(timeout)
        self.strict_dnssec = bool(strict_dnssec)

        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = self.timeout
        self._resolver.lifetime = self.timeout

        # Per-instance caches
        self._ns_cache: Dict[str, List[str]] = {}
        self._ips_cache: Dict[str, List[str]] = {}
        self._auth_ip_cache: Dict[str, List[str]] = {}
        # zone_fqdn -> (dnskey_rrset, server_ip_used, debug_detail_if_missing)
        self._dnskey_cache: Dict[str, Tuple[Optional[Any], Optional[str], Optional[str]]] = {}

    # ------------------------- helpers -------------------------

    @staticmethod
    def _fqdn(name: str) -> str:
        return name.strip().rstrip(".") + "."

    @staticmethod
    def _parent_zone(zone_fqdn: str) -> str:
        n = dns.name.from_text(zone_fqdn).canonicalize()
        if len(n) <= 1:
            return "."
        return str(n.parent())

    def _resolve_ns_names(self, zone_fqdn: str) -> List[str]:
        if zone_fqdn in self._ns_cache:
            return self._ns_cache[zone_fqdn]
        ans = self._resolver.resolve(zone_fqdn, "NS")
        ns = sorted({str(r.target).rstrip(".") for r in ans})
        self._ns_cache[zone_fqdn] = ns
        return ns

    def _resolve_ips(self, host: str) -> List[str]:
        if host in self._ips_cache:
            return self._ips_cache[host]

        ips: List[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                a = self._resolver.resolve(host, rdtype)
                ips.extend([r.address for r in a])
            except Exception:
                pass

        seen = set()
        out: List[str] = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)

        self._ips_cache[host] = out
        return out

    def _authoritative_server_ips(self, zone_fqdn: str) -> List[str]:
        if zone_fqdn in self._auth_ip_cache:
            return self._auth_ip_cache[zone_fqdn]

        ips: List[str] = []
        for ns in self._resolve_ns_names(zone_fqdn):
            ips.extend(self._resolve_ips(ns))

        seen = set()
        out: List[str] = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)

        self._auth_ip_cache[zone_fqdn] = out
        return out

    def _make_query(self, qname: str, qtype: str) -> dns.message.Message:
        return dns.message.make_query(
            qname,
            qtype,
            want_dnssec=True,
            use_edns=True,
            payload=1232,
        )

    def _query(self, server_ip: str, qname: str, qtype: str) -> dns.message.Message:
        msg = self._make_query(qname, qtype)
        resp = dns.query.udp(msg, server_ip, timeout=self.timeout)
        if resp.flags & dns.flags.TC:
            resp = dns.query.tcp(msg, server_ip, timeout=self.timeout)
        return resp

    @staticmethod
    def _debug_resp(resp: dns.message.Message) -> str:
        return (
            f"AA={bool(resp.flags & dns.flags.AA)} "
            f"rcode={dns.rcode.to_text(resp.rcode())} "
            f"answer_rrsets={len(resp.answer)} authority_rrsets={len(resp.authority)} additional_rrsets={len(resp.additional)}"
        )

    @staticmethod
    def _first_rrset_in_answer(resp: dns.message.Message, rdtype_text: str) -> Optional[Any]:
        want = dns.rdatatype.from_text(rdtype_text)
        for rrset in resp.answer:
            if rrset.rdtype == want:
                return rrset
        return None

    @staticmethod
    def _rrsets_answer_or_authority(resp: dns.message.Message, rdtype_text: str) -> List[Any]:
        want = dns.rdatatype.from_text(rdtype_text)
        rrsets = [rr for rr in resp.answer if rr.rdtype == want]
        if not rrsets:
            rrsets = [rr for rr in resp.authority if rr.rdtype == want]
        return rrsets

    # ------------------------- delegation / DS -------------------------

    def get_delegation_ds(self, zone: str) -> Tuple[DelegationInfo, List[Finding]]:
        """
        Query the parent zone's authoritative servers for DS(zone).

        - DS can appear in ANSWER or AUTHORITY.
        - If no DS exists, we treat the delegation as unsigned.
          * strict_dnssec=False -> DNSSEC_NOT_ENABLED (info)
          * strict_dnssec=True  -> DS_MISSING (error)
        """
        findings: List[Finding] = []

        child = self._fqdn(zone)
        parent = self._parent_zone(child)

        parent_auth_ips = self._authoritative_server_ips(parent)
        if not parent_auth_ips:
            findings.append(
                Finding(
                    zone=zone,
                    issue="PARENT_NS_IP_LOOKUP_FAILED",
                    severity="error",
                    detail=f"Could not resolve parent authoritative server IPs for {parent}.",
                )
            )
            return DelegationInfo(parent=parent.rstrip("."), ds_present=False, ds_records=[]), findings

        last_debug: Optional[str] = None
        last_exc: Optional[str] = None

        for ip in parent_auth_ips[:10]:
            try:
                resp = self._query(ip, child, "DS")
                last_debug = self._debug_resp(resp)

                ds_rrsets = self._rrsets_answer_or_authority(resp, "DS")
                if not ds_rrsets:
                    continue

                ds_list: List[Dict[str, Any]] = []
                for rrset in ds_rrsets:
                    for r in rrset:
                        ds_list.append(
                            {
                                "key_tag": r.key_tag,
                                "algorithm": r.algorithm,
                                "digest_type": r.digest_type,
                                "digest": r.digest.hex(),
                            }
                        )

                info = DelegationInfo(
                    parent=parent.rstrip("."),
                    ds_present=True,
                    ds_records=ds_list,
                    ds_rrset_text="\n".join(rrset.to_text() for rrset in ds_rrsets),
                )
                return info, findings
            except Exception as e:
                last_exc = f"{type(e).__name__}: {e} (server={ip})"
                continue

        # No DS returned by any parent server
        issue = "DS_MISSING" if self.strict_dnssec else "DNSSEC_NOT_ENABLED"
        severity = "error" if self.strict_dnssec else "info"

        findings.append(
            Finding(
                zone=zone,
                issue=issue,
                severity=severity,
                server=parent_auth_ips[0],
                repro=f"dig +dnssec DS {child} @{parent_auth_ips[0]}",
                detail=(
                    f"No DS record was returned by parent ({parent}) authoritative servers for {child}. "
                    f"This indicates an unsigned delegation."
                    + (f" {last_debug}" if last_debug else "")
                    + (f" Last error: {last_exc}" if last_exc else "")
                ).strip(),
            )
        )

        return DelegationInfo(parent=parent.rstrip("."), ds_present=False, ds_records=[]), findings

    # ------------------------- DNSKEY from child auth -------------------------

    def get_dnskey_rrset(self, zone: str) -> Tuple[Optional[Any], Optional[str], Optional[str]]:
        """
        Returns (dnskey_rrset, server_ip_used, debug_if_missing).
        Cached per zone to avoid duplicate repeated failures.
        """
        z = self._fqdn(zone)
        if z in self._dnskey_cache:
            return self._dnskey_cache[z]

        auth_ips = self._authoritative_server_ips(z)
        if not auth_ips:
            out = (None, None, "No authoritative server IPs found for zone.")
            self._dnskey_cache[z] = out
            return out

        last_detail: Optional[str] = None

        for ip in auth_ips[:10]:
            try:
                resp = self._query(ip, z, "DNSKEY")
                dnskey_rrset = self._first_rrset_in_answer(resp, "DNSKEY")

                if dnskey_rrset is None:
                    last_detail = f"DNSKEY missing from answer. {self._debug_resp(resp)} server={ip}"
                    continue

                if not (resp.flags & dns.flags.AA):
                    last_detail = f"DNSKEY present but AA=0. {self._debug_resp(resp)} server={ip}"
                    continue

                out = (dnskey_rrset, ip, None)
                self._dnskey_cache[z] = out
                return out

            except Exception as e:
                last_detail = f"{type(e).__name__}: {e} (server={ip})"
                continue

        out = (None, auth_ips[0], last_detail or "DNSKEY query failed on all authoritative servers.")
        self._dnskey_cache[z] = out
        return out

    # ------------------------- DS matches DNSKEY -------------------------

    def check_ds_matches_dnskey(self, zone: str, ds_records: List[Dict[str, Any]]) -> List[Finding]:
        """
        Compute DS from current DNSKEY KSK(s) (SEP=1) and ensure at least one matches parent DS.
        """
        findings: List[Finding] = []
        z = self._fqdn(zone)

        dnskey_rrset, ip, debug = self.get_dnskey_rrset(zone)
        if dnskey_rrset is None:
            findings.append(
                Finding(
                    zone=zone,
                    issue="DNSKEY_QUERY_FAILED",
                    severity="error",
                    server=ip,
                    repro=(f"dig +dnssec DNSKEY {z} @{ip}" if ip else None),
                    detail=f"Authoritative DNSKEY query returned no DNSKEY rrset. {debug or ''}".strip(),
                )
            )
            return findings

        computed: List[Dict[str, Any]] = []
        for r in dnskey_rrset:
            # DS should be computed from KSK(s): DNSKEY with SEP bit set.
            if not (r.flags & 0x0001):
                continue

            for digest_type in (2, 4):  # SHA-256, SHA-384
                try:
                    ds = dns.dnssec.make_ds(dns.name.from_text(z), r, digest_type)
                    computed.append(
                        {
                            "key_tag": ds.key_tag,
                            "algorithm": ds.algorithm,
                            "digest_type": ds.digest_type,
                            "digest": ds.digest.hex(),
                        }
                    )
                except Exception:
                    continue

        if not computed:
            findings.append(
                Finding(
                    zone=zone,
                    issue="DS_COMPUTE_FAILED",
                    severity="error",
                    detail="Could not compute DS from DNSKEY KSK(s) (no SEP keys found or unsupported key/digest).",
                )
            )
            return findings

        parent_set = {(d["key_tag"], d["algorithm"], d["digest_type"], d["digest"].lower()) for d in ds_records}
        child_set = {(d["key_tag"], d["algorithm"], d["digest_type"], d["digest"].lower()) for d in computed}

        if parent_set.isdisjoint(child_set):
            findings.append(
                Finding(
                    zone=zone,
                    issue="DS_MISMATCH",
                    severity="error",
                    detail="Parent DS does not match any DS computed from current DNSKEY KSK(s).",
                    data={"parent_ds": ds_records, "computed_ds": computed},
                )
            )
        return findings

    # ------------------------- RRSIG validation -------------------------

    def validate_rrsig_for_rrset(self, zone: str, rrtype: str) -> List[Finding]:
        """
        Fetch {rrtype} rrset at zone apex from authoritative servers and validate its RRSIG
        using the zone DNSKEY rrset.
        """
        findings: List[Finding] = []
        z = self._fqdn(zone)

        # DNSKEY is required for any signature validation.
        dnskey_rrset, dnskey_ip, dnskey_debug = self.get_dnskey_rrset(zone)
        if dnskey_rrset is None:
            findings.append(
                Finding(
                    zone=zone,
                    issue="DNSKEY_QUERY_FAILED",
                    severity="error",
                    server=dnskey_ip,
                    repro=(f"dig +dnssec DNSKEY {z} @{dnskey_ip}" if dnskey_ip else None),
                    detail=f"Authoritative DNSKEY query returned no DNSKEY rrset. {dnskey_debug or ''}".strip(),
                )
            )
            return findings

        auth_ips = self._authoritative_server_ips(z)
        if not auth_ips:
            findings.append(
                Finding(
                    zone=zone,
                    issue=f"{rrtype}_QUERY_FAILED",
                    severity="error",
                    detail="Could not determine authoritative server IPs for zone.",
                )
            )
            return findings

        want_type = dns.rdatatype.from_text(rrtype)

        rrset: Optional[Any] = None
        rrsig: Optional[Any] = None
        server_ip_used: Optional[str] = None
        last_debug: Optional[str] = None
        last_exc: Optional[str] = None

        # Query authoritative servers until we get an authoritative answer containing the rrset.
        for ip in auth_ips[:10]:
            try:
                resp = self._query(ip, z, rrtype)
                last_debug = self._debug_resp(resp)

                if not (resp.flags & dns.flags.AA):
                    continue

                rrset = None
                rrsig = None

                for a in resp.answer:
                    if a.rdtype == want_type:
                        rrset = a
                    if a.rdtype == dns.rdatatype.RRSIG and dns.rdatatype.to_text(a.covers) == rrtype:
                        rrsig = a

                if rrset is not None:
                    server_ip_used = ip
                    break

            except Exception as e:
                last_exc = f"{type(e).__name__}: {e} (server={ip})"
                continue

        # If no rrset, it's not necessarily a DNSSEC issue; it could be missing data.
        if rrset is None:
            findings.append(
                Finding(
                    zone=zone,
                    issue=f"{rrtype}_NODATA",
                    severity="warning",
                    server=auth_ips[0],
                    repro=f"dig +dnssec {rrtype} {z} @{auth_ips[0]}",
                    detail=(
                        f"No authoritative {rrtype} RRset at apex. "
                        + (f"{last_debug} " if last_debug else "")
                        + (f"Last error: {last_exc}" if last_exc else "")
                    ).strip(),
                )
            )
            return findings

        # If rrset exists but RRSIG missing, that *is* a DNSSEC issue for a signed zone.
        if rrsig is None:
            findings.append(
                Finding(
                    zone=zone,
                    issue=f"{rrtype}_RRSIG_MISSING",
                    severity="error",
                    server=server_ip_used or auth_ips[0],
                    repro=(f"dig +dnssec {rrtype} {z} @{server_ip_used}" if server_ip_used else f"dig +dnssec {rrtype} {z} @{auth_ips[0]}"),
                    detail=f"Missing RRSIG covering {rrtype}.",
                )
            )
            return findings

        key_dict = {dns.name.from_text(z): dnskey_rrset}

        try:
            dns.dnssec.validate(rrset, rrsig, key_dict)

        except dns.dnssec.ValidationFailure as e:
            # Legit DNSSEC misconfiguration: signature(s) present but none validate.
            findings.append(
                Finding(
                    zone=zone,
                    issue=f"{rrtype}_RRSIG_INVALID",
                    severity="error",
                    server=server_ip_used or auth_ips[0],
                    repro=(f"dig +dnssec {rrtype} {z} @{server_ip_used}" if server_ip_used else f"dig +dnssec {rrtype} {z} @{auth_ips[0]}"),
                    detail=f"RRSIG validation failed for {rrtype}: {e}",
                )
            )

        except ImportError as e:
            # Environment problem (missing cryptography), not a DNS misconfiguration.
            findings.append(
                Finding(
                    zone=zone,
                    issue="VALIDATION_UNAVAILABLE",
                    severity="error",
                    server=server_ip_used or auth_ips[0],
                    repro=(f"dig +dnssec {rrtype} {z} @{server_ip_used}" if server_ip_used else f"dig +dnssec {rrtype} {z} @{auth_ips[0]}"),
                    detail=f"Signature validation unavailable in this deployment: {e}. Install 'cryptography' to enable DNSSEC validation.",
                )
            )

        except Exception as e:
            findings.append(
                Finding(
                    zone=zone,
                    issue=f"{rrtype}_RRSIG_VALIDATE_ERROR",
                    severity="error",
                    server=server_ip_used or auth_ips[0],
                    repro=(f"dig +dnssec {rrtype} {z} @{server_ip_used}" if server_ip_used else f"dig +dnssec {rrtype} {z} @{auth_ips[0]}"),
                    detail=f"Unexpected validation error for {rrtype}: {type(e).__name__}: {e}",
                )
            )

        return findings

    # ------------------------- denial of existence (basic) -------------------------

    def validate_denial_of_existence(self, zone: str) -> List[Finding]:
        """
        Best-effort check that an NXDOMAIN/NODATA response includes NSEC/NSEC3 (+ RRSIG).
        """
        findings: List[Finding] = []
        z = self._fqdn(zone)

        auth_ips = self._authoritative_server_ips(z)
        if not auth_ips:
            findings.append(
                Finding(
                    zone=zone,
                    issue="NX_PROBE_FAILED",
                    severity="warning",
                    detail="Could not determine authoritative server IPs for NXDOMAIN probe.",
                )
            )
            return findings

        qname = f"__dnssec_probe_{random.randint(100000, 999999)}.{z}"

        resp: Optional[dns.message.Message] = None
        server_ip_used: Optional[str] = None
        last_exc: Optional[str] = None

        for ip in auth_ips[:10]:
            try:
                r = self._query(ip, qname, "A")
                if r.flags & dns.flags.AA:
                    resp = r
                    server_ip_used = ip
                    break
            except Exception as e:
                last_exc = f"{type(e).__name__}: {e} (server={ip})"
                continue

        if resp is None:
            findings.append(
                Finding(
                    zone=zone,
                    issue="NX_PROBE_QUERY_FAILED",
                    severity="warning",
                    server=auth_ips[0],
                    repro=f"dig +dnssec A {qname} @{auth_ips[0]}",
                    detail=f"NX probe query failed. {last_exc or ''}".strip(),
                )
            )
            return findings

        auth = resp.authority or []
        has_nsec = any(rr.rdtype == dns.rdatatype.NSEC for rr in auth)
        has_nsec3 = any(rr.rdtype == dns.rdatatype.NSEC3 for rr in auth)
        has_rrsig = any(rr.rdtype == dns.rdatatype.RRSIG for rr in auth)

        if not (has_nsec or has_nsec3):
            findings.append(
                Finding(
                    zone=zone,
                    issue="DENIAL_PROOF_MISSING",
                    severity="error",
                    server=server_ip_used or auth_ips[0],
                    repro=(f"dig +dnssec A {qname} @{server_ip_used}" if server_ip_used else f"dig +dnssec A {qname} @{auth_ips[0]}"),
                    detail="NXDOMAIN/NODATA response did not include NSEC/NSEC3 proof in authority section.",
                    data={"qname": qname, "debug": self._debug_resp(resp)},
                )
            )
            return findings

        if not has_rrsig:
            findings.append(
                Finding(
                    zone=zone,
                    issue="DENIAL_RRSIG_MISSING",
                    severity="error",
                    server=server_ip_used or auth_ips[0],
                    repro=(f"dig +dnssec A {qname} @{server_ip_used}" if server_ip_used else f"dig +dnssec A {qname} @{auth_ips[0]}"),
                    detail="Denial proof present but no RRSIG in authority section.",
                    data={"qname": qname, "debug": self._debug_resp(resp)},
                )
            )

        return findings
