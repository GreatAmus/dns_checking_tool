from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.dnssec
import dns.exception

from dnssec_models import Finding


@dataclass
class DelegationInfo:
    parent: str
    parent_signed: bool
    ds_rrset_text: Optional[str] = None
    ds_records: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.ds_records is None:
            self.ds_records = []


class DNSSECChecks:
    """
    All DNSSEC checks live here.
    The scanner calls these and aggregates Findings.
    """

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout

    # ---------- Basic helpers ----------

    def _parent_zone(self, zone: str) -> str:
        n = dns.name.from_text(zone).canonicalize()
        if len(n) <= 1:
            return "."
        return str(n.parent())

    def _resolve_ns(self, zone: str) -> List[str]:
        ans = self._resolver.resolve(zone, "NS")
        # dnspython returns names with trailing dot; normalize without dot for consistency
        return sorted({str(r.target).rstrip(".") for r in ans})

    def _udp_query(self, server: str, qname: str, qtype: str, want_dnssec: bool = True):
        msg = dns.message.make_query(
            qname,
            qtype,
            want_dnssec=want_dnssec,
            use_edns=True,
            payload=1232,
        )
        return dns.query.udp(msg, server, timeout=self.timeout)

    def _tcp_query(self, server: str, qname: str, qtype: str, want_dnssec: bool = True):
        msg = dns.message.make_query(
            qname,
            qtype,
            want_dnssec=want_dnssec,
            use_edns=True,
            payload=1232,
        )
        return dns.query.tcp(msg, server, timeout=self.timeout)

    def _query_auth(self, server: str, qname: str, qtype: str):
        """
        Try UDP, fall back to TCP if truncated.
        """
        try:
            r = self._udp_query(server, qname, qtype, want_dnssec=True)
            if r.flags & dns.flags.TC:
                r = self._tcp_query(server, qname, qtype, want_dnssec=True)
            return r
        except Exception as e:
            raise e

    # ---------- Delegation / chain-of-trust ----------

    def check_parent_signed_and_ds(self, zone: str) -> Tuple[DelegationInfo, List[Finding]]:
        findings: List[Finding] = []
        z = zone.rstrip(".") + "."
        parent = self._parent_zone(z)

        # Is parent signed? (has DNSKEY)
        parent_signed = False
        try:
            dnskey = self._resolver.resolve(parent, "DNSKEY")
            parent_signed = len(list(dnskey)) > 0
        except Exception:
            parent_signed = False

        info = DelegationInfo(parent=parent.rstrip("."), parent_signed=parent_signed)

        if not parent_signed:
            findings.append(
                Finding(
                    zone=zone,
                    issue="PARENT_UNSIGNED",
                    severity="info",
                    detail=f"Parent zone {parent} did not appear to publish DNSKEY; DNSSEC may not be required at delegation.",
                )
            )
            return info, findings

        # Query DS for child at parent (via recursive resolver is ok for presence,
        # but if you want strict, query parent auths; this is the pragmatic start)
        try:
            ds_ans = self._resolver.resolve(z, "DS")
            ds_list = []
            for r in ds_ans:
                ds_list.append(
                    {
                        "key_tag": r.key_tag,
                        "algorithm": r.algorithm,
                        "digest_type": r.digest_type,
                        "digest": r.digest.hex() if hasattr(r.digest, "hex") else str(r.digest),
                    }
                )
            info.ds_records = ds_list
            info.ds_rrset_text = "\n".join([r.to_text() for r in ds_ans])
        except dns.resolver.NXDOMAIN:
            findings.append(
                Finding(zone=zone, issue="DS_NXDOMAIN", severity="error", detail="Parent returned NXDOMAIN for DS query.")
            )
            return info, findings
        except dns.resolver.NoAnswer:
            findings.append(
                Finding(
                    zone=zone,
                    issue="DS_MISSING",
                    severity="warning",
                    detail=f"Parent {parent} is signed but no DS record exists for {z}.",
                )
            )
            return info, findings
        except Exception as e:
            findings.append(
                Finding(
                    zone=zone,
                    issue="PARENT_DS_QUERY_FAILED",
                    severity="error",
                    detail=f"Failed to query DS at parent: {type(e).__name__}: {e}",
                )
            )
            return info, findings

        if not info.ds_records:
            findings.append(
                Finding(zone=zone, issue="DS_MISSING", severity="warning", detail="No DS records returned.")
            )

        return info, findings

    def check_ds_matches_dnskey(self, zone: str, ds_records: List[Dict[str, Any]]) -> List[Finding]:
        """
        Compute DS from child DNSKEY(s) and compare to parent DS RR.
        """
        findings: List[Finding] = []
        z = zone.rstrip(".") + "."

        try:
            dnskey_ans = self._resolver.resolve(z, "DNSKEY")
        except Exception as e:
            findings.append(
                Finding(zone=zone, issue="DNSKEY_QUERY_FAILED", severity="error", detail=f"DNSKEY query failed: {e}")
            )
            return findings

        # Build rrset for dnspython DS computation
        dnskey_rrset = dnskey_ans.rrset
        if dnskey_rrset is None:
            findings.append(Finding(zone=zone, issue="DNSKEY_NODATA", severity="error", detail="No DNSKEY RRset."))
            return findings

        computed = []
        for r in dnskey_rrset:
            # compute DS for common digest types 2 (SHA-256) and 4 (SHA-384)
            for digest_type in (2, 4):
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
                    detail="Could not compute DS from DNSKEY (unsupported key/digest?).",
                )
            )
            return findings

        # compare
        parent_set = {(d["key_tag"], d["algorithm"], d["digest_type"], d["digest"].lower()) for d in ds_records}
        child_set = {(d["key_tag"], d["algorithm"], d["digest_type"], d["digest"].lower()) for d in computed}

        if parent_set.isdisjoint(child_set):
            findings.append(
                Finding(
                    zone=zone,
                    issue="DS_MISMATCH",
                    severity="error",
                    detail="Parent DS does not match any DS computed from current DNSKEY.",
                    data={"parent_ds": ds_records, "computed_ds": computed},
                )
            )
        return findings

    # ---------- Signature validation ----------

    def validate_rrsig_for_rrset(self, zone: str, rrtype: str) -> List[Finding]:
        """
        Validate RRSIG(rrtype) for zone apex using DNSKEY.
        Validates cryptographically using dnspython.
        """
        findings: List[Finding] = []
        z = zone.rstrip(".") + "."

        try:
            dnskey_ans = self._resolver.resolve(z, "DNSKEY")
            dnskey_rrset = dnskey_ans.rrset
        except Exception as e:
            findings.append(Finding(zone=zone, issue="DNSKEY_QUERY_FAILED", severity="error", detail=str(e)))
            return findings

        if dnskey_rrset is None:
            findings.append(Finding(zone=zone, issue="DNSKEY_NODATA", severity="error", detail="No DNSKEY RRset."))
            return findings

        # query target rrset with dnssec
        try:
            ans = self._resolver.resolve(z, rrtype, raise_on_no_answer=False)
            rrset = ans.rrset
            rrsig = None
            if ans.response and ans.response.answer:
                # find RRSIG in answer section for rrtype
                for rr in ans.response.answer:
                    if rr.rdtype == dns.rdatatype.RRSIG and dns.rdatatype.to_text(rr.covers) == rrtype:
                        rrsig = rr
                        break
        except dns.resolver.NoAnswer:
            rrset = None
            rrsig = None
        except Exception as e:
            findings.append(
                Finding(zone=zone, issue=f"{rrtype}_QUERY_FAILED", severity="error", detail=f"{type(e).__name__}: {e}")
            )
            return findings

        if rrset is None:
            findings.append(
                Finding(zone=zone, issue=f"{rrtype}_NODATA", severity="warning", detail=f"No {rrtype} RRset at apex.")
            )
            return findings

        if rrsig is None:
            findings.append(
                Finding(zone=zone, issue=f"{rrtype}_RRSIG_MISSING", severity="error", detail=f"Missing RRSIG for {rrtype}.")
            )
            return findings

        # Build key dict for validate()
        key_dict = {dns.name.from_text(z): dnskey_rrset}

        try:
            dns.dnssec.validate(rrset, rrsig, key_dict)
        except dns.dnssec.ValidationFailure as e:
            findings.append(
                Finding(
                    zone=zone,
                    issue=f"{rrtype}_RRSIG_INVALID",
                    severity="error",
                    detail=f"RRSIG validation failed for {rrtype}: {e}",
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    zone=zone,
                    issue=f"{rrtype}_RRSIG_VALIDATE_ERROR",
                    severity="error",
                    detail=f"Unexpected validation error for {rrtype}: {type(e).__name__}: {e}",
                )
            )

        # Timing sanity (inception/expiration) is embedded in dnspython validation,
        # but if you want explicit outputs, parse rrsig fields here.

        return findings

    # ---------- Denial of existence ----------

    def validate_denial_of_existence(self, zone: str) -> List[Finding]:
        """
        Basic check: query a random non-existent name under zone and ensure response includes
        signed NSEC/NSEC3 proof (presence check + signature validation where possible).
        """
        findings: List[Finding] = []
        z = zone.rstrip(".") + "."

        qname = f"__dnssec_probe_{random.randint(100000, 999999)}.{z}"
        try:
            resp = self._resolver.resolve(qname, "A", raise_on_no_answer=False)
            # We want NXDOMAIN, or NODATA with proofs. If it returned A, unexpected wildcard exists.
            if resp.rrset is not None and len(resp.rrset) > 0:
                findings.append(
                    Finding(
                        zone=zone,
                        issue="WILDCARD_PRESENT",
                        severity="info",
                        detail="Random non-existent name returned records (wildcard likely present).",
                        data={"qname": qname},
                    )
                )
                return findings
        except dns.resolver.NXDOMAIN:
            # NXDOMAIN is fine, now check the response content for NSEC/NSEC3 in authority
            # dnspython's resolver hides the message; do a direct query to get authority.
            pass
        except Exception as e:
            findings.append(
                Finding(zone=zone, issue="NX_PROBE_FAILED", severity="warning", detail=f"{type(e).__name__}: {e}")
            )
            return findings

        # direct query (recursive, but yields authority proofs typically)
        try:
            msg = dns.message.make_query(qname, "A", want_dnssec=True)
            # Use system resolver’s first nameserver
            ns = self._resolver.nameservers[0]
            m = dns.query.udp(msg, ns, timeout=self.timeout)
        except Exception as e:
            findings.append(Finding(zone=zone, issue="NX_PROBE_QUERY_FAILED", severity="warning", detail=str(e)))
            return findings

        # Presence check for NSEC/NSEC3 + RRSIG
        auth = m.authority or []
        has_nsec = any(rr.rdtype == dns.rdatatype.NSEC for rr in auth)
        has_nsec3 = any(rr.rdtype == dns.rdatatype.NSEC3 for rr in auth)
        has_rrsig = any(rr.rdtype == dns.rdatatype.RRSIG for rr in auth)

        if not (has_nsec or has_nsec3):
            findings.append(
                Finding(
                    zone=zone,
                    issue="DENIAL_PROOF_MISSING",
                    severity="error",
                    detail="NXDOMAIN response did not include NSEC/NSEC3 proof in authority section.",
                    data={"qname": qname},
                )
            )
            return findings

        if not has_rrsig:
            findings.append(
                Finding(
                    zone=zone,
                    issue="DENIAL_RRSIG_MISSING",
                    severity="error",
                    detail="Denial proof present but no RRSIG in authority section.",
                    data={"qname": qname},
                )
            )

        # Full cryptographic validation of denial proofs is more involved (requires chasing NSEC3 params),
        # but the presence checks above catch many real breakages. You can extend later.

        return findings
