from __future__ import annotations

import concurrent.futures
import time
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

from dnssec.models import Finding
from .models import DNSHealthResult


class DNSHealthTool:
    """
    Fast DNS "health" checks for delegation + authoritative correctness.

    Design goals:
      - fast: small timeouts + parallel probing of authoritative servers
      - actionable: produces Finding(issue=..., severity=..., detail=..., data=...)
      - DNSSEC-agnostic: focuses on *misconfiguration* rather than signature validity
    """

    def __init__(
        self,
        timeout: float = 2.0,
        lifetime: float = 2.0,
        max_workers: int = 12,
        edns_payload: int = 1232,
        per_ns_ip_limit: int = 1,
    ) -> None:
        self.timeout = float(timeout)
        self.lifetime = float(lifetime)
        self.max_workers = int(max_workers)
        self.edns_payload = int(edns_payload)
        self.per_ns_ip_limit = int(per_ns_ip_limit)

        # Recursive resolver used for *discovery* (delegation NS, NS A/AAAA).
        self._resolver = dns.resolver.Resolver(configure=True)
        self._resolver.timeout = self.timeout
        self._resolver.lifetime = self.lifetime

    # ----------------------------
    # Public entrypoint
    # ----------------------------

    def check_zone(self, zone: str) -> DNSHealthResult:
        z = (zone or "").strip().rstrip(".").lower()
        fqdn = z + "."

        out = DNSHealthResult(zone=z)
        started = time.perf_counter()

        # 1) Delegation NS hostnames (via recursive resolver)
        ns_names, ns_lookup_meta = self._lookup_ns(fqdn)
        out.observations["delegation_ns_lookup"] = ns_lookup_meta
        out.nameservers = ns_names

        if not ns_names:
            out.findings.append(
                Finding(
                    zone=z,
                    issue="NO_NAMESERVERS",
                    severity="high",
                    detail="No NS records were found for the zone via recursive lookup.",
                    data={"qname": fqdn, **ns_lookup_meta},
                )
            )
            out.overall = "broken"
            out.observations["timing_ms"] = int((time.perf_counter() - started) * 1000)
            return out

        # 2) Resolve NS hostnames to IPs (A/AAAA)
        ns_to_ips: Dict[str, List[str]] = {}
        ip_errors: Dict[str, str] = {}
        for ns in ns_names:
            ips, err = self._resolve_ns_ips(ns)
            if ips:
                ns_to_ips[ns] = ips[: self.per_ns_ip_limit]
            else:
                ns_to_ips[ns] = []
                if err:
                    ip_errors[ns] = err

        out.nameserver_ips = ns_to_ips

        if all(not ips for ips in ns_to_ips.values()):
            out.findings.append(
                Finding(
                    zone=z,
                    issue="AUTH_NS_IP_LOOKUP_FAILED",
                    severity="high",
                    detail="Delegated nameservers exist, but none of their hostnames resolved to an IP address.",
                    data={"nameservers": ns_names, "errors": ip_errors},
                )
            )
            out.overall = "broken"
            out.observations["timing_ms"] = int((time.perf_counter() - started) * 1000)
            return out

        # If some NS names do not resolve, warn (but keep going).
        for ns, ips in ns_to_ips.items():
            if not ips:
                out.findings.append(
                    Finding(
                        zone=z,
                        issue="NS_NAME_NO_ADDRESS",
                        severity="medium",
                        server=ns,
                        detail="Delegated NS hostname did not resolve to A/AAAA.",
                        data={"nameserver": ns, "error": ip_errors.get(ns, "")},
                    )
                )

        # 3) Probe authoritative servers directly (RD=0) in parallel.
        probes = self._probe_authoritative(z, ns_to_ips)
        out.observations["authoritative_probes"] = probes["meta"]

        # Availability/lame aggregation
        auth_ok = [p for p in probes["per_ns"] if p.get("authoritative_ok")]
        auth_bad = [p for p in probes["per_ns"] if not p.get("authoritative_ok")]

        if not auth_ok:
            out.findings.append(
                Finding(
                    zone=z,
                    issue="NO_AUTHORITATIVE_REACHABLE",
                    severity="high",
                    detail="None of the delegated nameservers returned an authoritative SOA response for the zone.",
                    data={"probes": probes["per_ns"]},
                )
            )
            out.overall = "broken"
            out.observations["timing_ms"] = int((time.perf_counter() - started) * 1000)
            return out

        if auth_bad:
            out.findings.append(
                Finding(
                    zone=z,
                    issue="NS_PARTIAL_OUTAGE",
                    severity="low",
                    detail="Some delegated nameservers did not respond authoritatively (timeout/lame/refused).",
                    data={"bad": auth_bad},
                )
            )

        # Baseline child NS RRset from first authoritative-good server
        baseline_child_ns: Optional[List[str]] = None
        for p in probes["per_ns"]:
            if p.get("authoritative_ok") and p.get("child_ns"):
                baseline_child_ns = sorted([x.rstrip(".").lower() for x in p["child_ns"]])
                break

        # Per-nameserver issues
        for p in probes["per_ns"]:
            ns = p.get("ns")
            ip = p.get("ip")

            label = f"{ns} ({ip})" if ns and ip else (ns or "")

            # Reachability errors (timeouts, etc.)
            if p.get("error"):
                out.findings.append(
                    Finding(
                        zone=z,
                        issue="NS_UNREACHABLE",
                        severity="medium",
                        server=label,
                        detail="Nameserver did not respond to authoritative probes.",
                        data={"probe": p},
                    )
                )
                continue

            # Lame delegation / not authoritative
            if not p.get("authoritative_ok"):
                out.findings.append(
                    Finding(
                        zone=z,
                        issue="LAME_DELEGATION",
                        severity="high",
                        server=label,
                        detail="Nameserver responded but did not appear authoritative for the zone (AA=0 or no SOA).",
                        data={"probe": p},
                    )
                )
                continue

            # Apex CNAME (generally invalid)
            if p.get("apex_cname"):
                out.findings.append(
                    Finding(
                        zone=z,
                        issue="APEX_CNAME",
                        severity="high",
                        server=label,
                        detail="Zone apex returned a CNAME. This is generally invalid and breaks many resolvers/tools.",
                        data={"cname": p.get("apex_cname"), "probe": p},
                    )
                )

            # EDNS brokenness (EDNS fails but non-EDNS works)
            if p.get("edns_broken"):
                out.findings.append(
                    Finding(
                        zone=z,
                        issue="EDNS_BROKEN",
                        severity="low",
                        server=label,
                        detail="Server appears to mishandle EDNS(0). This can cause timeouts or truncation issues.",
                        data={"probe": p},
                    )
                )

            # TCP fallback when UDP truncates
            if p.get("udp_truncated") and p.get("tcp_ok") is False:
                out.findings.append(
                    Finding(
                        zone=z,
                        issue="TCP_FALLBACK_BROKEN",
                        severity="medium",
                        server=label,
                        detail="UDP response was truncated (TC=1) but TCP fallback failed.",
                        data={"probe": p},
                    )
                )

            # Large UDP response heuristic (fragmentation risk)
            if isinstance(p.get("udp_size"), int) and p["udp_size"] > self.edns_payload:
                out.findings.append(
                    Finding(
                        zone=z,
                        issue="UDP_RESPONSE_LARGE",
                        severity="info",
                        server=label,
                        detail=(
                            f"UDP response size {p['udp_size']} bytes exceeds {self.edns_payload}; "
                            "fragmentation/middlebox issues possible."
                        ),
                        data={"probe": p},
                    )
                )

            # Authoritative servers disagree on child NS RRset
            child = sorted([x.rstrip(".").lower() for x in (p.get("child_ns") or [])])
            if child and baseline_child_ns and child != baseline_child_ns:
                out.findings.append(
                    Finding(
                        zone=z,
                        issue="NS_INCONSISTENT",
                        severity="low",
                        server=label,
                        detail="Authoritative servers disagree on the child NS RRset; this can cause flakiness.",
                        data={
                            "baseline_child_ns": baseline_child_ns,
                            "this_child_ns": child,
                            "probe": p,
                        },
                    )
                )

        # Parent/child mismatch: delegation NS vs authoritative NS
        if baseline_child_ns:
            delegation_set = sorted([x.rstrip(".").lower() for x in ns_names])
            if delegation_set != baseline_child_ns:
                out.findings.append(
                    Finding(
                        zone=z,
                        issue="NS_PARENT_CHILD_MISMATCH",
                        severity="low",
                        detail="Delegation NS set (parent view) differs from the zone's authoritative NS RRset (child view).",
                        data={"delegation": delegation_set, "authoritative": baseline_child_ns},
                    )
                )

        # Overall classification
        severities = [f.severity for f in out.findings]
        if "high" in severities:
            out.overall = "broken"
        elif "medium" in severities or "low" in severities:
            out.overall = "warning"
        else:
            out.overall = "ok"

        out.observations["timing_ms"] = int((time.perf_counter() - started) * 1000)
        return out

    # ----------------------------
    # Discovery helpers
    # ----------------------------

    def _lookup_ns(self, fqdn: str) -> Tuple[List[str], Dict[str, Any]]:
        """Recursive NS lookup for the zone."""
        meta: Dict[str, Any] = {"qname": fqdn, "qtype": "NS"}
        try:
            ans = self._resolver.resolve(fqdn, "NS", raise_on_no_answer=False)
            meta["rcode"] = getattr(getattr(ans, "response", None), "rcode", lambda: None)()
            ns = [str(r.target).rstrip(".").lower() for r in (ans.rrset or [])]
            return sorted(set(ns)), meta
        except dns.resolver.NXDOMAIN:
            meta["error"] = "NXDOMAIN"
            return [], meta
        except dns.exception.Timeout:
            meta["error"] = "TIMEOUT"
            return [], meta
        except Exception as e:
            meta["error"] = f"ERROR: {type(e).__name__}: {e}"
            return [], meta

    def _resolve_ns_ips(self, ns_name: str) -> Tuple[List[str], Optional[str]]:
        """Resolve a nameserver hostname to A/AAAA addresses."""
        fqdn = ns_name.rstrip(".") + "."
        ips: List[str] = []
        try:
            for rtype in ("A", "AAAA"):
                try:
                    ans = self._resolver.resolve(fqdn, rtype, raise_on_no_answer=False)
                    if ans.rrset:
                        ips.extend([str(r.address) for r in ans])
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except dns.exception.Timeout:
                    continue
            ips = [ip for ip in ips if ip]
            return ips, None if ips else "No A/AAAA records"
        except Exception as e:
            return [], f"{type(e).__name__}: {e}"

    # ----------------------------
    # Authoritative probing
    # ----------------------------

    def _probe_authoritative(self, zone: str, ns_to_ips: Dict[str, List[str]]) -> Dict[str, Any]:
        """Probe each nameserver (first IP by default) in parallel."""
        jobs: List[Tuple[str, str]] = []
        for ns, ips in ns_to_ips.items():
            for ip in ips[: self.per_ns_ip_limit]:
                jobs.append((ns, ip))

        meta: Dict[str, Any] = {
            "timeout": self.timeout,
            "lifetime": self.lifetime,
            "edns_payload": self.edns_payload,
            "jobs": len(jobs),
        }

        per_ns: List[Dict[str, Any]] = []
        if not jobs:
            return {"meta": meta, "per_ns": per_ns}

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, len(jobs))) as ex:
            futs = [ex.submit(self._probe_one, zone, ns, ip) for (ns, ip) in jobs]
            for f in concurrent.futures.as_completed(futs):
                try:
                    per_ns.append(f.result())
                except Exception as e:
                    per_ns.append({"authoritative_ok": False, "error": f"{type(e).__name__}: {e}"})

        per_ns.sort(key=lambda d: (str(d.get("ns")), str(d.get("ip"))))
        return {"meta": meta, "per_ns": per_ns}

    def _probe_one(self, zone: str, ns: str, ip: str) -> Dict[str, Any]:
        """Probe a single authoritative server for a few behaviors."""
        result: Dict[str, Any] = {"ns": ns, "ip": ip}
        fqdn = zone.rstrip(".") + "."

        # SOA query (authoritativeness check)
        soa_udp = self._query_udp(ip, fqdn, dns.rdatatype.SOA, use_edns=True)
        result.update({"soa_udp": soa_udp.get("meta", {})})

        if soa_udp.get("error"):
            result["error"] = soa_udp["error"]
            result["authoritative_ok"] = False
            return result

        result["udp_size"] = soa_udp.get("size")
        result["udp_truncated"] = bool(soa_udp.get("tc"))
        result["rcode"] = soa_udp.get("rcode")
        result["aa"] = bool(soa_udp.get("aa"))

        soa_in_answer = bool(soa_udp.get("has_soa"))
        result["authoritative_ok"] = bool(result["aa"] and soa_in_answer and result.get("rcode") == "NOERROR")

        if soa_udp.get("edns_broken"):
            result["edns_broken"] = True

        # Child NS query (for mismatch detection)
        ns_udp = self._query_udp(ip, fqdn, dns.rdatatype.NS, use_edns=True)
        if not ns_udp.get("error") and ns_udp.get("rcode") == "NOERROR":
            result["child_ns"] = ns_udp.get("rrset", [])

        # Apex CNAME check
        cname_udp = self._query_udp(ip, fqdn, dns.rdatatype.CNAME, use_edns=True)
        if not cname_udp.get("error") and cname_udp.get("rcode") == "NOERROR":
            rr = cname_udp.get("rrset", [])
            if rr:
                result["apex_cname"] = rr

        # TCP fallback: only if UDP truncates
        if result["udp_truncated"]:
            tcp = self._query_tcp(ip, fqdn, dns.rdatatype.SOA, use_edns=True)
            result["tcp_ok"] = bool(not tcp.get("error") and tcp.get("rcode") == "NOERROR")

        return result

    # ----------------------------
    # Raw DNS query helpers
    # ----------------------------

    def _make_query(self, qname: str, rdatatype: dns.rdatatype.RdataType, *, use_edns: bool) -> dns.message.Message:
        m = dns.message.make_query(qname, rdatatype)
        # Authoritative probing: do NOT request recursion.
        m.flags &= ~dns.flags.RD
        if use_edns:
            m.use_edns(edns=0, payload=self.edns_payload)
        return m

    def _query_udp(
        self,
        server_ip: str,
        qname: str,
        rdatatype: dns.rdatatype.RdataType,
        *,
        use_edns: bool,
    ) -> Dict[str, Any]:
        """UDP query with an EDNS sanity fallback."""
        meta: Dict[str, Any] = {"transport": "udp", "qname": qname, "qtype": dns.rdatatype.to_text(rdatatype)}

        # First try: with EDNS
        q1 = self._make_query(qname, rdatatype, use_edns=use_edns)
        try:
            r1 = dns.query.udp(q1, server_ip, timeout=self.timeout)
            wire = r1.to_wire(max_size=65535)
            meta.update({"edns": bool(use_edns)})
            return self._parse_response(r1, wire, meta)
        except dns.exception.Timeout:
            return {"error": "TIMEOUT", "meta": meta}
        except dns.exception.FormError:
            # Broken servers that choke on EDNS: retry without EDNS once.
            if use_edns:
                q2 = self._make_query(qname, rdatatype, use_edns=False)
                try:
                    r2 = dns.query.udp(q2, server_ip, timeout=self.timeout)
                    wire = r2.to_wire(max_size=65535)
                    parsed = self._parse_response(r2, wire, {**meta, "edns": False})
                    parsed["edns_broken"] = True
                    return parsed
                except Exception as e2:
                    return {"error": f"FORMERR_then_{type(e2).__name__}", "meta": meta, "edns_broken": True}
            return {"error": "FORMERR", "meta": meta}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}", "meta": meta}

    def _query_tcp(
        self,
        server_ip: str,
        qname: str,
        rdatatype: dns.rdatatype.RdataType,
        *,
        use_edns: bool,
    ) -> Dict[str, Any]:
        meta: Dict[str, Any] = {"transport": "tcp", "qname": qname, "qtype": dns.rdatatype.to_text(rdatatype)}
        q = self._make_query(qname, rdatatype, use_edns=use_edns)
        try:
            r = dns.query.tcp(q, server_ip, timeout=self.timeout)
            wire = r.to_wire(max_size=65535)
            meta.update({"edns": bool(use_edns)})
            return self._parse_response(r, wire, meta)
        except dns.exception.Timeout:
            return {"error": "TIMEOUT", "meta": meta}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}", "meta": meta}

    def _parse_response(self, msg: dns.message.Message, wire: bytes, meta: Dict[str, Any]) -> Dict[str, Any]:
        rcode = dns.rcode.to_text(msg.rcode())
        aa = bool(msg.flags & dns.flags.AA)
        tc = bool(msg.flags & dns.flags.TC)

        rrset_txt: List[str] = []
        has_soa = False
        try:
            for rrset in msg.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    has_soa = True
                for rdata in rrset:
                    rrset_txt.append(rdata.to_text())
        except Exception:
            pass

        return {
            "rcode": rcode,
            "aa": aa,
            "tc": tc,
            "size": len(wire) if isinstance(wire, (bytes, bytearray)) else None,
            "rrset": rrset_txt,
            "has_soa": has_soa,
            "meta": meta,
        }
