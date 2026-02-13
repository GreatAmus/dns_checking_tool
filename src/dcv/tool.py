from __future__ import annotations

import ipaddress
import random
import socket
import ssl
import string
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import dns.exception
import dns.resolver

from dnssec.models import Finding
from .models import DCVResult


@dataclass(frozen=True)
class _HTTPProbe:
    url: str
    status: Optional[int]
    final_url: str
    redirects: List[str]
    body: str = ""
    error: Optional[str] = None


class DCVTool:
    """
    DCV readiness checks aligned with modern BR validation methods:

    Website-based:
      - ACME HTTP-01 path readiness (/.well-known/acme-challenge/)
      - Non-ACME website change readiness (commonly /.well-known/pki-validation/)
      - Generic website change (user-specified path + expected content)

    DNS-based:
      - ACME DNS-01 (_acme-challenge.<domain> TXT)
      - BR 3.2.2.4.7 DNS Change (generic TXT or CNAME at specified name)
      - BR 3.2.2.4.22 Persistent DCV TXT (generic TXT at specified name)

    IP-based:
      - BR 3.2.2.5.1 Website change for IP (connect to IP directly)
      - BR 3.2.2.5.8 Persistent DCV TXT in reverse namespace (TXT at reverse name)

    Fast defaults:
      - short timeouts, limited redirects, minimal probes
    """

    def __init__(
        self,
        timeout_seconds: float = 2.5,
        max_redirects: int = 5,
        dns_timeout: float = 2.0,
        dns_lifetime: float = 2.0,
    ) -> None:
        self.timeout = float(timeout_seconds)
        self.max_redirects = int(max_redirects)

        self._resolver = dns.resolver.Resolver(configure=True)
        self._resolver.timeout = float(dns_timeout)
        self._resolver.lifetime = float(dns_lifetime)

    # -------------------------
    # Public API
    # -------------------------

    def check(
        self,
        domain: str,
        *,
        # ACME-style inputs (optional)
        expected_dns01_txt: Optional[str] = None,
        expected_http_body: Optional[str] = None,
        http_token: Optional[str] = None,

        # NEW: Website change (ACME + non-ACME + generic)
        # If you provide expected bodies, we verify exact match on final response.
        website_paths: Optional[List[str]] = None,
        website_expected: Optional[Dict[str, str]] = None,
        website_allow_404: bool = True,

        # NEW: BR 3.2.2.4.7 DNS Change (generic)
        dns_change_qname: Optional[str] = None,
        dns_change_type: str = "TXT",  # TXT or CNAME
        dns_change_expected: Optional[str] = None,

        # NEW: BR 3.2.2.4.22 Persistent DCV TXT (generic)
        persistent_txt_qname: Optional[str] = None,
        persistent_txt_expected: Optional[str] = None,

        # NEW: BR 3.2.2.5.1 + 3.2.2.5.8 (IP control methods)
        ip_address: Optional[str] = None,
        ip_website_path: Optional[str] = None,
        ip_website_expected: Optional[str] = None,
        reverse_persistent_expected: Optional[str] = None,

        # Which methods to run
        prefer_methods: Optional[List[str]] = None,
    ) -> DCVResult:
        """
        Run DCV checks for a domain (and optionally an IP address).
        """
        target = (domain or "").strip().rstrip(".")
        out = DCVResult(target=target)
        started = time.perf_counter()

        methods = [m.lower() for m in (prefer_methods or [
            "http01", "dns01", "alpn01",
            "website_change", "dns_change", "persistent_txt",
            "ip_website_change", "reverse_persistent_txt",
        ])]

        findings: List[Finding] = []

        # -------------------------
        # HTTP-01 (ACME)
        # -------------------------
        if "http01" in methods:
            f, meta = self._check_http01(target, expected_http_body, http_token)
            findings.extend(f)
            out.http01 = meta

        # -------------------------
        # DNS-01 (ACME)
        # -------------------------
        if "dns01" in methods:
            f, meta = self._check_dns01(target, expected_dns01_txt)
            findings.extend(f)
            out.dns01 = meta

        # -------------------------
        # TLS-ALPN-01 (ACME)
        # -------------------------
        if "alpn01" in methods:
            f, meta = self._check_alpn01(target)
            findings.extend(f)
            out.alpn01 = meta

        # -------------------------
        # Website Change (ACME + non-ACME readiness)
        # BR 3.2.2.5.1 also uses "website change" but for IP; handled below.
        # -------------------------
        if "website_change" in methods:
            f, meta = self._check_website_change(
                host=target,
                website_paths=website_paths,
                website_expected=website_expected,
                allow_404=website_allow_404,
            )
            findings.extend(f)
            out.website_change = meta

        # -------------------------
        # BR 3.2.2.4.7 DNS Change (generic: TXT or CNAME)
        # -------------------------
        if "dns_change" in methods:
            f, meta = self._check_dns_change(
                host=target,
                qname=dns_change_qname,
                rtype=dns_change_type,
                expected=dns_change_expected,
            )
            findings.extend(f)
            out.dns01.setdefault("extra", {})
            out.dns01["extra"]["dns_change"] = meta

        # -------------------------
        # BR 3.2.2.4.22 Persistent DCV TXT (generic)
        # -------------------------
        if "persistent_txt" in methods:
            f, meta = self._check_persistent_txt(
                host=target,
                qname=persistent_txt_qname,
                expected=persistent_txt_expected,
            )
            findings.extend(f)
            out.dns01.setdefault("extra", {})
            out.dns01["extra"]["persistent_txt"] = meta

        # -------------------------
        # BR 3.2.2.5.1 Agreed-Upon Change to Website (IP address)
        # -------------------------
        if "ip_website_change" in methods:
            f, meta = self._check_ip_website_change(
                ip=ip_address,
                path=ip_website_path,
                expected=ip_website_expected,
            )
            findings.extend(f)
            out.reverse_dns.setdefault("extra", {})
            out.reverse_dns["extra"]["ip_website_change"] = meta

        # -------------------------
        # BR 3.2.2.5.8 Persistent TXT in reverse namespace
        # -------------------------
        if "reverse_persistent_txt" in methods:
            f, meta = self._check_reverse_persistent_txt(
                ip=ip_address,
                expected=reverse_persistent_expected,
            )
            findings.extend(f)
            out.reverse_dns.setdefault("extra", {})
            out.reverse_dns["extra"]["reverse_persistent_txt"] = meta

        out.findings = findings

        sevs = [f.severity for f in findings]
        if "high" in sevs:
            out.overall = "broken"
        elif any(s in ("medium", "low") for s in sevs):
            out.overall = "warning"
        else:
            out.overall = "ok"

        # record total timing
        out.website_change.setdefault("timing_ms_total", int((time.perf_counter() - started) * 1000))
        return out

    # =========================================================
    # ACME HTTP-01
    # =========================================================

    def _check_http01(
        self,
        host: str,
        expected_body: Optional[str],
        token: Optional[str],
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"method": "http-01"}

        if not self._tcp_connect(host, 80):
            findings.append(Finding(
                zone=host,
                issue="HTTP01_PORT80_CLOSED",
                severity="high",
                detail="Could not connect to port 80 (HTTP). HTTP-01 validation requires port 80 to be reachable publicly.",
                data={"host": host, "port": 80},
            ))
            meta["port80"] = {"reachable": False}
            return findings, meta

        meta["port80"] = {"reachable": True}

        tok = token or self._rand_token()
        path = f"/.well-known/acme-challenge/{tok}"
        url = f"http://{host}{path}"

        probe = self._http_fetch(url, expected_body=expected_body)
        meta["probe"] = self._probe_to_dict(probe)

        if probe.error:
            findings.append(Finding(
                zone=host,
                issue="HTTP01_FETCH_FAILED",
                severity="high",
                detail=f"HTTP-01 probe failed fetching {url}: {probe.error}",
                data=meta["probe"],
            ))
            return findings, meta

        status = probe.status or 0
        if status in (401, 403):
            findings.append(Finding(
                zone=host,
                issue="HTTP01_BLOCKED_PATH",
                severity="high",
                detail="HTTP-01 challenge path appears blocked (401/403). Allow unauthenticated GET to /.well-known/acme-challenge/…",
                data={"status": status, "final_url": probe.final_url, "redirects": probe.redirects},
            ))
        elif 500 <= status <= 599:
            findings.append(Finding(
                zone=host,
                issue="HTTP01_SERVER_ERROR",
                severity="medium",
                detail="Server returned 5xx during HTTP-01 probe. Validation may be unreliable until the server is healthy.",
                data={"status": status, "final_url": probe.final_url},
            ))

        final_host = (urlparse(probe.final_url).hostname or "").lower()
        if final_host and final_host != host.lower():
            findings.append(Finding(
                zone=host,
                issue="HTTP01_REDIRECT_DIFFERENT_HOST",
                severity="medium",
                detail=f"HTTP-01 probe redirected from {host} to {final_host}. Prefer keeping validation on the same hostname.",
                data={"final_host": final_host, "final_url": probe.final_url, "redirects": probe.redirects},
            ))

        if len(probe.redirects) >= self.max_redirects:
            findings.append(Finding(
                zone=host,
                issue="HTTP01_REDIRECT_LOOP",
                severity="medium",
                detail="HTTP-01 probe hit the maximum redirect limit; a redirect loop may exist.",
                data={"redirects": probe.redirects, "final_url": probe.final_url},
            ))

        return findings, meta

    # =========================================================
    # ACME DNS-01
    # =========================================================

    def _check_dns01(self, host: str, expected_txt: Optional[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"method": "dns-01"}

        qname = f"_acme-challenge.{host}.".replace("..", ".")
        meta["qname"] = qname

        return self._query_txt(host, qname, expected_txt, findings, meta, prefix="DNS01")

    # =========================================================
    # TLS-ALPN-01
    # =========================================================

    def _check_alpn01(self, host: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"method": "tls-alpn-01"}

        if not self._tcp_connect(host, 443):
            findings.append(Finding(
                zone=host,
                issue="ALPN01_PORT443_CLOSED",
                severity="high",
                detail="Could not connect to port 443 (HTTPS). TLS-ALPN-01 requires port 443 to be reachable publicly.",
                data={"host": host, "port": 443},
            ))
            meta["port443"] = {"reachable": False}
            return findings, meta

        meta["port443"] = {"reachable": True}

        try:
            negotiated, tls_version = self._tls_handshake_alpn(host)
            meta["tls_version"] = tls_version
            meta["alpn_negotiated"] = negotiated

            if negotiated is None:
                findings.append(Finding(
                    zone=host,
                    issue="ALPN01_ALPN_UNSUPPORTED",
                    severity="medium",
                    detail="TLS handshake succeeded but no ALPN was negotiated. TLS-ALPN-01 requires ALPN support.",
                    data=meta,
                ))

        except ssl.SSLError as e:
            findings.append(Finding(
                zone=host,
                issue="ALPN01_TLS_HANDSHAKE_FAILED",
                severity="high",
                detail=f"TLS handshake failed on port 443: {e}",
                data={"host": host},
            ))
        except socket.timeout:
            findings.append(Finding(
                zone=host,
                issue="ALPN01_TIMEOUT",
                severity="medium",
                detail="Timed out during TLS handshake on port 443.",
                data={"host": host},
            ))
        except Exception as e:
            findings.append(Finding(
                zone=host,
                issue="ALPN01_ERROR",
                severity="medium",
                detail=f"Unexpected error during TLS-ALPN-01 probe: {type(e).__name__}: {e}",
                data={"host": host},
            ))

        return findings, meta

    def _tls_handshake_alpn(self, host: str) -> Tuple[Optional[str], str]:
        host_idna = host.encode("idna").decode("ascii")
        sock = socket.create_connection((host_idna, 443), timeout=self.timeout)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["acme-tls/1", "http/1.1"])

            ssock = ctx.wrap_socket(sock, server_hostname=host_idna)
            ssock.settimeout(self.timeout)

            negotiated = ssock.selected_alpn_protocol()
            version = ssock.version() or "unknown"

            ssock.close()
            return negotiated, version
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # =========================================================
    # Website Change readiness (ACME + non-ACME + generic)
    # =========================================================

    def _check_website_change(
        self,
        host: str,
        website_paths: Optional[List[str]],
        website_expected: Optional[Dict[str, str]],
        allow_404: bool,
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Implements readiness for:
          - "Agreed-Upon Change to Website" (non-ACME)
          - "Agreed-Upon Change to Website - ACME" (path readiness)
        """
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"method": "website-change", "host": host}

        # Default: check both well-known directories used in practice:
        # - ACME HTTP-01: /.well-known/acme-challenge/<token>
        # - Non-ACME: commonly /.well-known/pki-validation/<file>
        paths = website_paths or [
            "/.well-known/acme-challenge/",
            "/.well-known/pki-validation/",
        ]

        # Ensure port 80 reachable (website change is typically HTTP-based).
        if not self._tcp_connect(host, 80):
            findings.append(Finding(
                zone=host,
                issue="WEBSITE_CHANGE_PORT80_CLOSED",
                severity="high",
                detail="Could not connect to port 80. Website-change validation methods require the site to be reachable over HTTP.",
                data={"host": host, "port": 80},
            ))
            meta["port80"] = {"reachable": False}
            return findings, meta
        meta["port80"] = {"reachable": True}

        probes: List[Dict[str, Any]] = []

        for p in paths:
            path = p if p.startswith("/") else f"/{p}"
            # If path is a directory, append a random filename to detect blocking/WAF behavior.
            url = f"http://{host}{path}"
            expected = (website_expected or {}).get(p)

            # If the caller gave a directory path (endswith /), probe with a random file as well.
            if url.endswith("/"):
                url = url + self._rand_token(10)

            probe = self._http_fetch(url, expected_body=expected)
            probes.append(self._probe_to_dict(probe))

            if probe.error:
                findings.append(Finding(
                    zone=host,
                    issue="WEBSITE_CHANGE_FETCH_FAILED",
                    severity="high",
                    detail=f"Website-change probe failed fetching {url}: {probe.error}",
                    data={"url": url, "probe": self._probe_to_dict(probe)},
                ))
                continue

            status = probe.status or 0

            # If caller provided expected content and it didn't match, _http_fetch will return error.
            if status in (401, 403):
                findings.append(Finding(
                    zone=host,
                    issue="WEBSITE_CHANGE_PATH_BLOCKED",
                    severity="high",
                    detail=(
                        "Website-change validation path appears blocked (401/403). "
                        "Allow unauthenticated GET access to the CA/ACME validation path under .well-known."
                    ),
                    data={"url": url, "status": status, "final_url": probe.final_url, "redirects": probe.redirects},
                ))
            elif status == 404 and not allow_404 and expected is not None:
                # If user expects content at an exact path, 404 is a failure.
                findings.append(Finding(
                    zone=host,
                    issue="WEBSITE_CHANGE_NOT_FOUND",
                    severity="high",
                    detail="Expected website-change content was not found (404). Publish the validation file/token at the exact path.",
                    data={"url": url, "final_url": probe.final_url},
                ))
            elif 500 <= status <= 599:
                findings.append(Finding(
                    zone=host,
                    issue="WEBSITE_CHANGE_SERVER_ERROR",
                    severity="medium",
                    detail="Server returned 5xx while probing a website-change validation path.",
                    data={"url": url, "status": status, "final_url": probe.final_url},
                ))

        meta["probes"] = probes
        return findings, meta

    # =========================================================
    # BR 3.2.2.4.7 DNS Change (generic)
    # =========================================================

    def _check_dns_change(
        self,
        host: str,
        qname: Optional[str],
        rtype: str,
        expected: Optional[str],
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Generic DNS Change: verify a CA-provided name has the expected TXT or CNAME value.

        If qname is not provided, we can’t guess it (CA-specific),
        so we return a medium "not configured" finding (optional) instead of failing the domain.
        """
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"method": "dns-change", "rtype": rtype}

        if not qname:
            meta["skipped"] = True
            meta["reason"] = "No dns_change_qname provided (CA-specific name required)."
            return findings, meta

        fqdn = qname.rstrip(".") + "."
        meta["qname"] = fqdn

        rtype_u = (rtype or "TXT").strip().upper()
        if rtype_u not in ("TXT", "CNAME"):
            findings.append(Finding(
                zone=host,
                issue="DNS_CHANGE_BAD_TYPE",
                severity="medium",
                detail="dns_change_type must be TXT or CNAME.",
                data={"provided": rtype},
            ))
            return findings, meta

        if rtype_u == "TXT":
            return self._query_txt(host, fqdn, expected, findings, meta, prefix="DNS_CHANGE")

        # CNAME
        try:
            ans = self._resolver.resolve(fqdn, "CNAME", raise_on_no_answer=False)
            values: List[str] = []
            if ans.rrset:
                for r in ans:
                    values.append(str(r.target).rstrip(".").lower())
            meta["cname_values"] = values

            if not values:
                findings.append(Finding(
                    zone=host,
                    issue="DNS_CHANGE_CNAME_MISSING",
                    severity="high",
                    detail=f"No CNAME record found at {fqdn}.",
                    data={"qname": fqdn},
                ))
                return findings, meta

            if expected is not None:
                exp = expected.rstrip(".").lower()
                if exp not in values:
                    findings.append(Finding(
                        zone=host,
                        issue="DNS_CHANGE_CNAME_MISMATCH",
                        severity="high",
                        detail=f"CNAME exists at {fqdn} but does not match expected value.",
                        data={"qname": fqdn, "expected": exp, "values": values},
                    ))

        except dns.resolver.NXDOMAIN:
            findings.append(Finding(
                zone=host,
                issue="DNS_CHANGE_NXDOMAIN",
                severity="high",
                detail=f"{fqdn} does not exist (NXDOMAIN). Create the required DNS Change record.",
                data={"qname": fqdn},
            ))
        except dns.exception.Timeout:
            findings.append(Finding(
                zone=host,
                issue="DNS_CHANGE_TIMEOUT",
                severity="medium",
                detail=f"Timed out querying {rtype_u} at {fqdn}.",
                data={"qname": fqdn},
            ))
        except Exception as e:
            findings.append(Finding(
                zone=host,
                issue="DNS_CHANGE_QUERY_FAILED",
                severity="medium",
                detail=f"Failed querying {rtype_u} at {fqdn}: {type(e).__name__}: {e}",
                data={"qname": fqdn},
            ))

        return findings, meta

    # =========================================================
    # BR 3.2.2.4.22 Persistent DCV TXT (generic)
    # =========================================================

    def _check_persistent_txt(
        self,
        host: str,
        qname: Optional[str],
        expected: Optional[str],
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"method": "persistent-txt"}

        if not qname:
            meta["skipped"] = True
            meta["reason"] = "No persistent_txt_qname provided (CA-specific name required)."
            return findings, meta

        fqdn = qname.rstrip(".") + "."
        meta["qname"] = fqdn

        return self._query_txt(host, fqdn, expected, findings, meta, prefix="PERSISTENT_TXT")

    # =========================================================
    # BR 3.2.2.5.1 Website change for IP address
    # =========================================================

    def _check_ip_website_change(
        self,
        ip: Optional[str],
        path: Optional[str],
        expected: Optional[str],
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"method": "ip-website-change"}

        if not ip:
            meta["skipped"] = True
            meta["reason"] = "No ip_address provided."
            return findings, meta

        try:
            ip_obj = ipaddress.ip_address(ip)
            meta["ip"] = str(ip_obj)
        except Exception:
            findings.append(Finding(
                zone=str(ip),
                issue="IP_WEBSITE_CHANGE_BAD_IP",
                severity="medium",
                detail="ip_address is not a valid IPv4/IPv6 address.",
                data={"ip": ip},
            ))
            return findings, meta

        # Website change for IP requires a CA-specified URL path and token. We can only check readiness unless provided.
        p = (path or "/.well-known/pki-validation/").strip()
        if not p.startswith("/"):
            p = "/" + p
        if p.endswith("/"):
            p = p + self._rand_token(10)

        url = f"http://{ip}{p}"
        probe = self._http_fetch(url, expected_body=expected, sni_host=None)  # direct-to-IP; no SNI
        meta["probe"] = self._probe_to_dict(probe)

        if probe.error:
            findings.append(Finding(
                zone=str(ip),
                issue="IP_WEBSITE_CHANGE_FETCH_FAILED",
                severity="high",
                detail=f"Failed probing website-change over IP at {url}: {probe.error}",
                data=meta["probe"],
            ))
            return findings, meta

        status = probe.status or 0
        if status in (401, 403):
            findings.append(Finding(
                zone=str(ip),
                issue="IP_WEBSITE_CHANGE_BLOCKED",
                severity="high",
                detail="Website-change over IP appears blocked (401/403). The validation path must be publicly readable.",
                data={"url": url, "status": status},
            ))
        elif 500 <= status <= 599:
            findings.append(Finding(
                zone=str(ip),
                issue="IP_WEBSITE_CHANGE_SERVER_ERROR",
                severity="medium",
                detail="Server returned 5xx while probing website-change over IP.",
                data={"url": url, "status": status},
            ))

        return findings, meta

    # =========================================================
    # BR 3.2.2.5.8 Reverse namespace persistent TXT
    # =========================================================

    def _check_reverse_persistent_txt(
        self,
        ip: Optional[str],
        expected: Optional[str],
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"method": "reverse-persistent-txt"}

        if not ip:
            meta["skipped"] = True
            meta["reason"] = "No ip_address provided."
            return findings, meta

        try:
            ip_obj = ipaddress.ip_address(ip)
        except Exception:
            findings.append(Finding(
                zone=str(ip),
                issue="REVERSE_PTXT_BAD_IP",
                severity="medium",
                detail="ip_address is not a valid IPv4/IPv6 address.",
                data={"ip": ip},
            ))
            return findings, meta

        # ipaddress provides reverse_pointer as the PTR name; we need TXT at that name.
        reverse_name = ip_obj.reverse_pointer.rstrip(".") + "."
        meta["reverse_name"] = reverse_name

        return self._query_txt(str(ip_obj), reverse_name, expected, findings, meta, prefix="REVERSE_PTXT")

    # =========================================================
    # Shared TXT query helper
    # =========================================================

    def _query_txt(
        self,
        zone_label: str,
        qname: str,
        expected_txt: Optional[str],
        findings: List[Finding],
        meta: Dict[str, Any],
        *,
        prefix: str,
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        try:
            ans = self._resolver.resolve(qname, "TXT", raise_on_no_answer=False)
            values: List[str] = []
            if ans.rrset:
                for r in ans:
                    try:
                        strings = getattr(r, "strings", None)
                        if strings:
                            values.append(b"".join(strings).decode("utf-8", errors="replace"))
                        else:
                            values.append(str(r).strip('"'))
                    except Exception:
                        values.append(str(r).strip('"'))

            meta["txt_values"] = values

            if not values:
                findings.append(Finding(
                    zone=zone_label,
                    issue=f"{prefix}_TXT_MISSING",
                    severity="high",
                    detail=f"No TXT record found at {qname}.",
                    data={"qname": qname},
                ))
                return findings, meta

            if expected_txt is not None and expected_txt not in values:
                findings.append(Finding(
                    zone=zone_label,
                    issue=f"{prefix}_TXT_MISMATCH",
                    severity="high",
                    detail=f"TXT exists at {qname}, but none of the values matched the expected value.",
                    data={"qname": qname, "expected": expected_txt, "values": values},
                ))
            elif expected_txt is None and len(values) > 1:
                findings.append(Finding(
                    zone=zone_label,
                    issue=f"{prefix}_TXT_MULTIPLE",
                    severity="low",
                    detail=f"Multiple TXT values exist at {qname}. Remove outdated validation tokens when possible.",
                    data={"qname": qname, "values": values},
                ))

        except dns.resolver.NXDOMAIN:
            findings.append(Finding(
                zone=zone_label,
                issue=f"{prefix}_NXDOMAIN",
                severity="high",
                detail=f"{qname} does not exist (NXDOMAIN).",
                data={"qname": qname},
            ))
        except dns.exception.Timeout:
            findings.append(Finding(
                zone=zone_label,
                issue=f"{prefix}_TIMEOUT",
                severity="medium",
                detail=f"Timed out querying TXT at {qname}.",
                data={"qname": qname},
            ))
        except Exception as e:
            findings.append(Finding(
                zone=zone_label,
                issue=f"{prefix}_QUERY_FAILED",
                severity="medium",
                detail=f"Failed querying TXT at {qname}: {type(e).__name__}: {e}",
                data={"qname": qname},
            ))

        return findings, meta

    # =========================================================
    # HTTP helpers
    # =========================================================

    def _probe_to_dict(self, p: _HTTPProbe) -> Dict[str, Any]:
        return {
            "url": p.url,
            "status": p.status,
            "final_url": p.final_url,
            "redirects": p.redirects,
            "error": p.error,
        }

    def _http_fetch(self, url: str, *, expected_body: Optional[str], sni_host: Optional[str] = "auto") -> _HTTPProbe:
        redirects: List[str] = []
        current = url

        for _ in range(self.max_redirects):
            parsed = urlparse(current)
            scheme = (parsed.scheme or "http").lower()
            host = parsed.hostname or ""
            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"

            # For direct-IP probes, caller passes sni_host=None
            sni = host if (sni_host == "auto") else sni_host

            try:
                status, headers, body = self._raw_http_request(scheme, host, port, path, sni_host=sni)
            except Exception as e:
                return _HTTPProbe(url=url, status=None, final_url=current, redirects=redirects, error=f"{type(e).__name__}: {e}")

            if expected_body is not None:
                if status != 200:
                    if status in (301, 302, 303, 307, 308):
                        pass
                    else:
                        return _HTTPProbe(url=url, status=status, final_url=current, redirects=redirects, error=f"Expected 200, got {status}")
                else:
                    if body != expected_body:
                        return _HTTPProbe(url=url, status=status, final_url=current, redirects=redirects, error="Body did not match expected content")

            if status in (301, 302, 303, 307, 308):
                loc = headers.get("location")
                if not loc:
                    break
                redirects.append(current)
                current = urljoin(current, loc)
                continue

            return _HTTPProbe(url=url, status=status, final_url=current, redirects=redirects, body=body, error=None)

        return _HTTPProbe(url=url, status=None, final_url=current, redirects=redirects, error=None)

    def _raw_http_request(self, scheme: str, host: str, port: int, path: str, *, sni_host: Optional[str]) -> Tuple[int, Dict[str, str], str]:
        host_idna = host.encode("idna").decode("ascii")
        addr = (host_idna, port)

        sock = socket.create_connection(addr, timeout=self.timeout)
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # sni_host=None disables SNI (useful for direct-IP probes)
                sock = ctx.wrap_socket(sock, server_hostname=(sni_host.encode("idna").decode("ascii") if sni_host else None))

            sock.settimeout(self.timeout)

            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host_idna}\r\n"
                f"User-Agent: dns-checking-tool/0.1 (dcv)\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(req.encode("utf-8"))

            raw = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
        finally:
            try:
                sock.close()
            except Exception:
                pass

        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if not lines:
            raise ValueError("Empty HTTP response")

        status_line = lines[0].decode("latin1", errors="replace")
        parts = status_line.split()
        if len(parts) < 2:
            raise ValueError(f"Bad status line: {status_line}")

        status = int(parts[1])
        headers: Dict[str, str] = {}
        for ln in lines[1:]:
            try:
                k, v = ln.split(b":", 1)
                headers[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()
            except Exception:
                continue

        try:
            body_txt = body.decode("utf-8", errors="replace")
        except Exception:
            body_txt = ""

        return status, headers, body_txt

    # =========================================================
    # Utilities
    # =========================================================

    def _tcp_connect(self, host: str, port: int) -> bool:
        host_idna = host.encode("idna").decode("ascii")
        try:
            with socket.create_connection((host_idna, port), timeout=self.timeout):
                return True
        except Exception:
            return False

    def _rand_token(self, n: int = 24) -> str:
        alphabet = string.ascii_letters + string.digits + "-_"
        return "".join(random.choice(alphabet) for _ in range(n))
