from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import dns.flags
import dns.message
import dns.query
import dns.rcode


@dataclass
class DNSQueryResult:
    qname: str
    qtype: str
    rcode: str
    answers: List[str]
    ttl_min: Optional[int]
    flags: Dict[str, bool]
    validated: bool
    error: Optional[str] = None
    resolver_mode: str = "unbound"


class UnboundValidatingResolver:
    """
    Query a recursive resolver (typically your local Unbound) and report:
      - rcode
      - answers
      - AD/CD flags
      - validated=True if AD is set AND we did not ask for CD (checking-disabled)

    IMPORTANT:
      - "validated=False" does NOT necessarily mean "bad"; it just means we didn't
        get an AD=1 validated response.
      - If Unbound returns SERVFAIL for CD=0 but works for CD=1, that indicates
        DNSSEC validation failure on that lookup path.
    """

    mode = "unbound"

    def __init__(
        self,
        ip: str = "127.0.0.1",
        port: int = 5053,
        timeout: float = 2.0,
        lifetime: float = 2.0,
        use_tcp: bool = False,
    ) -> None:
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.lifetime = lifetime
        self.use_tcp = use_tcp

    def query(self, qname: str, qtype: str, *, checking_disabled: bool = False) -> DNSQueryResult:
        qname = qname.rstrip(".") + "."
        qtype = str(qtype).upper()

        # RD=1 so we ask for recursion.
        msg = dns.message.make_query(qname, qtype, want_dnssec=True)
        msg.flags |= dns.flags.RD

        if checking_disabled:
            # Set CD bit (Checking Disabled) so the resolver will *not* validate.
            msg.flags |= dns.flags.CD

        try:
            if self.use_tcp:
                resp = dns.query.tcp(
                    msg, self.ip, port=self.port, timeout=self.timeout, lifetime=self.lifetime
                )
            else:
                resp = dns.query.udp(
                    msg, self.ip, port=self.port, timeout=self.timeout, lifetime=self.lifetime
                )

            rcode_text = dns.rcode.to_text(resp.rcode())

            # AD bit indicates "validated" by the resolver. (Meaningful only if CD=0)
            ad = bool(resp.flags & dns.flags.AD)
            cd = bool(resp.flags & dns.flags.CD)
            ra = bool(resp.flags & dns.flags.RA)
            rd = bool(resp.flags & dns.flags.RD)

            answers: List[str] = []
            ttl_min: Optional[int] = None

            for rrset in resp.answer:
                # Only capture the requested qtype rrsets for display.
                if rrset.rdtype != dns.rdatatype.from_text(qtype):
                    continue

                ttl_min = rrset.ttl if ttl_min is None else min(ttl_min, rrset.ttl)

                for rdata in rrset:
                    # For CAA we want something like: 0 issue "digicert.com"
                    if qtype == "CAA":
                        # rdata: flags, tag, value
                        try:
                            answers.append(f"{int(rdata.flags)} {rdata.tag} {rdata.value.to_text()}")
                        except Exception:
                            answers.append(rdata.to_text())
                    else:
                        answers.append(rdata.to_text())

            # "validated" only counts if AD=1 and we did NOT ask for checking disabled
            validated = ad and not checking_disabled

            return DNSQueryResult(
                qname=qname,
                qtype=qtype,
                rcode=rcode_text,
                answers=answers,
                ttl_min=ttl_min,
                flags={"ad": ad, "cd": cd, "ra": ra, "rd": rd},
                validated=validated,
                error=None,
                resolver_mode=self.mode,
            )

        except Exception as e:
            return DNSQueryResult(
                qname=qname,
                qtype=qtype,
                rcode="ERROR",
                answers=[],
                ttl_min=None,
                flags={"ad": False, "cd": checking_disabled, "ra": False, "rd": True},
                validated=False,
                error=f"{type(e).__name__}: {e}",
                resolver_mode=self.mode,
            )
