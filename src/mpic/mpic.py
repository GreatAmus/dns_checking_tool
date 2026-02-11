# mpic.py
"""
MPIC (Multi-Perspective Issuance Corroboration) DNS checker.

This version is tuned to avoid false positives like "google.com diverges" by:
- Treating A/AAAA answer-set differences as *normal* (INFO) when all perspectives succeed.
- Escalating only when there is:
    - RCODE mismatch (e.g., NXDOMAIN vs NOERROR)  -> HIGH
    - Resolver errors (SERVFAIL/TIMEOUT/ERROR)    -> MEDIUM/HIGH (depending on frequency)
    - CAA divergence                              -> HIGH (issuance-impacting)
    - NS divergence                               -> MEDIUM

It also runs each perspective query concurrently to avoid "hanging" due to sequential timeouts.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.flags
import dns.rcode
import dns.resolver


# -----------------------------
# Data models
# -----------------------------

@dataclass(frozen=True)
class Perspective:
    """One independent recursive resolver perspective."""
    name: str
    nameservers: Tuple[str, ...]
    port: int = 53


@dataclass
class PerspectiveResult:
    perspective: str
    qname: str
    qtype: str
    rcode: str
    answers: List[str] = field(default_factory=list)
    ttl_min: Optional[int] = None
    flags: Dict[str, bool] = field(default_factory=dict)
    error: Optional[str] = None

    def signature(self) -> Tuple[str, Tuple[str, ...]]:
        """Normalized comparison key for strict comparisons."""
        return (self.rcode, tuple(sorted(self.answers)))


@dataclass
class MPICQueryResult:
    qname: str
    qtype: str
    results: List[PerspectiveResult]
    consistent: bool
    majority_signature: Optional[Tuple[str, Tuple[str, ...]]] = None
    divergent_perspectives: List[str] = field(default_factory=list)
    error_count: int = 0


@dataclass
class MPICResult:
    """
    High-level MPIC result for a zone, suitable for your Assemble() output.
    """
    zone: str
    risk_score: float
    risk_level: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    queries: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "zone": self.zone,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings": self.findings,
            "queries": self.queries,
        }


# -----------------------------
# Checker
# -----------------------------

class MPICChecker:
    """
    Query DNS from multiple recursive resolvers ("perspectives") and detect divergence.

    Important behavior change vs. naive implementations:
      - "Divergence" does NOT automatically mean "MPIC failure risk."
      - A/AAAA can differ normally across resolvers; we treat that as INFO unless rcode mismatch/errors.
      - CAA divergence is treated as HIGH because it can directly block issuance.
    """

    DEFAULT_PERSPECTIVES: Tuple[Perspective, ...] = (
        Perspective("google", ("8.8.8.8", "8.8.4.4")),
        Perspective("cloudflare", ("1.1.1.1", "1.0.0.1")),
        Perspective("quad9", ("9.9.9.9", "149.112.112.112")),
        Perspective("opendns", ("208.67.222.222", "208.67.220.220")),
    )

    def __init__(
        self,
        perspectives: Optional[List[Perspective]] = None,
        timeout: float = 1.5,
        lifetime: float = 1.5,
        use_tcp: bool = False,
        max_workers: Optional[int] = None,
    ) -> None:
        self.perspectives = perspectives or list(self.DEFAULT_PERSPECTIVES)
        self.timeout = float(timeout)
        self.lifetime = float(lifetime)
        self.use_tcp = bool(use_tcp)
        self.max_workers = max_workers or max(1, len(self.perspectives))

    # ---- low-level helpers ----

    def _make_resolver(self, p: Perspective) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = list(p.nameservers)
        r.port = p.port
        r.timeout = self.timeout
        r.lifetime = self.lifetime
        r.retry_servfail = False
        # Set DO bit (DNSSEC OK) to allow AD where supported.
        r.use_edns(0, dns.flags.DO, 1232)
        return r

    @staticmethod
    def _normalize_answers(answer: dns.resolver.Answer) -> Tuple[List[str], Optional[int]]:
        if not getattr(answer, "rrset", None):
            return [], None
        rrset = answer.rrset
        ttl = getattr(rrset, "ttl", None)
        out = [r.to_text() for r in rrset]
        return out, ttl

    @staticmethod
    def _rcode_text_from_answer(answer: Optional[dns.resolver.Answer]) -> str:
        if answer is None:
            return "unknown"
        resp = getattr(answer, "response", None)
        if resp is None:
            return "unknown"
        return dns.rcode.to_text(resp.rcode())

    @staticmethod
    def _flags_from_answer(answer: Optional[dns.resolver.Answer]) -> Dict[str, bool]:
        resp = getattr(answer, "response", None)
        if resp is None:
            return {}
        f = resp.flags
        return {
            "ad": bool(f & dns.flags.AD),
            "cd": bool(f & dns.flags.CD),
            "ra": bool(f & dns.flags.RA),
            "rd": bool(f & dns.flags.RD),
        }

    def _run_one(self, p: Perspective, qname: str, qtype: str) -> PerspectiveResult:
        resolver = self._make_resolver(p)
        pr = PerspectiveResult(perspective=p.name, qname=qname, qtype=qtype, rcode="unknown")
        try:
            ans = resolver.resolve(
                qname,
                qtype,
                tcp=self.use_tcp,
                raise_on_no_answer=False,
                search=False,
            )
            pr.answers, pr.ttl_min = self._normalize_answers(ans)
            pr.rcode = self._rcode_text_from_answer(ans)
            pr.flags = self._flags_from_answer(ans)
        except dns.resolver.NXDOMAIN:
            pr.rcode = "NXDOMAIN"
        except dns.resolver.NoNameservers as e:
            pr.rcode = "SERVFAIL"
            pr.error = f"NoNameservers: {e}"
        except dns.exception.Timeout as e:
            pr.rcode = "TIMEOUT"
            pr.error = f"Timeout: {e}"
        except Exception as e:
            pr.rcode = "ERROR"
            pr.error = f"{type(e).__name__}: {e}"
        return pr

    # ---- public query methods ----

    def query(self, qname: str, qtype: str) -> MPICQueryResult:
        """
        Query one name/type across all perspectives concurrently.
        'consistent' remains strict equality of rcode + answer set, but check_zone()
        will interpret this in a record-type aware way.
        """
        qname = qname.strip().rstrip(".") + "."
        qtype = qtype.strip().upper()

        results: List[PerspectiveResult] = []
        sig_counts: Dict[Tuple[str, Tuple[str, ...]], int] = {}
        error_count = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = [ex.submit(self._run_one, p, qname, qtype) for p in self.perspectives]
            for fut in as_completed(futures):
                pr = fut.result()
                results.append(pr)
                if pr.error:
                    error_count += 1
                sig = pr.signature()
                sig_counts[sig] = sig_counts.get(sig, 0) + 1

        majority_sig = max(sig_counts.items(), key=lambda kv: kv[1])[0] if sig_counts else None
        consistent = (len(sig_counts) == 1) if sig_counts else False
        divergent = [r.perspective for r in results if majority_sig and r.signature() != majority_sig]

        return MPICQueryResult(
            qname=qname,
            qtype=qtype,
            results=results,
            consistent=consistent,
            majority_signature=majority_sig,
            divergent_perspectives=divergent,
            error_count=error_count,
        )

    def query_caa_chain(self, domain: str, max_labels: int = 10) -> List[MPICQueryResult]:
        """
        RFC-style behavior: if no CAA at name, check parent, up to max_labels.
        Stops when any CAA records are observed at a level.
        """
        d = domain.strip().rstrip(".")
        labels = [x for x in d.split(".") if x]
        out: List[MPICQueryResult] = []

        for i in range(0, min(len(labels), max_labels)):
            name = ".".join(labels[i:])
            qr = self.query(name, "CAA")
            out.append(qr)

            # if any perspective returned actual CAA RRs, stop climbing
            if any(r.answers for r in qr.results):
                break

        return out

    # -----------------------------
    # Risk scoring + interpretation
    # -----------------------------

    @staticmethod
    def _rcodes(qr: MPICQueryResult) -> List[str]:
        return [r.rcode for r in qr.results]

    @staticmethod
    def _has_rcode_mismatch(qr: MPICQueryResult) -> bool:
        rc = set(MPICChecker._rcodes(qr))
        return len(rc) > 1

    @staticmethod
    def _any_errors(qr: MPICQueryResult) -> bool:
        return any(r.error for r in qr.results)

    @staticmethod
    def _all_success_noerror(qr: MPICQueryResult) -> bool:
        # "Success" here means NOERROR (even if empty NOANSWER)
        return all(r.rcode == "NOERROR" and not r.error for r in qr.results)

    @staticmethod
    def _answers_present(qr: MPICQueryResult) -> bool:
        return any(r.answers for r in qr.results)

    def mpic_risk_score(self, query_results: List[MPICQueryResult]) -> float:
        """
        0..1 risk score, weighted by what typically matters for issuance:
          - HIGH weight: CAA rcode mismatch / divergence
          - HIGH weight: RCODE mismatch (NXDOMAIN vs NOERROR) anywhere
          - MED weight: resolver errors
          - LOW weight: NS divergence
          - VERY LOW weight: A/AAAA answer-set differences (often normal)
        """
        if not query_results:
            return 0.0

        score = 0.0

        for qr in query_results:
            qtype = qr.qtype.upper()
            rcode_mismatch = self._has_rcode_mismatch(qr)
            errors = self._any_errors(qr)
            strict_div = (not qr.consistent)

            if rcode_mismatch:
                # Existence / error disagreements are high risk
                score += 0.35
                continue

            if errors:
                # Partial timeouts/SERVFAIL matter
                score += 0.18
                continue

            if qtype == "CAA":
                # CAA differences are high impact
                if strict_div:
                    score += 0.30
                continue

            if qtype == "NS":
                if strict_div:
                    score += 0.12
                continue

            if qtype in ("A", "AAAA"):
                # Typically normal. Only small bump if empty on some perspectives.
                # If everyone is NOERROR and everyone has at least one answer -> 0 bump.
                if self._all_success_noerror(qr):
                    # if at least one perspective had answers but some had none
                    any_ans = any(r.answers for r in qr.results)
                    all_ans = all(bool(r.answers) for r in qr.results)
                    if any_ans and not all_ans:
                        score += 0.05
                continue

            # Default: small penalty for strict divergence on other types
            if strict_div:
                score += 0.08

        # normalize into 0..1-ish; cap
        return max(0.0, min(1.0, score))

    # -----------------------------
    # High-level API for your app/assembler
    # -----------------------------

    def check_zone(self, zone: str) -> MPICResult:
        """
        High-level entrypoint used by your FastAPI endpoint:
            mpic_result = mpic.check_zone(zone)

        Returns MPICResult with:
          - findings (for Assemble to unify)
          - queries (raw detail, helpful for UI drill-down)
        """
        # Queries to run
        checks: List[MPICQueryResult] = [
            self.query(zone, "A"),
            self.query(zone, "AAAA"),
            self.query(zone, "NS"),
        ]
        checks.extend(self.query_caa_chain(zone))

        score = float(self.mpic_risk_score(checks))
        if score >= 0.60:
            level = "high"
        elif score >= 0.25:
            level = "medium"
        else:
            level = "low"

        # Build raw queries list (JSON-friendly)
        queries: List[Dict[str, Any]] = []
        for qr in checks:
            queries.append({
                "qname": qr.qname,
                "qtype": qr.qtype,
                "consistent": qr.consistent,  # strict
                "divergent_perspectives": qr.divergent_perspectives,
                "error_count": qr.error_count,
                "results": [
                    {
                        "perspective": r.perspective,
                        "rcode": r.rcode,
                        "answers": r.answers,
                        "ttl_min": r.ttl_min,
                        "flags": r.flags,
                        "error": r.error,
                    }
                    for r in qr.results
                ],
            })

        # Findings (record-type aware)
        findings: List[Dict[str, Any]] = []

        # 1) RCODE mismatches are always high-risk
        rcode_mismatches = [qr for qr in checks if self._has_rcode_mismatch(qr)]
        if rcode_mismatches:
            items = ", ".join([f"{qr.qtype}@{qr.qname}".replace("..", ".") for qr in rcode_mismatches[:6]])
            findings.append({
                "issue": "mpic_rcode_mismatch",
                "severity": "high",
                "title": "RCODE mismatch across perspectives",
                "detail": (
                    "Different resolvers returned different response codes (e.g., NOERROR vs NXDOMAIN) for one or more queries. "
                    f"Affected: {items}{'...' if len(rcode_mismatches) > 6 else ''}."
                ),
            })

        # 2) Resolver errors matter (timeouts/SERVFAIL)
        error_q = [qr for qr in checks if self._any_errors(qr)]
        if error_q:
            items = ", ".join([f"{qr.qtype}@{qr.qname}".replace("..", ".") for qr in error_q[:6]])
            findings.append({
                "issue": "mpic_resolution_errors",
                "severity": "medium",
                "title": "Resolution errors from some perspectives",
                "detail": (
                    "One or more perspectives timed out or returned errors (e.g., TIMEOUT/SERVFAIL/ERROR). "
                    f"Affected: {items}{'...' if len(error_q) > 6 else ''}."
                ),
            })

        # 3) CAA divergence is high signal for issuance
        caa_q = [qr for qr in checks if qr.qtype.upper() == "CAA"]
        caa_div = [qr for qr in caa_q if (not qr.consistent) and (not self._has_rcode_mismatch(qr)) and (not self._any_errors(qr))]
        if caa_div:
            findings.append({
                "issue": "mpic_caa_divergence",
                "severity": "high",
                "title": "CAA differs across perspectives",
                "detail": (
                    "CAA responses were not consistent across resolvers. Because CAA controls issuance authorization, "
                    "this can directly cause MPIC corroboration to fail for certificate issuance."
                ),
            })

        # 4) NS divergence is medium signal
        ns_q = [qr for qr in checks if qr.qtype.upper() == "NS"]
        ns_div = [qr for qr in ns_q if (not qr.consistent) and (not self._has_rcode_mismatch(qr)) and (not self._any_errors(qr))]
        if ns_div:
            findings.append({
                "issue": "mpic_ns_divergence",
                "severity": "medium",
                "title": "NS differs across perspectives",
                "detail": (
                    "NS answers differed across resolvers. This may indicate inconsistent delegation visibility, caching differences, "
                    "or resolver-path issues."
                ),
            })

        # 5) A/AAAA answer-set differences are usually normal (info only)
        a_q = [qr for qr in checks if qr.qtype.upper() in ("A", "AAAA")]
        a_div = [qr for qr in a_q if (not qr.consistent) and self._all_success_noerror(qr)]
        if a_div and not rcode_mismatches and not error_q and not caa_div and not ns_div:
            findings.append({
                "issue": "mpic_geo_variation",
                "severity": "info",
                "title": "A/AAAA varies across perspectives",
                "detail": (
                    "Different A/AAAA answers across resolvers are common for globally load-balanced domains "
                    "(anycast/geo steering) and do not necessarily indicate MPIC issuance failure risk."
                ),
            })

        # Always include a score summary finding (info)
        findings.append({
            "issue": "mpic_risk_score",
            "severity": "info",
            "title": "MPIC risk score",
            "detail": f"MPIC risk score is {score:.3f} ({level}).",
        })

        return MPICResult(
            zone=zone,
            risk_score=round(score, 3),
            risk_level=level,
            findings=findings,
            queries=queries,
        )
