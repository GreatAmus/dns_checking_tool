# dnssec_tool.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

import pandas as pd

from .checks import DNSSECChecks
from .models import Finding, ZoneResult
from reporting.recommendations import Recommendations


# -----------------------------
# Reporter + Analytics helpers
# -----------------------------

class Reporter:
    """
    Turns scan results into a DataFrame suitable for analytics/plotting.
    Defensive against schema drift (e.g., detail_head/detail_tail not present).
    """

    def report(self, zones: Sequence[str], scanner: "DNSSECScanner", include_debug: bool = False) -> pd.DataFrame:
        rows: List[Dict[str, Any]] = []

        for zone in zones:
            zr = scanner.scan_zone(zone)

            # Ensure at least one row per zone for analytics
            if not zr.findings:
                rows.append(
                    {
                        "zone": zr.zone,
                        "overall": zr.overall,
                        "issue": None,
                        "severity": None,
                        "server": None,
                        "repro": None,
                        "detail": None,
                        "recommendation": None,
                        "detail_head": None,
                        "detail_tail": None,
                    }
                )
                continue

            for f in zr.findings:
                row = {
                    "zone": zr.zone,
                    "overall": zr.overall,
                    "issue": f.issue,
                    "severity": getattr(f, "severity", None),
                    "server": getattr(f, "server", None),
                    "repro": getattr(f, "repro", None),
                    "detail": getattr(f, "detail", None),
                    "recommendation": getattr(f, "recommendation", None),
                    # Backwards/forwards compatibility:
                    "detail_head": getattr(f, "detail_head", None),
                    "detail_tail": getattr(f, "detail_tail", None),
                }

                if include_debug:
                    row["data"] = getattr(f, "data", None)

                rows.append(row)

        return pd.DataFrame(rows)


class Analytics:
    """
    Computes simple summary tables used by /graph.png.
    """

    @staticmethod
    def compute(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        out: Dict[str, pd.DataFrame] = {}

        if df is None or df.empty or "issue" not in df.columns:
            out["counts_by_issue"] = pd.DataFrame(columns=["issue", "count"])
            out["severity_score_by_zone"] = pd.DataFrame(columns=["zone", "severity_score"])
            out["issue_by_zone"] = pd.DataFrame()
            out["cooccurrence_pairs"] = pd.DataFrame(columns=["issue_a", "issue_b", "zones_with_pair"])
            return out

        # counts by issue
        counts = (
            df.dropna(subset=["issue"])
            .groupby("issue", as_index=False)
            .size()
            .rename(columns={"size": "count"})
            .sort_values("count", ascending=False)
        )
        out["counts_by_issue"] = counts

        # severity score by zone (simple weighting)
        sev_map = {"error": 3, "fail": 3, "warning": 1, "info": 0, None: 0}
        d2 = df.copy()
        d2["sev_score"] = d2.get("severity").map(sev_map).fillna(0).astype(int)
        sev = (
            d2.groupby("zone", as_index=False)["sev_score"]
            .sum()
            .rename(columns={"sev_score": "severity_score"})
            .sort_values("severity_score", ascending=False)
        )
        out["severity_score_by_zone"] = sev

        # issue-by-zone heatmap pivot
        piv = (
            df.dropna(subset=["issue"])
            .assign(count=1)
            .pivot_table(index="zone", columns="issue", values="count", aggfunc="sum", fill_value=0)
        )
        out["issue_by_zone"] = piv

        # co-occurrence pairs (zone-level)
        zone_issues = (
            df.dropna(subset=["issue"])
            .groupby("zone")["issue"]
            .apply(lambda s: sorted(set([x for x in s if isinstance(x, str) and x])))
        )

        pair_counts: Dict[tuple, int] = {}
        for issues in zone_issues:
            for i in range(len(issues)):
                for j in range(i + 1, len(issues)):
                    pair = (issues[i], issues[j])
                    pair_counts[pair] = pair_counts.get(pair, 0) + 1

        pairs_df = pd.DataFrame(
            [{"issue_a": a, "issue_b": b, "zones_with_pair": c} for (a, b), c in pair_counts.items()]
        ).sort_values("zones_with_pair", ascending=False)

        if pairs_df.empty:
            pairs_df = pd.DataFrame(columns=["issue_a", "issue_b", "zones_with_pair"])

        out["cooccurrence_pairs"] = pairs_df
        return out


# -----------------------------
# DNSSEC Scanner + Tool
# -----------------------------

class DNSSECScanner:
    """
    Orchestrates DNSSECChecks and produces a ZoneResult with findings.

    Key behavior for correctness:
      - If NS cannot be found OR NS->IP resolution fails, we emit a hard finding and set overall=error.
      - Only performs DNSSEC validation logic when we can actually query authoritative servers.
      - Only treats missing DS as a finding when strict_dnssec=True; otherwise it's "DNSSEC_NOT_ENABLED" info.
    """

    def __init__(self, timeout: float = 8.0, strict_dnssec: bool = False, include_unsigned_finding: bool = False):
        self.timeout = float(timeout)
        self.strict_dnssec = bool(strict_dnssec)
        self.include_unsigned_finding = bool(include_unsigned_finding)

        self.checks = DNSSECChecks(timeout=self.timeout, strict_dnssec=self.strict_dnssec)

    def scan_zone(self, zone: str) -> ZoneResult:
        zone = (zone or "").strip().rstrip(".")
        zr = ZoneResult(zone=zone, overall="unknown", nameservers=[], findings=[])

        if not zone:
            zr.findings.append(
                Finding(zone=zone, issue="INVALID_ZONE", severity="error", detail="Empty zone provided.")
            )
            zr.overall = "error"
            return zr

        zfqdn = self.checks._fqdn(zone)

        # -------------------------
        # Explicit NS / auth-IP guardrail
        # -------------------------
        try:
            ns_names = self.checks._resolve_ns_names(zfqdn)
        except Exception as e:
            zr.findings.append(
                Finding(
                    zone=zone,
                    issue="NS_LOOKUP_FAILED",
                    severity="error",
                    detail=f"Could not resolve NS records for zone: {type(e).__name__}: {e}",
                )
            )
            zr.overall = "error"
            return zr

        if not ns_names:
            zr.findings.append(
                Finding(
                    zone=zone,
                    issue="NO_NAMESERVERS",
                    severity="error",
                    detail="No NS records were found for this zone (cannot evaluate DNSSEC).",
                )
            )
            zr.overall = "error"
            return zr

        zr.nameservers = ns_names

        auth_ips = self.checks._authoritative_server_ips(zfqdn)
        if not auth_ips:
            zr.findings.append(
                Finding(
                    zone=zone,
                    issue="AUTH_NS_IP_LOOKUP_FAILED",
                    severity="error",
                    detail="Nameservers exist but none could be resolved to IPs (cannot query authoritative DNS).",
                    data={"nameservers": ns_names},
                )
            )
            zr.overall = "error"
            return zr

        # -------------------------
        # Delegation / DS
        # -------------------------
        delegation, ds_findings = self.checks.get_delegation_ds(zone)
        zr.findings.extend(ds_findings)

        # If delegation is unsigned:
        if not delegation.ds_present:
            # If you want an explicit unsigned finding even when strict is off:
            if self.include_unsigned_finding and self.strict_dnssec is False:
                zr.findings.append(
                    Finding(
                        zone=zone,
                        issue="DNSSEC_NOT_ENABLED",
                        severity="info",
                        detail="No DS at parent; zone is delegated insecure (DNSSEC not enabled).",
                    )
                )

            # Overall should NOT be "fail" unless strict_dnssec made it an error;
            # if there's an error already, finalize below.
            self._finalize_overall(zr)
            # We do NOT run signature validation when no DS is present.
            return zr

        # -------------------------
        # Signed delegation checks
        # -------------------------
        zr.findings.extend(self.checks.check_ds_matches_dnskey(zone, delegation.ds_records))

        # Validate RRSIGs for key rrsets at apex
        for rrtype in ("DNSKEY", "SOA", "NS"):
            zr.findings.extend(self.checks.validate_rrsig_for_rrset(zone, rrtype))

        # Denial-of-existence basic probe (best-effort)
        zr.findings.extend(self.checks.validate_denial_of_existence(zone))

        # Attach recommendations (always)
        for f in zr.findings:
            try:
                if getattr(f, "recommendation", None):
                    continue
                f.recommendation = Recommendations.recommend(f.issue)
            except Exception:
                # never let recommendation break scanning
                pass

        self._finalize_overall(zr)
        return zr

    @staticmethod
    def _finalize_overall(zr: ZoneResult) -> None:
        # If any hard error exists => fail
        if any(getattr(f, "severity", "").lower() in ("error", "fail") for f in zr.findings):
            zr.overall = "fail"
            return
        # warnings => warn/partial (or pass-with-warnings)
        if any(getattr(f, "severity", "").lower() == "warning" for f in zr.findings):
            zr.overall = "warn"
            return
        # otherwise pass
        zr.overall = "pass"


class DNSSECTool:
    """
    Public API used by app.py
    """

    def __init__(
        self,
        timeout: float = 8.0,
        strict_dnssec: bool = False,
        include_unsigned_finding: bool = False,
    ):
        self.scanner = DNSSECScanner(
            timeout=timeout,
            strict_dnssec=strict_dnssec,
            include_unsigned_finding=include_unsigned_finding,
        )
        self.reporter = Reporter()

    def scan_zone(self, zone: str) -> ZoneResult:
        return self.scanner.scan_zone(zone)

    def report(self, zones: Sequence[str], include_debug: bool = False) -> pd.DataFrame:
        return self.reporter.report(zones, scanner=self.scanner, include_debug=include_debug)
