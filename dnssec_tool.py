"""
DNSSEC Checking Tool provides:
- Recommendations
- Reporting -> pandas DataFrame
- Analytics + plotting
"""

from typing import Dict, List, Tuple, Any, Optional
import pandas as pd
import matplotlib.pyplot as plt 

from dnssec_scanner import DNSSECScanner
from dnssec_models import Finding, ZoneResult
from dnssec_recommendations import Recommendations
from dnssec_analytics import ReportAnalyzer

# ============================================================
# Reporting
# ============================================================

class Reporter:
    def __init__(self, scanner: DNSSECScanner):
        self.scanner = scanner

    def report(self, zones: List[str], include_debug: bool = True) -> "pd.DataFrame":
        rows: List[Dict[str, Any]] = []

        for z in zones:
            zr: ZoneResult = self.scanner.scan_zone(z)

            if not zr.findings:
                rows.append({
                    "zone": zr.zone,
                    "server": "",
                    "issue": "OK",
                    "recommendation": Recommendations.recommend("OK"),
                    "repro": "",
                    "detail_tail": "",
                })
                continue

            for f in zr.findings:
                row = {
                    "zone": f.zone,
                    "server": f.server,
                    "issue": f.issue,
                    "recommendation": Recommendations.recommend(f.issue),
                }
                if include_debug:
                    row["repro"] = f.repro
                    row["detail_tail"] = f.detail_tail
                rows.append(row)

        df = pd.DataFrame(rows)
        if df.empty:
            return df

        issue_rank = {
            "DNSSEC_BOGUS": 0,
            "DNSKEY_INCONSISTENT": 1,
            "DNSKEY_NODATA": 2,
            "NS_UNREACHABLE": 3,
            "NS_REFUSED": 4,
            "PARENT_DS_QUERY_FAILED": 5,
            "DNSSEC_UNSIGNED": 90,
            "PARENT_UNSIGNED": 91,
            "OK": 99,
        }
        df["_rank"] = df["issue"].astype(str).str.upper().map(issue_rank).fillna(50).astype(int)
        df = df.sort_values(["_rank", "zone", "server"]).drop(columns=["_rank"]).reset_index(drop=True)
        return df

from dnssec_scanner import DNSSECScanner

class DNSSECTool:
    def __init__(self, timeout: float = 8.0):
        self.scanner = DNSSECScanner(timeout=timeout)

    def scan_zone(self, zone: str):
        return self.scanner.scan_zone(zone)
    
# ============================================================
# Analytics + plotting (kept lightweight)
# ============================================================

class Analytics:
    """
    Single public analytics API.
    Delegates to dnssec_analytics.ReportAnalyzer, then adds extra tables used by graphs.
    """

    @staticmethod
    def compute(df: "pd.DataFrame") -> Dict[str, "pd.DataFrame"]:
        ra = ReportAnalyzer()
        base = ra.analytics(df)  # includes counts_by_issue, worst_zones, prioritized_queue, cooccurrence_pairs

        # Always return the same keys for the UI/plotter
        if df is None or df.empty:
            empty = pd.DataFrame()
            return {
                "counts_by_issue": base.get("counts_by_issue", empty),
                "counts_by_zone": empty,
                "issue_by_zone": empty,
                "counts_by_server": empty,
                "worst_zones": base.get("worst_zones", empty),
                "severity_score_by_zone": empty,
                "prioritized_queue": base.get("prioritized_queue", empty),
                "cooccurrence_pairs": base.get("cooccurrence_pairs", empty),
            }

        broken = df[df["issue"] != "OK"].copy()

        counts_by_zone = (
            broken.groupby("zone").size().sort_values(ascending=False).reset_index(name="count")
            if not broken.empty else pd.DataFrame(columns=["zone", "count"])
        )

        issue_by_zone = (
            broken.pivot_table(index="zone", columns="issue", values="server", aggfunc="count", fill_value=0).sort_index()
            if not broken.empty else pd.DataFrame()
        )

        counts_by_server = (
            broken[
                broken["server"].astype(str).str.strip().ne("") &
                ~broken["server"].astype(str).str.startswith("(")
            ]
            .groupby("server").size().sort_values(ascending=False).reset_index(name="count")
            if not broken.empty else pd.DataFrame(columns=["server", "count"])
        )

        # Simple severity scoring (you can tune weights later)
        weights = {
            "DNSSEC_BOGUS": 10,
            "DS_MISMATCH": 9,
            "DNSKEY_INCONSISTENT": 7,
            "DNSKEY_NODATA": 6,
            "DENIAL_PROOF_MISSING": 7,
            "DENIAL_RRSIG_MISSING": 7,
            "NS_UNREACHABLE": 4,
            "NS_REFUSED": 4,
            "PARENT_DS_QUERY_FAILED": 3,
        }
        if not broken.empty:
            broken["severity_weight"] = broken["issue"].map(weights).fillna(1).astype(int)
            severity_score_by_zone = (
                broken.groupby("zone")["severity_weight"].sum().sort_values(ascending=False).reset_index(name="severity_score")
            )
        else:
            severity_score_by_zone = pd.DataFrame(columns=["zone", "severity_score"])

        return {
            "counts_by_issue": base.get("counts_by_issue", pd.DataFrame(columns=["issue", "count"])),
            "counts_by_zone": counts_by_zone,
            "issue_by_zone": issue_by_zone,
            "counts_by_server": counts_by_server,
            "worst_zones": base.get("worst_zones", pd.DataFrame(columns=["zone", "count", "issue_breakdown"])),
            "severity_score_by_zone": severity_score_by_zone,
            "prioritized_queue": base.get("prioritized_queue", df.copy()),
            "cooccurrence_pairs": base.get("cooccurrence_pairs", pd.DataFrame(columns=["issue_a", "issue_b", "zones_with_pair"])),
        }


class Plotter:
    """Matplotlib plots for analytics outputs."""

    @staticmethod
    def plot_analytics_2x2(a: Dict[str, "pd.DataFrame"], top_issues: int = 12, top_zones: int = 15) -> None:
        if plt is None:
            raise RuntimeError("matplotlib is required for Plotter.plot_analytics_2x2()")

        fig, axs = plt.subplots(2, 2, figsize=(16, 10))
        axs = axs.ravel()

        # 1) Findings by issue
        counts_by_issue = a.get("counts_by_issue", pd.DataFrame())
        ax = axs[0]
        if counts_by_issue.empty:
            ax.text(0.5, 0.5, "counts_by_issue is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            d = counts_by_issue.head(top_issues)
            ax.bar(d["issue"], d["count"])
            ax.set_title("Findings by issue")
            ax.tick_params(axis="x", rotation=45)

        # 2) Severity score by zone
        sev = a.get("severity_score_by_zone", pd.DataFrame())
        ax = axs[1]
        if sev.empty:
            ax.text(0.5, 0.5, "severity_score_by_zone is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            d = sev.head(top_zones)
            ax.bar(d["zone"], d["severity_score"])
            ax.set_title("Severity score by zone")
            ax.tick_params(axis="x", rotation=60)

        # 3) Heatmap issues by zone
        pivot = a.get("issue_by_zone", pd.DataFrame())
        ax = axs[2]
        if pivot.empty:
            ax.text(0.5, 0.5, "issue_by_zone is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            totals = pivot.sum(axis=1).sort_values(ascending=False)
            p = pivot.loc[totals.head(20).index]
            im = ax.imshow(p.values, aspect="auto")
            ax.set_title("Issues by zone (top 20)")
            ax.set_yticks(range(p.shape[0]))
            ax.set_yticklabels(p.index)
            ax.set_xticks(range(p.shape[1]))
            ax.set_xticklabels(p.columns, rotation=45, ha="right")
            fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

        # 4) Worst zones (simple bar by count)
        worst = a.get("worst_zones", pd.DataFrame())
        ax = axs[3]
        if worst.empty:
            ax.text(0.5, 0.5, "worst_zones is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            d = worst.head(top_zones)
            ax.bar(d["zone"], d["count"])
            ax.set_title("Worst zones by finding count")
            ax.tick_params(axis="x", rotation=60)

        plt.tight_layout()
        plt.show()


# ============================================================
# High-level facade
# ============================================================

class DNSSECTool:
    """
    High-level façade.

    Example:
      tool = DNSSECTool(timeout=20)
      df = tool.report(["dnssec-failed.org", "cloudflare.com"])
      a  = tool.analytics(df)
      tool.plot_analytics_2x2(a)
    """

    def __init__(self, timeout: int = 20, include_unsigned_finding: bool = False):
        # DnssecScanner internally uses dnssec_runner.CommandRunner, so keep construction simple.
        self.scanner = DNSSECScanner(cmd_timeout_seconds=timeout, include_unsigned_finding=include_unsigned_finding)
        self.reporter = Reporter(self.scanner)

    def scan_zone(self, zone: str) -> ZoneResult:
        return self.scanner.scan_zone(zone)

    def report(self, zones: List[str], include_debug: bool = True) -> "pd.DataFrame":
        return self.reporter.report(zones, include_debug=include_debug)

    def analytics(self, df: "pd.DataFrame") -> Dict[str, "pd.DataFrame"]:
        return Analytics.compute(df)

    def plot_analytics_2x2(self, a: Dict[str, "pd.DataFrame"], **kwargs: Any) -> None:
        return Plotter.plot_analytics_2x2(a, **kwargs)


__all__ = [
    "DNSSECTool",
    "Reporter",
    "Analytics",
    "Plotter",
    "Recommendations",
]
