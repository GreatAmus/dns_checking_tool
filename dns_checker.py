'''
DNSSEC Checking Tool

This module wraps common DNSSEC diagnostics (dig + delv) into a small, readable API.

Primary entry point:
  tool = DNSSECTool()
  df = tool.report(["dnssec-failed.org", "cloudflare.com"])
  a  = tool.analytics(df)
  tool.plot_analytics_2x2(a)

Notes
-----
- Requires command-line tools:
    - dig   (dnsutils)
    - delv  (bind9-dnsutils)

  On Debian/Ubuntu/Colab:
    apt-get update
    apt-get install -y dnsutils bind9-dnsutils
'''

from __future__ import annotations
import subprocess
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

try:
    import pandas as pd  # type: ignore
except Exception:  # pragma: no cover
    pd = None  # type: ignore

# matplotlib is optional unless you call plotting methods
try:
    import matplotlib.pyplot as plt  # type: ignore
except Exception:  # pragma: no cover
    plt = None  # type: ignore


# ============================================================
# Command runner
# ============================================================

@dataclass
class CommandResult:
    cmd: List[str]
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def text(self) -> str:
        """Combined stdout+stderr as a single string."""
        return ((self.stdout or "") + "\n" + (self.stderr or "")).strip()


class CommandRunner:
    """Runs shell commands with a timeout and returns a structured result."""

    def __init__(self, timeout: int = 20):
        self.timeout = int(timeout)

    def run(self, cmd: List[str]) -> CommandResult:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            return CommandResult(cmd=cmd, stdout=p.stdout or "", stderr=p.stderr or "", timed_out=False)
        except subprocess.TimeoutExpired:
            return CommandResult(cmd=cmd, stdout="", stderr=f"[timeout after {self.timeout}s]", timed_out=True)


# ============================================================
# dig helpers
# ============================================================

class DigClient:
    """
    Small wrapper around `dig` for two output "contracts":
      - answer-only: stable, compact output (useful for comparing RRsets)
      - answer+authority: includes NSEC/NSEC3 proofs (useful for DNSSEC diagnostics)
    """

    def __init__(self, runner: CommandRunner):
        self.runner = runner

    def ns(self, zone: str) -> List[str]:
        """Discover authoritative NS for a zone."""
        res = self.runner.run(["dig", "+short", zone, "NS"]).text
        return [l.strip().rstrip(".") for l in res.splitlines() if l.strip()]

    def answer(self, server: str, name: str, rtype: str) -> str:
        """Return ANSWER section only (plus DNSSEC records if present)."""
        return self.runner.run(["dig", f"@{server}", name, rtype, "+dnssec", "+noall", "+answer"]).text

    def answer_authority(self, server: str, name: str, rtype: str) -> str:
        """Return ANSWER + AUTHORITY sections (needed for NSEC/NSEC3 proofs)."""
        return self.runner.run(
            ["dig", f"@{server}", name, rtype, "+dnssec", "+noall", "+answer", "+authority"]
        ).text


# ============================================================
# delv probe (validator perspective)
# ============================================================

class DelvValidator:
    """
    Wrap `delv +rtrace` and classify its output into a coarse status.

    This catches cases where DNSSEC is *actually* failing validation (DNSSEC_BOGUS),
    even when authoritative responses look superficially "complete".
    """

    def __init__(self, runner: CommandRunner):
        self.runner = runner

    def probe(self, qname: str, qtype: str, server: Optional[str] = None) -> Dict[str, Any]:
        cmd = ["delv", "+rtrace", qname, qtype]
        if server:
            cmd.append(f"@{server}")

        out = self.runner.run(cmd).text
        low = out.lower()

        issues: List[str] = []

        # Rough classification (heuristic parsing across delv versions)
        if "validation failure" in low or "bogus" in low:
            status = "bogus"
            issues.append("DNSSEC validation failed (bogus).")
        elif "fully validated" in low or re.search(r"\bsecure\b", low):
            status = "secure"
        elif "insecure" in low:
            status = "insecure"
        elif "indeterminate" in low:
            status = "indeterminate"
            issues.append("Validation indeterminate.")
        elif "timed out" in low or low.startswith("[timeout"):
            status = "timeout"
            issues.append("Query timed out.")
        elif "network unreachable" in low or "no route to host" in low:
            status = "network_error"
            issues.append("Network error.")
        else:
            status = "unknown"
            issues.append("Could not classify delv output; inspect detail.")

        # Common hints
        if "expired" in low:
            issues.append("Possible expired signature or timing issue.")
        if "not yet valid" in low:
            issues.append("Signature not yet valid (clock skew or bad inception).")
        if "no valid ds" in low or "no ds" in low:
            issues.append("No DS at parent or DS mismatch (broken chain of trust).")
        if "bad key" in low or "key not found" in low:
            issues.append("Signature doesn't match an available key (rollover mismatch or stale data).")

        detail = "\n".join(out.splitlines()[-80:])

        return {
            "qname": qname,
            "qtype": qtype,
            "server": server,
            "status": status,
            "issues": issues,
            "detail": detail,
            "repro_cmd": " ".join(cmd),
        }


# ============================================================
# DNSSEC checks and scanning
# ============================================================

class DNSSECChecks:
    """Pure checks that operate on dig output and convert them to standardized findings."""

    @staticmethod
    def compare_dnskey_across_ns(dig: DigClient, zone: str) -> Dict[str, Any]:
        ns = dig.ns(zone)
        per_ns: Dict[str, str] = {}
        normalized: Dict[str, str] = {}

        for s in ns:
            ans = (dig.answer(s, zone, "DNSKEY") or "").strip()
            per_ns[s] = ans
            # normalize TTL + whitespace to reduce false differences
            norm = re.sub(r"\s+", " ", re.sub(r"\s+\d+\s+IN\s+", " IN ", ans)).strip()
            normalized[s] = norm

        unique_norm = {v for v in normalized.values() if v}
        consistent = (len(unique_norm) == 1 and len(unique_norm) > 0)

        return {
            "zone": zone,
            "nameservers": ns,
            "consistent_dnskey_rrset": consistent,
            "per_ns": per_ns,
        }

    @staticmethod
    def check_authoritative_ns(dig: DigClient, server: str, zone: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # DNSKEY presence + RRSIG presence
        out = dig.answer_authority(server, zone, "DNSKEY")

        if " DNSKEY " not in out:
            findings.append({
                "zone": zone,
                "server": server,
                "issue": "DNSKEY_MISSING",
                "repro": f"dig +dnssec @{server} {zone} DNSKEY +noall +answer +authority",
                "detail_tail": "\n".join(out.splitlines()[-60:]),
            })
            return findings

        if " RRSIG " not in out:
            findings.append({
                "zone": zone,
                "server": server,
                "issue": "RRSIGS_MISSING",
                "repro": f"dig +dnssec @{server} {zone} DNSKEY +noall +answer +authority",
                "detail_tail": "\n".join(out.splitlines()[-60:]),
            })

        # NXDOMAIN proof should include NSEC or NSEC3 in AUTHORITY for signed zones
        nx = f"does-not-exist-{zone.strip('.')}.{zone.strip('.')}."
        out = dig.answer_authority(server, nx, "A")
        if (" NSEC " not in out) and (" NSEC3 " not in out):
            findings.append({
                "zone": zone,
                "server": server,
                "issue": "NSEC_MISSING",
                "repro": f"dig +dnssec @{server} {nx} A +noall +answer +authority",
                "detail_tail": "\n".join(out.splitlines()[-60:]),
            })

        return findings


class DNSSECScanner:
    """
    Minimal DNSSEC scan for a zone:
      - One delv validation (SOA) -> DNSSEC_BOGUS if bogus
      - DNSKEY consistency across NS -> DNSKEY_INCONSISTENT
      - Per-NS dig checks -> DNSKEY_MISSING / RRSIGS_MISSING / NSEC_MISSING
    """

    def __init__(self, dig: DigClient, delv: DelvValidator):
        self.dig = dig
        self.delv = delv

    def scan_zone(self, zone: str) -> Dict[str, Any]:
        zone = zone.rstrip(".") + "."
        ns = self.dig.ns(zone)

        findings: List[Dict[str, Any]] = []

        # Validator perspective (delv)
        v = self.delv.probe(zone, "SOA")
        if v.get("status") == "bogus":
            findings.append({
                "zone": zone,
                "server": "(validator path)",
                "issue": "DNSSEC_BOGUS",
                "repro": v.get("repro_cmd", ""),
                "detail_tail": v.get("detail", ""),
            })

        # DNSKEY consistency across NS
        ns_consistency = DNSSECChecks.compare_dnskey_across_ns(self.dig, zone)
        if ns_consistency.get("nameservers") and not ns_consistency.get("consistent_dnskey_rrset", True):
            findings.append({
                "zone": zone,
                "server": "(authoritatives)",
                "issue": "DNSKEY_INCONSISTENT",
                "repro": f"dig +dnssec @<ns> {zone} DNSKEY +noall +answer",
                "detail_tail": "DNSKEY differs across NS; see ns_consistency['per_ns'] for raw answers.",
            })

        # Explicit authoritative checks across ALL NS
        for s in ns:
            findings.extend(DNSSECChecks.check_authoritative_ns(self.dig, s, zone))

        overall = "pass" if not findings else "fail"
        return {
            "zone": zone,
            "overall": overall,
            "nameservers": ns,
            "ns_consistency": ns_consistency,
            "findings": findings,
        }


# ============================================================
# Reporting, recommendations, analytics, plotting
# ============================================================

class Recommendations:
    """Human-readable recommendations keyed by issue code."""

    @staticmethod
    def recommend(issue: str) -> str:
        issue = (issue or "").upper()

        if issue == "DNSSEC_BOGUS":
            return (
                "Validation failed.\n"
                "- Run the repro command to see where the chain breaks.\n"
                "- Verify parent DS matches the zone’s DNSKEY (KSK).\n"
                "- Check RRSIG timing (expired/not-yet-valid) and key rollover state.\n"
                "- If intermittent, check DNSKEY consistency across all authoritatives."
            )
        if issue == "DNSKEY_INCONSISTENT":
            return (
                "Authoritative servers disagree on DNSKEY RRset.\n"
                "- Compare SOA serial and DNSKEY across all NS; identify stale/out-of-sync servers.\n"
                "- Fix IXFR/AXFR/NOTIFY or anycast propagation; reload/resync zone everywhere.\n"
                "- During rollovers, publish old+new keys everywhere before removing old."
            )
        if issue == "DNSKEY_MISSING":
            return (
                "Authoritative server did not return DNSKEY.\n"
                "- Confirm you’re querying the zone apex and it is DNSSEC-signed.\n"
                "- Ensure the signed zone (with DNSKEY) is being served on this NS.\n"
                "- Check transfers/anycast propagation; reload/resync this nameserver."
            )
        if issue == "RRSIGS_MISSING":
            return (
                "DNSKEY returned without RRSIG.\n"
                "- Ensure zone signing is enabled and signer publishes RRSIGs.\n"
                "- Verify this NS serves the signed copy (not an unsigned/stale copy).\n"
                "- Resync secondaries / anycast nodes."
            )
        if issue == "NSEC_MISSING":
            return (
                "NXDOMAIN response missing NSEC/NSEC3 proof.\n"
                "- Ensure zone is signed with NSEC or NSEC3 and proofs are generated.\n"
                "- Verify authority section is returned (no filtering/truncation).\n"
                "- Re-sign and redeploy the signed zone if incomplete on this NS."
            )
        if issue == "OK":
            return "No issues detected by these checks."

        return "No recommendation available for this issue."


class Reporter:
    """Convert scan results into a flat pandas DataFrame."""

    def __init__(self, scanner: DNSSECScanner):
        self.scanner = scanner

    def report(self, zones: List[str]) -> "pd.DataFrame":
        if pd is None:
            raise RuntimeError("pandas is required for Reporter.report()")

        rows: List[Dict[str, Any]] = []

        for z in zones:
            report = self.scanner.scan_zone(z)
            findings = report.get("findings", [])

            if not findings:
                rows.append({
                    "zone": report.get("zone"),
                    "server": "",
                    "issue": "OK",
                    "recommendation": Recommendations.recommend("OK"),
                    "repro": "",
                    "detail_tail": "",
                })
                continue

            for f in findings:
                issue = f.get("issue", "")
                rows.append({
                    "zone": f.get("zone", report.get("zone")),
                    "server": f.get("server", ""),
                    "issue": issue,
                    "recommendation": Recommendations.recommend(issue),
                    "repro": f.get("repro", ""),
                    "detail_tail": f.get("detail_tail", ""),
                })

        df = pd.DataFrame(rows)
        if df.empty:
            return df

        issue_rank = {
            "DNSSEC_BOGUS": 0,
            "DNSKEY_INCONSISTENT": 1,
            "DNSKEY_MISSING": 2,
            "RRSIGS_MISSING": 3,
            "NSEC_MISSING": 4,
            "OK": 9,
        }
        df["issue_rank"] = df["issue"].map(issue_rank).fillna(99).astype(int)
        df = df.sort_values(["issue_rank", "zone", "server"]).drop(columns=["issue_rank"])
        return df


class Analytics:
    """Compute useful rollups from the report DataFrame."""

    @staticmethod
    def compute(df: "pd.DataFrame") -> Dict[str, "pd.DataFrame"]:
        if pd is None:
            raise RuntimeError("pandas is required for Analytics.compute()")

        if df is None or df.empty:
            empty = pd.DataFrame()
            return {
                "counts_by_issue": empty,
                "counts_by_zone": empty,
                "issue_by_zone": empty,
                "counts_by_server": empty,
                "worst_zones": empty,
                "severity_score_by_zone": empty,
                "single_cause_zones": empty,
                "cooccurrence_pairs": empty,
                "perspective_breakdown": empty,
                "prioritized_queue": empty,
            }

        broken = df[df["issue"] != "OK"].copy()

        counts_by_issue = (
            broken.groupby("issue").size().sort_values(ascending=False).reset_index(name="count")
        )

        counts_by_zone = (
            broken.groupby("zone").size().sort_values(ascending=False).reset_index(name="count")
        )

        issue_by_zone = (
            broken.pivot_table(index="zone", columns="issue", values="server", aggfunc="count", fill_value=0).sort_index()
        )

        counts_by_server = (
            broken[
                broken["server"].astype(str).str.strip().ne("") &
                ~broken["server"].astype(str).str.startswith("(")
            ]
            .groupby("server").size().sort_values(ascending=False).reset_index(name="count")
        )

        tmp = broken.groupby(["zone", "issue"]).size().reset_index(name="count").sort_values(["zone", "count"], ascending=[True, False])
        breakdown = (
            tmp.groupby("zone")
            .apply(lambda g: "; ".join([f"{row.issue}:{int(row['count'])}" for _, row in g.iterrows()]))
            .reset_index(name="issue_breakdown")
        )
        worst_zones = counts_by_zone.merge(breakdown, on="zone", how="left")

        weights = {
            "DNSSEC_BOGUS": 10,
            "DNSKEY_INCONSISTENT": 7,
            "DNSKEY_MISSING": 6,
            "RRSIGS_MISSING": 5,
            "NSEC_MISSING": 4,
        }
        broken["severity_weight"] = broken["issue"].map(weights).fillna(1).astype(int)
        severity_score_by_zone = (
            broken.groupby("zone")["severity_weight"].sum().sort_values(ascending=False).reset_index(name="severity_score")
        )

        single_cause = broken.groupby("zone")["issue"].nunique().reset_index(name="distinct_issues")
        single_cause_zones = (
            single_cause[single_cause["distinct_issues"] == 1]
            .merge(broken.groupby("zone")["issue"].first().reset_index(name="only_issue"), on="zone", how="left")
            .merge(counts_by_zone, on="zone", how="left")
            .sort_values("count", ascending=False)
        )

        # co-occurrence pairs
        issue_sets = broken.groupby("zone")["issue"].apply(lambda s: sorted(set(s))).reset_index(name="issues")
        pair_counts: Dict[Tuple[str, str], int] = {}
        for _, row in issue_sets.iterrows():
            issues = row["issues"]
            for i in range(len(issues)):
                for j in range(i + 1, len(issues)):
                    pair = (issues[i], issues[j])
                    pair_counts[pair] = pair_counts.get(pair, 0) + 1
        cooccurrence_pairs = pd.DataFrame(
            [{"issue_a": a, "issue_b": b, "zones_with_pair": c} for (a, b), c in pair_counts.items()]
        )
        if not cooccurrence_pairs.empty:
            cooccurrence_pairs = cooccurrence_pairs.sort_values("zones_with_pair", ascending=False)

        def perspective(server: str) -> str:
            s = (server or "").strip()
            if s.startswith("(validator"):
                return "validator"
            if s.startswith("(authorit"):
                return "authoritative-meta"
            if s.startswith("("):
                return "meta"
            if s == "":
                return "unknown"
            return "authoritative-ns"

        broken["perspective"] = broken["server"].astype(str).apply(perspective)
        perspective_breakdown = (
            broken.groupby(["perspective", "issue"]).size().reset_index(name="count").sort_values(["perspective", "count"], ascending=[True, False])
        )

        # prioritized queue
        per_zone_issue_counts = broken.groupby(["zone", "issue"]).size().reset_index(name="count")
        per_zone_issue_counts["weight"] = per_zone_issue_counts["issue"].map(weights).fillna(1).astype(int)
        per_zone_issue_counts = per_zone_issue_counts.sort_values(["zone", "weight", "count"], ascending=[True, False, False])
        top_issue_per_zone = per_zone_issue_counts.groupby("zone").head(1)[["zone", "issue", "count", "weight"]]

        rep_row = broken.copy()
        rep_row["weight"] = rep_row["issue"].map(weights).fillna(1).astype(int)
        rep_row = rep_row.sort_values(["zone", "weight"], ascending=[True, False]).groupby(["zone", "issue"]).head(1)

        keep_cols = ["zone", "issue", "server"]
        for c in ["repro", "recommendation", "detail_tail"]:
            if c in df.columns:
                keep_cols.append(c)
        rep_row = rep_row[keep_cols]
        prioritized_queue = top_issue_per_zone.merge(rep_row, on=["zone", "issue"], how="left").sort_values(["weight", "count"], ascending=[False, False])

        return {
            "counts_by_issue": counts_by_issue,
            "counts_by_zone": counts_by_zone,
            "issue_by_zone": issue_by_zone,
            "counts_by_server": counts_by_server,
            "worst_zones": worst_zones,
            "severity_score_by_zone": severity_score_by_zone,
            "single_cause_zones": single_cause_zones,
            "cooccurrence_pairs": cooccurrence_pairs,
            "perspective_breakdown": perspective_breakdown,
            "prioritized_queue": prioritized_queue,
        }


class Plotter:
    """Matplotlib plots for analytics outputs."""

    @staticmethod
    def plot_analytics_2x2(a: Dict[str, "pd.DataFrame"], top_issues: int = 12, top_zones: int = 15, heatmap_zones: int = 20, top_pairs: int = 10) -> None:
        if plt is None:
            raise RuntimeError("matplotlib is required for Plotter.plot_analytics_2x2()")
        if pd is None:
            raise RuntimeError("pandas is required for Plotter.plot_analytics_2x2()")

        fig, axs = plt.subplots(2, 2, figsize=(16, 10))
        axs = axs.ravel()

        # 1) Findings by issue
        counts_by_issue = a.get("counts_by_issue", pd.DataFrame())
        ax = axs[0]
        if counts_by_issue is None or counts_by_issue.empty:
            ax.text(0.5, 0.5, "counts_by_issue is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            d = counts_by_issue.head(top_issues)
            ax.bar(d["issue"], d["count"])
            ax.set_title(f"Findings by issue (top {min(top_issues, len(d))})")
            ax.set_ylabel("Count")
            ax.tick_params(axis="x", rotation=45)

        # 2) Severity score by zone
        sev = a.get("severity_score_by_zone", pd.DataFrame())
        ax = axs[1]
        if sev is None or sev.empty:
            ax.text(0.5, 0.5, "severity_score_by_zone is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            d = sev.head(top_zones)
            ax.bar(d["zone"], d["severity_score"])
            ax.set_title(f"Severity score by zone (top {min(top_zones, len(d))})")
            ax.set_ylabel("Severity score")
            ax.tick_params(axis="x", rotation=60)

        # 3) Heatmap issues by zone
        pivot = a.get("issue_by_zone", pd.DataFrame())
        ax = axs[2]
        if pivot is None or pivot.empty:
            ax.text(0.5, 0.5, "issue_by_zone is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            totals = pivot.sum(axis=1).sort_values(ascending=False)
            p = pivot.loc[totals.head(heatmap_zones).index]
            im = ax.imshow(p.values, aspect="auto")
            ax.set_title(f"Issues by zone (top {min(heatmap_zones, p.shape[0])} zones)")
            ax.set_yticks(range(p.shape[0]))
            ax.set_yticklabels(p.index)
            ax.set_xticks(range(p.shape[1]))
            ax.set_xticklabels(p.columns, rotation=45, ha="right")
            fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="Count")

        # 4) Co-occurring issue pairs
        pairs = a.get("cooccurrence_pairs", pd.DataFrame())
        ax = axs[3]
        if pairs is None or pairs.empty:
            ax.text(0.5, 0.5, "cooccurrence_pairs is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            d = pairs.head(top_pairs).copy()
            d["pair"] = d["issue_a"] + " + " + d["issue_b"]
            ax.bar(d["pair"], d["zones_with_pair"])
            ax.set_title(f"Co-occurring issue pairs (top {min(top_pairs, len(d))})")
            ax.set_ylabel("Zones with pair")
            ax.tick_params(axis="x", rotation=60)

        plt.tight_layout()
        plt.show()


# ============================================================
# High-level convenience: one class to wire everything together
# ============================================================

class DNSSECTool:
    """
    High-level façade for the tool.

    Example:
      tool = DNSSECTool(timeout=20)
      df = tool.report(["dnssec-failed.org", "cloudflare.com"])
      a  = tool.analytics(df)
      tool.plot_analytics_2x2(a)
    """

    def __init__(self, timeout: int = 20):
        runner = CommandRunner(timeout=timeout)
        self.dig = DigClient(runner)
        self.delv = DelvValidator(runner)
        self.scanner = DNSSECScanner(self.dig, self.delv)
        self.reporter = Reporter(self.scanner)

    def scan_zone(self, zone: str) -> Dict[str, Any]:
        return self.scanner.scan_zone(zone)

    def report(self, zones: List[str]) -> "pd.DataFrame":
        return self.reporter.report(zones)

    def analytics(self, df: "pd.DataFrame") -> Dict[str, "pd.DataFrame"]:
        return Analytics.compute(df)

    def plot_analytics_2x2(self, a: Dict[str, "pd.DataFrame"], **kwargs: Any) -> None:
        return Plotter.plot_analytics_2x2(a, **kwargs)


__all__ = [
    "DNSSECTool",
    "DNSSECScanner",
    "DNSSECChecks",
    "Reporter",
    "Analytics",
    "Plotter",
    "Recommendations",
    "CommandRunner",
    "DigClient",
    "DelvValidator",
]
