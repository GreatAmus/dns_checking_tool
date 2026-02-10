from typing import List, Tuple, Dict, Any, Optional
import pandas as pd
from dnssec_scanner import DnssecScanner
from dnssec_analytics import ReportAnalyzer
from dnssec_plot import Recommendations

# Columns you likely want in the main UI/table
DEFAULT_COLUMNS = ["zone", "issue", "recommendation"]

# Useful for drill-down, but noisy for the main table
DEBUG_COLUMNS = ["server", "repro", "detail_tail"]


def reporting(
    zones: List[str],
    scanner: Optional[DnssecScanner] = None,
    include_debug: bool = False,
) -> pd.DataFrame:
    scanner = scanner or DnssecScanner()
    rows: List[Dict[str, Any]] = []

    for z in zones:
        zr = scanner.scan_zone(z)

        # If your scanner can return "no findings" for a pass, emit an OK row.
        if not zr.findings:
            rows.append({
                "zone": zr.zone,
                "issue": "OK",
                "recommendation": Recommendations.recommend("OK"),
            })
            continue

        for f in zr.findings:
            row = {
                "zone": f.zone,
                "issue": f.issue,
                "recommendation": Recommendations.recommend(f.issue),
            }

            if include_debug:
                row.update({
                    "server": f.server,
                    "repro": f.repro,
                    "detail_tail": f.detail_tail,
                })

            rows.append(row)

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    # consistent sorting
    issue_rank = {
        "DNSSEC_BOGUS": 0,
        "DNSKEY_INCONSISTENT": 1,
        "NS_UNREACHABLE": 2,
        "NS_REFUSED": 3,
        "CHILD_UNSIGNED_UNDER_SIGNED_PARENT": 4,
        "DNSKEY_NODATA": 5,
        "DNSKEY_MISSING": 6,
        "RRSIGS_MISSING": 7,
        "NSEC_MISSING": 8,
        "DNSSEC_UNSIGNED": 90,
        "PARENT_UNSIGNED": 91,
        "OK": 99,
    }
    df["_rank"] = df["issue"].astype(str).str.upper().map(issue_rank).fillna(50).astype(int)

    # Sort; if server missing (non-debug mode), handle gracefully
    sort_cols = ["_rank", "zone"]
    if "server" in df.columns:
        sort_cols.append("server")

    df = df.sort_values(sort_cols).drop(columns=["_rank"]).reset_index(drop=True)

    # Keep only the columns we want (in a stable order)
    wanted = DEFAULT_COLUMNS + (DEBUG_COLUMNS if include_debug else [])
    wanted = [c for c in wanted if c in df.columns]
    df = df[wanted]

    return df


def run_dnssec_report(
    domains: List[str],
    scanner: Optional[DnssecScanner] = None,
    include_debug: bool = False,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    df = reporting(domains, scanner=scanner, include_debug=include_debug)
    analyzer = ReportAnalyzer()
    a = analyzer.analytics(df)
    return df, a