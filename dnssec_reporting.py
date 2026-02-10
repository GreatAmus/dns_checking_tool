from typing import List, Tuple, Dict, Any, Optional
import pandas as pd
from dnssec_scanner import DnssecScanner
from dnssec_analytics import ReportAnalyzer

def reporting(zones: List[str], scanner: Optional[DnssecScanner] = None) -> pd.DataFrame:
    scanner = scanner or DnssecScanner()
    rows: List[Dict[str, Any]] = []

    for z in zones:
        zr = scanner.scan_zone(z)
        for f in zr.findings:
            rows.append({
                "zone": f.zone,
                "server": f.server,
                "issue": f.issue,
                "repro": f.repro,
                "detail_tail": f.detail_tail,
            })

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    # consistent sorting
    issue_rank = {
        "DNSSEC_BOGUS": 0,
        "DNSKEY_INCONSISTENT": 1,
        "NS_UNREACHABLE": 2,
        "NS_REFUSED": 3,
        "DNSKEY_NODATA": 4,
        "DNSSEC_UNSIGNED": 8,
        "OK": 9,
    }
    df["_rank"] = df["issue"].map(issue_rank).fillna(50).astype(int)
    df = df.sort_values(["_rank", "zone", "server"]).drop(columns=["_rank"]).reset_index(drop=True)
    return df


def run_dnssec_report(domains: List[str], scanner: Optional[DnssecScanner] = None) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    df = reporting(domains, scanner=scanner)
    analyzer = ReportAnalyzer()
    a = analyzer.analytics(df)
    return df, a
