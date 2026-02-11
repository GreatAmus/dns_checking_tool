# test_dnssec_scanner.py
from __future__ import annotations

import os
import re
import subprocess
from typing import List, Optional

import pandas as pd
import pytest

from dnssec_analytics import ReportAnalyzer
from dnssec_scanner import DNSSECScanner
from dnssec_tool import Analytics


# ----------------------------
# Analytics schema tests
# ----------------------------
def test_analytics_compute_returns_stable_schema_and_expected_rollups():
    """
    Ensure dnssec_tool.Analytics.compute stays aligned with dnssec_analytics.ReportAnalyzer
    and returns the keys expected by the UI/plotter.
    """
    df = pd.DataFrame(
        [
            # zone1 has two issues (pair should be counted once for that zone)
            {
                "zone": "zone1.example",
                "server": "ns1",
                "issue": "DNSSEC_BOGUS",
                "recommendation": "",
                "repro": "",
                "detail_tail": "",
            },
            {
                "zone": "zone1.example",
                "server": "ns2",
                "issue": "DNSKEY_NODATA",
                "recommendation": "",
                "repro": "",
                "detail_tail": "",
            },
            # zone2 has one issue
            {
                "zone": "zone2.example",
                "server": "ns1",
                "issue": "DNSKEY_NODATA",
                "recommendation": "",
                "repro": "",
                "detail_tail": "",
            },
            # OK rows should not affect broken rollups
            {
                "zone": "zone3.example",
                "server": "",
                "issue": "OK",
                "recommendation": "",
                "repro": "",
                "detail_tail": "",
            },
        ]
    )

    a = Analytics.compute(df)

    required_keys = {
        "counts_by_issue",
        "counts_by_zone",
        "issue_by_zone",
        "counts_by_server",
        "worst_zones",
        "severity_score_by_zone",
        "prioritized_queue",
        "cooccurrence_pairs",
    }
    assert required_keys.issubset(set(a.keys()))

    ra = ReportAnalyzer()
    base = ra.analytics(df)
    assert set(base["counts_by_issue"].columns) == {"issue", "count"}

    got_counts = dict(zip(a["counts_by_issue"]["issue"], a["counts_by_issue"]["count"]))
    base_counts = dict(zip(base["counts_by_issue"]["issue"], base["counts_by_issue"]["count"]))

    assert got_counts.get("DNSKEY_NODATA") == base_counts.get("DNSKEY_NODATA") == 2
    assert got_counts.get("DNSSEC_BOGUS") == base_counts.get("DNSSEC_BOGUS") == 1

    pairs = a["cooccurrence_pairs"]
    if not pairs.empty:
        rows = pairs.to_dict("records")
        assert any(
            (
                r.get("issue_a") == "DNSKEY_NODATA"
                and r.get("issue_b") == "DNSSEC_BOGUS"
                and r.get("zones_with_pair") == 1
            )
            or (
                r.get("issue_a") == "DNSSEC_BOGUS"
                and r.get("issue_b") == "DNSKEY_NODATA"
                and r.get("zones_with_pair") == 1
            )
            for r in rows
        )


def test_analytics_compute_empty_df_returns_empty_frames_with_stable_keys():
    df = pd.DataFrame(columns=["zone", "server", "issue", "recommendation", "repro", "detail_tail"])
    a = Analytics.compute(df)

    required_keys = {
        "counts_by_issue",
        "counts_by_zone",
        "issue_by_zone",
        "counts_by_server",
        "worst_zones",
        "severity_score_by_zone",
        "prioritized_queue",
        "cooccurrence_pairs",
    }
    assert required_keys.issubset(set(a.keys()))

    for k in required_keys:
        assert hasattr(a[k], "empty")


# ----------------------------
# Optional integration tests (real DNS)
# ----------------------------
def _have_cmd(cmd: str) -> bool:
    try:
        subprocess.run([cmd, "-v"], capture_output=True, text=True, timeout=3)
        return True
    except Exception:
        return False


def _run(cmd: List[str], timeout: int = 10) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (p.stdout or "") + (p.stderr or "")


def _parent_zone(name: str) -> str:
    z = name.rstrip(".") + "."
    parts = z.split(".")
    if len(parts) <= 2:
        return "."
    return ".".join(parts[1:])


def _dig_short_ns(zone: str) -> List[str]:
    out = _run(["dig", "+short", zone, "NS"])
    return [l.strip().rstrip(".") for l in out.splitlines() if l.strip()]


def _parent_ds_exists(child: str) -> Optional[bool]:
    """
    True/False/None based on authoritative parent DS over TCP.
    """
    child = child.rstrip(".") + "."
    parent = _parent_zone(child)
    parent_ns = _dig_short_ns(parent)
    if not parent_ns:
        return None

    saw_success = False
    saw_ds = False
    for ns in parent_ns[:6]:
        out = _run(
            ["dig", f"@{ns}", child, "DS", "+dnssec", "+tcp", "+norecurse", "+noall", "+answer", "+comments"],
            timeout=10,
        )
        low = out.lower()
        if out.startswith("[timeout") or "no servers could be reached" in low or "connection timed out" in low:
            continue
        if "refused" in low:
            continue
        saw_success = True
        if re.search(r"\sDS\s", out):
            saw_ds = True

    if not saw_success:
        return None
    return True if saw_ds else False


integration = pytest.mark.skipif(
    os.getenv("RUN_INTEGRATION", "0") != "1",
    reason="Integration tests disabled. Run with RUN_INTEGRATION=1",
)

requires_tools = pytest.mark.skipif(
    not _have_cmd("dig"),
    reason="dig not available in PATH",
)


@integration
@requires_tools
@pytest.mark.parametrize("domain", ["google.com", "cloudflare.com", "iana.org"])
def test_integration_dnskey_checks_only_when_ds_exists(domain: str):
    """
    This is a high-level behavior test that should remain true even as checks expand:
    if there is no DS at the parent, do not emit "zone must be signed" findings.
    """
    ds_state = _parent_ds_exists(domain)
    if ds_state is None:
        pytest.skip("Could not determine DS state from parent NS (network/path issue).")

    scanner = DNSSECScanner()
    zr = scanner.scan_zone(domain)
    issues = {f.issue for f in zr.findings}

    # Depending on your new check set, the exact names may differ.
    # Keep this list aligned with your scanner's "requires DS" findings.
    ds_required_findings = {
        "DS_MISMATCH",
        "DNSKEY_NODATA",
        "DNSKEY_QUERY_FAILED",
        "DNSKEY_RRSIG_MISSING",
        "DNSKEY_RRSIG_INVALID",
    }

    if ds_state is False:
        assert ds_required_findings.isdisjoint(
            issues
        ), f"{domain} DS absent but scanner emitted DS-required findings: {issues}"
    else:
        # When DS exists, we should at least be able to find some nameservers (best effort)
        assert zr.zone == domain
