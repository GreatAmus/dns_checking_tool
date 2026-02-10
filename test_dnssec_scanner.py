# test_dnssec_scanner.py
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pytest

from dnssec_scanner import DnssecScanner


# ----------------------------
# Flexible FakeRunner
# ----------------------------
@dataclass
class _FakeResult:
    output: str


class FlexibleFakeRunner:
    """
    Fake runner that matches dig() calls by required tokens rather than exact arg lists.

    Provide rules like:
      dig_rules = [
        (["@a.gtld-servers.net", "com.", "DNSKEY"], "....output...."),
        (["+short", "com.", "NS"], "a.gtld-servers.net.\n"),
      ]
    The first rule whose required tokens are all present (in order-independent "contains" sense)
    wins.
    """
    def __init__(
        self,
        dig_rules: List[Tuple[List[str], str]],
        delv_output: str = "",
    ):
        self.dig_rules = dig_rules
        self.delv_output = delv_output

    def dig(self, args: List[str]) -> _FakeResult:
        for required, out in self.dig_rules:
            if all(tok in args for tok in required):
                return _FakeResult(out)
        raise AssertionError(
            "Unexpected dig call:\n"
            f"  args={args}\n"
            "No dig_rules matched. Add a rule with required tokens that appear in args."
        )

    def delv(self, args: List[str]) -> _FakeResult:
        return _FakeResult(self.delv_output)


# ----------------------------
# Unit tests (deterministic)
# ----------------------------
def test_unit_parent_unsigned_skips_dnskey_checks():
    """
    If parent isn't signed, scan returns early and does NOT emit DNSKEY_* issues.
    """
    runner = FlexibleFakeRunner(
        dig_rules=[
            (["+short", "google.com.", "NS"], "ns1.google.com.\n"),
            (["+short", "com.", "NS"], "a.gtld-servers.net.\n"),

            # Parent DNSKEY query (any options) => empty ANSWER => treat as unsigned
            (["@a.gtld-servers.net", "com.", "DNSKEY"], ""),
        ],
        delv_output="insecure\n",
    )

    s = DnssecScanner(runner=runner, include_unsigned_finding=False)
    res = s.scan_zone("google.com")

    issues = {f.issue for f in res.findings}
    assert "DNSKEY_NODATA" not in issues
    assert "DNSKEY_INCONSISTENT" not in issues
    assert "DNSKEY_MISSING" not in issues


def test_unit_parent_signed_child_no_ds_is_not_required_to_be_signed_when_policy_silent():
    """
    This asserts your desired behavior: if no DS at parent, the child is not required to be signed
    and we do not produce DNSKEY_* warnings.
    """
    runner = FlexibleFakeRunner(
        dig_rules=[
            # child NS
            (["+short", "unsigned.com.", "NS"], "ns1.unsigned.com.\n"),

            # parent NS
            (["+short", "com.", "NS"], "a.gtld-servers.net.\n"),

            # parent signed => has DNSKEY
            (["@a.gtld-servers.net", "com.", "DNSKEY"], "com. 86400 IN DNSKEY 257 3 13 ABCD==\n"),

            # no DS for child at parent
            (["@a.gtld-servers.net", "unsigned.com.", "DS"], ""),
        ],
        delv_output="secure\n",
    )

    s = DnssecScanner(runner=runner, include_unsigned_finding=False)
    res = s.scan_zone("unsigned.com")

    issues = {f.issue for f in res.findings}
    assert "DNSKEY_NODATA" not in issues
    assert "DNSKEY_INCONSISTENT" not in issues
    assert "DNSKEY_MISSING" not in issues
    # Depending on your code, you may return early with no findings at all, which is fine.


def test_unit_ds_exists_then_missing_dnskey_is_real_problem():
    """
    If DS exists (child should be signed), and child returns SOA-only / no DNSKEY,
    we should flag DNSKEY_NODATA.
    """
    runner = FlexibleFakeRunner(
        dig_rules=[
            (["+short", "broken.com.", "NS"], "ns1.broken.com.\n"),
            (["+short", "com.", "NS"], "a.gtld-servers.net.\n"),

            # parent signed
            (["@a.gtld-servers.net", "com.", "DNSKEY"], "com. 86400 IN DNSKEY 257 3 13 ABCD==\n"),

            # DS exists
            (["@a.gtld-servers.net", "broken.com.", "DS"], "broken.com. 86400 IN DS 12345 13 2 DEADBEEF\n"),

            # child DNSKEY queries return nothing in ANSWER; authority SOA shows up in the
            # dig_dnssec_sections() path; your code checks for " dnskey " in output.
            (["@ns1.broken.com", "broken.com.", "DNSKEY"], "broken.com. 60 IN SOA ns1.broken.com. hostmaster.broken.com. 1 900 900 1800 60\n"),
        ],
        delv_output="secure\n",
    )

    s = DnssecScanner(runner=runner, include_unsigned_finding=False)
    res = s.scan_zone("broken.com")

    issues = [f.issue for f in res.findings]
    assert "DNSKEY_NODATA" in issues


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
        out = _run(["dig", f"@{ns}", child, "DS", "+dnssec", "+tcp", "+norecurse", "+noall", "+answer", "+comments"], timeout=10)
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
    ds_state = _parent_ds_exists(domain)
    if ds_state is None:
        pytest.skip("Could not determine DS state from parent NS (network/path issue).")

    scanner = DnssecScanner(include_unsigned_finding=False)
    zr = scanner.scan_zone(domain)
    issues = {f.issue for f in zr.findings}

    dnskey_warnings = {"DNSKEY_NODATA", "DNSKEY_INCONSISTENT", "DNSKEY_MISSING"}

    if ds_state is False:
        assert dnskey_warnings.isdisjoint(issues), f"{domain} DS absent but scanner emitted DNSKEY warnings: {issues}"
    else:
        assert zr.nameservers, "Scanner did not discover nameservers"
        # It's okay if ns_consistency is {} when you early-return on some failures, but it
        # should not be empty due to skipping when DS exists.
