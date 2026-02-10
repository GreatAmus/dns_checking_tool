# test_dnssec_scanner.py
from __future__ import annotations

import importlib.util
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple, Optional

import pytest


# ----------------------------
# Auto-import DnssecScanner
# ----------------------------
def _load_dnssec_scanner_class() -> type:
    """
    Finds a .py file under the project root that contains 'class DnssecScanner'
    and imports DnssecScanner from it.

    This avoids hardcoding 'from yourmodule import DnssecScanner'.
    """
    project_root = Path(__file__).resolve().parent

    # Skip common junk dirs
    skip_dirs = {".venv", "venv", "__pycache__", ".git", ".pytest_cache", "node_modules", "dist", "build"}

    candidates = []
    for py in project_root.rglob("*.py"):
        parts = {p.name for p in py.parents}
        if parts & skip_dirs:
            continue
        try:
            txt = py.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if "class DnssecScanner" in txt:
            candidates.append(py)

    if not candidates:
        raise RuntimeError("Could not find a Python file defining 'class DnssecScanner' under the project root.")

    # Prefer a file name that looks like scanner
    candidates.sort(key=lambda p: (0 if "scanner" in p.name.lower() else 1, len(str(p))))

    target = candidates[0]
    mod_name = f"_dnssec_scanner_under_test_{re.sub(r'\\W+', '_', str(target))}"

    spec = importlib.util.spec_from_file_location(mod_name, target)
    if not spec or not spec.loader:
        raise RuntimeError(f"Failed creating import spec for: {target}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]

    if not hasattr(module, "DnssecScanner"):
        raise RuntimeError(f"Imported {target} but it did not export DnssecScanner")

    return getattr(module, "DnssecScanner")


DnssecScanner = _load_dnssec_scanner_class()


# ----------------------------
# Fake runner to stub dig/delv
# ----------------------------
@dataclass
class _FakeResult:
    output: str


class FakeRunner:
    """
    Minimal stand-in for CommandRunner.

    Provide dig_map/delv_map mapping:
        tuple(args) -> output string
    """
    def __init__(
        self,
        dig_map: Optional[Dict[Tuple[str, ...], str]] = None,
        delv_map: Optional[Dict[Tuple[str, ...], str]] = None,
    ):
        self.dig_map = dig_map or {}
        self.delv_map = delv_map or {}

    def dig(self, args):
        key = tuple(args)
        if key not in self.dig_map:
            raise AssertionError(f"Unexpected dig call:\n  args={args}\nAdd this key to dig_map.")
        return _FakeResult(self.dig_map[key])

    def delv(self, args):
        key = tuple(args)
        # delv outputs aren't always critical; default to empty unless you want strictness
        return _FakeResult(self.delv_map.get(key, ""))


# ----------------------------
# Helpers for building maps
# ----------------------------
def k(*args: str) -> Tuple[str, ...]:
    return tuple(args)


# ----------------------------
# Tests
# ----------------------------

def test_parent_unsigned_skips_child_dnskey_checks():
    """
    If parent isn't signed, we should not require the child to have DNSSEC.
    This should prevent false positives like "DNSKEY_NODATA" for the child.
    """
    dig_map = {
        # scan_zone() -> dig_ns(child)
        k("+short", "google.com.", "NS"): "ns1.google.com.\n",

        # parent zone lookup -> dig_ns(parent)
        k("+short", "com.", "NS"): "a.gtld-servers.net.\n",

        # parent signed? -> query parent DNSKEY at its NS
        # Empty answer means "parent unsigned" in this unit test.
        k("@a.gtld-servers.net", "com.", "DNSKEY", "+dnssec", "+norecurse", "+noall", "+answer"): "",

        # delv_probe called early: delv +rtrace zone SOA
        # (We don't assert on this in this test; but provide something)
    }
    delv_map = {
        k("+rtrace", "google.com.", "SOA"): "insecure\n"
    }

    s = DnssecScanner(runner=FakeRunner(dig_map=dig_map, delv_map=delv_map))
    res = s.scan_zone("google.com")

    issues = {f.issue for f in res.findings}
    assert "DNSKEY_NODATA" not in issues
    assert "DNSKEY_MISSING" not in issues
    # You might emit "PARENT_UNSIGNED" (or similar) depending on your patch; that's fine.


def test_parent_signed_child_no_ds_flags_issue():
    """
    If parent is signed AND parent does not publish DS for the child,
    that is the policy violation we want to catch.
    """
    dig_map = {
        # scan_zone() -> dig_ns(child)
        k("+short", "unsigned-under-signed.com.", "NS"): "ns1.unsigned-under-signed.com.\n",

        # parent zone: com.
        k("+short", "com.", "NS"): "a.gtld-servers.net.\n",

        # parent signed
        k("@a.gtld-servers.net", "com.", "DNSKEY", "+dnssec", "+norecurse", "+noall", "+answer"):
            "com. 86400 IN DNSKEY 257 3 13 ABCD==\n",

        # parent DS for child is missing
        k("@a.gtld-servers.net", "unsigned-under-signed.com.", "DS", "+dnssec", "+norecurse", "+noall", "+answer"): "",
    }
    delv_map = {
        k("+rtrace", "unsigned-under-signed.com.", "SOA"): "secure\n"
    }

    s = DnssecScanner(runner=FakeRunner(dig_map=dig_map, delv_map=delv_map))
    res = s.scan_zone("unsigned-under-signed.com")

    assert any(f.issue == "CHILD_UNSIGNED_UNDER_SIGNED_PARENT" for f in res.findings), \
        f"Findings were: {[f.issue for f in res.findings]}"


def test_parent_signed_ds_exists_but_child_has_no_dnskey_flags_nodata():
    """
    If DS exists at the parent (so we expect the child to be signed),
    and child returns NODATA/SOA-only for DNSKEY, we should flag DNSKEY_NODATA (or equivalent).
    """
    dig_map = {
        # child NS
        k("+short", "broken-signed.com.", "NS"): "ns1.broken-signed.com.\n",

        # parent com NS
        k("+short", "com.", "NS"): "a.gtld-servers.net.\n",

        # parent signed
        k("@a.gtld-servers.net", "com.", "DNSKEY", "+dnssec", "+norecurse", "+noall", "+answer"):
            "com. 86400 IN DNSKEY 257 3 13 ABCD==\n",

        # parent publishes DS for child
        k("@a.gtld-servers.net", "broken-signed.com.", "DS", "+dnssec", "+norecurse", "+noall", "+answer"):
            "broken-signed.com. 86400 IN DS 12345 13 2 DEADBEEF\n",

        # compare_dnskey_across_ns uses dig_answer() -> +dnssec +noall +answer
        k("@ns1.broken-signed.com", "broken-signed.com.", "DNSKEY", "+dnssec", "+noall", "+answer"): "",

        # check_authoritative_ns uses dig_dnssec_sections() -> +answer +authority +comments
        k("@ns1.broken-signed.com", "broken-signed.com.", "DNSKEY", "+dnssec", "+noall", "+answer", "+authority", "+comments"):
            "broken-signed.com. 60 IN SOA ns1.broken-signed.com. hostmaster.broken-signed.com. 1 900 900 1800 60\n",
    }
    delv_map = {
        k("+rtrace", "broken-signed.com.", "SOA"): "secure\n"
    }

    s = DnssecScanner(runner=FakeRunner(dig_map=dig_map, delv_map=delv_map))
    res = s.scan_zone("broken-signed.com")

    assert any(f.issue in {"DNSKEY_NODATA", "DNSKEY_MISSING"} for f in res.findings), \
        f"Findings were: {[f.issue for f in res.findings]}"
