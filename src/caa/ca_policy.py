# ca_policy.py
from __future__ import annotations
from typing import Any, Dict, List


def enforce_caa_dnssec_policy(caa_check: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
    """
    CA-like policy for March 15, 2026:
      - DNSSEC validation errors during CAA lookup MUST NOT be treated as permission to issue.

    We model this as a CRITICAL/HIGH finding in this tool.

    Inputs:
      caa_check: JSON-safe dict from checks["caa"] (i.e., caa_result.to_dict()).
      findings: unified findings list (mutated in place).
    """
    lookup = (caa_check or {}).get("lookup") or {}
    rcode = str(lookup.get("rcode") or "").upper()
    validated = bool(lookup.get("validated"))
    eff = str((caa_check or {}).get("effective_domain") or "").strip()

    # Fail-closed conditions for CA-like behavior:
    bad_rcodes = {"SERVFAIL", "TIMEOUT", "ERROR"}
    if rcode in bad_rcodes or not validated:
        detail_bits = []
        if eff:
            detail_bits.append(f"effective_domain={eff}")
        detail_bits.append(f"rcode={rcode or 'unknown'}")
        detail_bits.append(f"validated={validated}")

        err = lookup.get("error")
        if err:
            detail_bits.append(f"error={err}")

        findings.append({
            "check": "caa",
            "issue": "CAA_DNSSEC_VALIDATION_CRITICAL",
            "severity": "high",
            "title": "CAA lookup not DNSSEC-validated (CA-style hard stop)",
            "detail": (
                "CAA authorization must be based on DNSSEC-validated lookups (back to the root trust anchor). "
                "Validation failures or uncertainty must NOT be treated as permission to issue. "
                f"Observed: {', '.join(detail_bits)}."
            ),
        })
