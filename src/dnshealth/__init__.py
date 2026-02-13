"""
DNS health / misconfiguration checks.

This package is intentionally DNSSEC-agnostic: it focuses on common delegation and
authoritative misconfigurations that cause flaky or broken resolution.

Public entrypoint: DNSHealthTool
"""

from .tool import DNSHealthTool

__all__ = ["DNSHealthTool"]
