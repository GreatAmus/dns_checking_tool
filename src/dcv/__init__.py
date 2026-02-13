"""
Domain Control Validation (DCV) readiness checks.

Supports modern methods commonly used by ACME/CAs:
  - HTTP-01 (port 80)
  - DNS-01 (TXT at _acme-challenge.<domain>)
  - TLS-ALPN-01 (port 443, ALPN support)
"""

from .tool import DCVTool

__all__ = ["DCVTool"]