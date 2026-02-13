
import argparse
import json
from typing import Any, Dict, List
from reporting.assembler import Assemble
from dnssec.tool import DNSSECTool
from mpic.mpic import MPICChecker
from caa.caa import CAAChecker
from reporting.targets import *
from dnshealth.tool import DNSHealthTool

"""
The command-line interface for the DNS Checker (DNSSEC + MPIC + CAA)
The command-line interface mirros the flow of the API
  1) Validate + normalize each user-provided domain (require_domain)
  2) Run checkers
  3) Assemble the results into a single consistent JSON-safe response using Assemble.build()

"""

# Input validation/normalization used by app.py.
from reporting.targets import InvalidDomain, require_domain

# Parse the command-line arguemetns
def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="DNS Checker CLI (DNSSEC + MPIC)")
    p.add_argument("zones", nargs="+", help="Domain/zone names (e.g., example.com)")
    p.add_argument("--json", dest="as_json", action="store_true", help="Output JSON")
    p.add_argument("--no-mpic", action="store_true", help="Disable MPIC checks")

    # Timeouts: match the defaults you're using in app.py, but let CLI override them.
    p.add_argument("--dnssec-timeout", type=float, default=15.0, help="DNSSEC timeout (seconds)")
    p.add_argument("--mpic-timeout", type=float, default=3.5, help="MPIC timeout (seconds)")
    p.add_argument("--mpic-lifetime", type=float, default=3.5, help="MPIC lifetime (seconds)")

    # Included in response["meta"] so you can track CLI output versions.
    p.add_argument("--version", default="0.1", help="Version string included in output meta")
    p.add_argument("--no-health", action="store_true", help="Disable DNS health checks")

    return p.parse_args(argv)


def validate_zones(raw_zones: List[str]) -> List[str]:
    """
    Validate + normalize all zones.

    We validate everything first so errors are reported together and we don't do partial work.

    Args:
        raw_zones: User-provided zone strings.

    Returns:
        List of normalized zones.

    Raises:
        SystemExit(2): if any zones are invalid.
    """
    normalized: List[str] = []
    errors: List[str] = []

    for z in raw_zones:
        try:
            normalized.append(require_domain(z))
        except InvalidDomain as e:
            errors.append(f"{z}: {e}")

    if errors:
        for e in errors:
            print(f"Invalid input: {e}")
        raise SystemExit(2)

    return normalized

def run_checks_for_zone(
    zone: str,
    dnssec_tool: DNSSECTool,
    mpic_tool: MPICChecker,
    health_tool: DNSHealthTool,   # <-- add
    assembler: Assemble,
    enable_mpic: bool,
    enable_health: bool,          # <-- add
    version: str,
) -> Dict[str, Any]:
    checks: Dict[str, Any] = {"dnssec": dnssec_tool.scan_zone(zone)}

    if enable_mpic:
        checks["mpic"] = mpic_tool.check_zone(zone)

    if enable_health:
        checks["dns_health"] = health_tool.check_zone(zone)

    return assembler.build(
        target=zone,
        checks=checks,
        meta={"version": version, "source": "cli"},
    )



def print_human(zone_response: Dict[str, Any]) -> None:
    """
    Print a readable console output for a single zone.

    Args:
        zone_response: Response dict from assembler.build().
    """
    target = zone_response.get("target", "")
    summary = zone_response.get("summary") or {}
    findings = zone_response.get("findings") or []

    print(f"\n== {target} ==")
    print(
        f"Issues: {summary.get('issues', 0)} | "
        f"High: {summary.get('high', 0)} | "
        f"Medium: {summary.get('medium', 0)} | "
        f"Low: {summary.get('low', 0)} | "
        f"Info: {summary.get('info', 0)} | "
        f"Score: {summary.get('score', 0)}"
    )

    if not findings:
        print("No findings.")
        return

    for f in findings:
        check = f.get("check", "")
        issue = f.get("issue", "")
        sev = f.get("severity", "unknown")
        msg = f.get("message", "")
        rec = f.get("recommendation", "")

        line = f"- [{sev}] {check}:{issue}"
        if msg:
            line += f" — {msg}"
        print(line)
        if rec:
            print(f"    Recommendation: {rec}")


def main(argv: List[str] | None = None) -> int:
    """
    CLI entrypoint.

    Returns:
        Process exit code (0 = success).
    """
    args = parse_args(argv)

    # Validate all zones up-front.
    zones = validate_zones(args.zones)

    # Create tools once and reuse for all zones (faster than recreating per zone).
    dnssec_tool = DNSSECTool(timeout=args.dnssec_timeout, strict_dnssec=True)
    mpic_tool = MPICChecker(timeout=args.mpic_timeout, lifetime=args.mpic_lifetime)
    health_tool = DNSHealthTool(timeout=2.0, lifetime=2.0)
    assembler = Assemble()

    # Run checks for each zone.
    results: List[Dict[str, Any]] = []
    for zone in zones:
        results.append(
            run_checks_for_zone(
                zone=zone,
                dnssec_tool=dnssec_tool,
                mpic_tool=mpic_tool,
                health_tool=health_tool,             # <-- add
                assembler=assembler,
                enable_mpic=not args.no_mpic,
                enable_health=not args.no_health,    # <-- add
                version=args.version,
            )
        )

    # Output: JSON (machine-readable) or human-readable text
    if args.as_json:
        out = {"targets": zones, "results": results}
        print(json.dumps(out, indent=2))
    else:
        for r in results:
            print_human(r)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
