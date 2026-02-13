import os
import socket
from pathlib import Path
# FastAPI creates the app object defines the different routes
from fastapi import FastAPI, Query, HTTPException
# Sends a file from disk efficiently so I don't have to return HTML manually
from fastapi.responses import FileResponse, JSONResponse
# Enables hosting UI assets (JS/CSS/images) from a folder:
from fastapi.staticfiles import StaticFiles
from dcv import DCVTool

# The core engine that actually performs the DNS/DNSSEC checks.
from dnssec.tool import DNSSECTool
from mpic.mpic import MPICChecker
from caa.caa import CAAChecker
from caa.ca_resolver import UnboundValidatingResolver
from dnshealth.tool import DNSHealthTool  # add

# input validation
from reporting.targets import *

# Combine returned checks into a something the user can see
from reporting.assembler import Assemble

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
app = FastAPI(title="DNS Settings Checker")

import socket

RESOLVER_HOST = os.getenv("RESOLVER_HOST", "127.0.0.1")
RESOLVER_PORT = int(os.getenv("RESOLVER_PORT", "5053"))

# Resolve hostnames like "resolver" or "dns-checking-resolver.internal" to an IP for dnspython
try:
    RESOLVER_IP = socket.gethostbyname(RESOLVER_HOST)
except OSError:
    RESOLVER_IP = RESOLVER_HOST  # if it's already an IP or DNS fails, keep as-is

resolver = UnboundValidatingResolver(ip=RESOLVER_IP, port=RESOLVER_PORT, timeout=2.0)

# DNS checking objects
tool = DNSSECTool(timeout=15, strict_dnssec=False)
assembler = Assemble()
mpic = MPICChecker(timeout=3.5, lifetime=3.5)
caa = CAAChecker(resolver=resolver, max_labels=10)
health = DNSHealthTool(timeout=2.0, lifetime=2.0)
dcv = DCVTool(timeout_seconds=2.5, max_redirects=5, dns_timeout=2.0, dns_lifetime=2.0)

# Serve static front-end
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Home page
@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")

# Check a domain
@app.get("/check")
def check(zone: str = Query(..., min_length=1, max_length=253)):
    # Validate + normalize input
    try:
        zone = require_domain(zone)
    except InvalidDomain as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Run the included checkers
    dnssec_result = tool.scan_zone(zone)
    mpic_result = mpic.check_zone(zone)  # <-- NEW (returns MPICResult)
    caa_result = caa.check_zone(zone)
    health_result = health.check_zone(zone)  # add
    dcv_result = dcv.check(zone)

    # Assemble unified payload (findings merged automatically)
    response = assembler.build(
        target=zone,
        checks={
            "dns_health": health_result,  # add
            "dnssec": dnssec_result,
            "mpic": mpic_result,
            "caa": caa_result,
            "dcv": dcv_result,
        },
        meta={"version": "0.1"},
    )
    try:
        checks = response.get("checks") or {}
        unified = response.get("findings") or []
        if isinstance(checks.get("caa"), dict) and isinstance(unified, list):
            checks.enforce_caa_dnssec_policy(checks["caa"], unified)
            # Recompute summary since we may have added a HIGH issue
            response["summary"] = assembler._summarize(unified)  # if _summarize is accessible
    except Exception:
        pass
    return JSONResponse(content=response)