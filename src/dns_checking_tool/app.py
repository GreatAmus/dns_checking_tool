from pathlib import Path
# FastAPI creates the app object defines the different routes
from fastapi import FastAPI, Query, HTTPException
# Sends a file from disk efficiently so I don't have to return HTML manually
from fastapi.responses import FileResponse, JSONResponse
# Enables hosting UI assets (JS/CSS/images) from a folder:
from fastapi.staticfiles import StaticFiles

# The core engine that actually performs the DNS/DNSSEC checks.
from src.dnssec.tool import DNSSECTool
from src.mpic.mpic import MPICChecker
from caa import CAAChecker
from caa import CAAChecker
from src.caa.ca_resolver import UnboundValidatingResolver, SystemResolver, CAFailClosedResolver

# input validation
from src.reporting.targets import require_domain, InvalidDomain

# Combine returned checks into a something the user can see
from src.reporting.assembler import Assemble

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
app = FastAPI(title="DNS Settings Checker")

# DNS checking objects
tool = DNSSECTool(timeout=15, strict_dnssec=False)
assembler = Assemble()
mpic = MPICChecker(timeout=3.5, lifetime=3.5)
resolver = UnboundValidatingResolver(ip="127.0.0.1", port=5053, timeout=2.0, lifetime=2.0)
caa = CAAChecker(resolver=resolver, max_labels=10)

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
    dnssec_result = tool.scan_zone(zone)
    caa_result = caa.check_zone(zone)

    # Assemble unified payload (findings merged automatically)
    response = assembler.build(
        target=zone,
        checks={
            "dnssec": dnssec_result,
            "mpic": mpic_result,
            "caa": caa_result,
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