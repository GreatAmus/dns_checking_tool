from fastapi import FastAPI, Query, HTTPException
from dnssec_tool import DNSSECTool

app = FastAPI(title="DNS Settings Checker")
tool = DNSSECTool(timeout=15)

@app.get("/check")
def check(zone: str = Query(..., min_length=1, max_length=253)):
    zone = zone.strip().rstrip(".")
    if not zone or any(c.isspace() for c in zone):
        raise HTTPException(status_code=400, detail="Invalid zone")
    return tool.scan_zone(zone)

@app.get("/health")
def health():
    return {"ok": True}