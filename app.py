import io
from typing import Any, Dict, List

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # server-safe (no GUI)
import matplotlib.pyplot as plt

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from dnssec_tool import DNSSECTool, Analytics  # from your existing module


app = FastAPI(title="DNS Settings Checker")
tool = DNSSECTool(timeout=15)

# Serve static front-end
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    return {"ok": True}

@app.get("/check")
def check(zone: str = Query(..., min_length=1, max_length=253)):
    zone = zone.strip().rstrip(".")
    if not zone or any(c.isspace() for c in zone):
        raise HTTPException(status_code=400, detail="Invalid zone")

    result = tool.scan_zone(zone)
    return jsonable_encoder(result)

def plot_analytics_2x2_to_png(a: Dict[str, pd.DataFrame],
                             top_issues: int = 12,
                             top_zones: int = 15,
                             heatmap_zones: int = 20,
                             top_pairs: int = 10) -> bytes:
    """
    Adaptation of Plotter.plot_analytics_2x2() that returns a PNG instead of plt.show().
    Your original creates a 2x2 figure from keys like:
    counts_by_issue, severity_score_by_zone, issue_by_zone, cooccurrence_pairs. :contentReference[oaicite:3]{index=3}
    """
    fig, axs = plt.subplots(2, 2, figsize=(16, 10))
    axs = axs.ravel()

    # 1) Findings by issue
    counts_by_issue = a.get("counts_by_issue", pd.DataFrame())
    ax = axs[0]
    if counts_by_issue is None or counts_by_issue.empty:
        ax.text(0.5, 0.5, "counts_by_issue is empty", ha="center", va="center")
        ax.set_axis_off()
    else:
        d = counts_by_issue.head(top_issues)
        ax.bar(d["issue"], d["count"])
        ax.set_title(f"Findings by issue (top {min(top_issues, len(d))})")
        ax.set_ylabel("Count")
        ax.tick_params(axis="x", rotation=45)

    # 2) Severity score by zone
    sev = a.get("severity_score_by_zone", pd.DataFrame())
    ax = axs[1]
    if sev is None or sev.empty:
        ax.text(0.5, 0.5, "severity_score_by_zone is empty", ha="center", va="center")
        ax.set_axis_off()
    else:
        d = sev.head(top_zones)
        ax.bar(d["zone"], d["severity_score"])
        ax.set_title(f"Severity score by zone (top {min(top_zones, len(d))})")
        ax.set_ylabel("Severity score")
        ax.tick_params(axis="x", rotation=60)

    # 3) Heatmap issues by zone
    pivot = a.get("issue_by_zone", pd.DataFrame())
    ax = axs[2]
    if pivot is None or pivot.empty:
        ax.text(0.5, 0.5, "issue_by_zone is empty", ha="center", va="center")
        ax.set_axis_off()
    else:
        totals = pivot.sum(axis=1).sort_values(ascending=False)
        p = pivot.loc[totals.head(heatmap_zones).index]
        im = ax.imshow(p.values, aspect="auto")
        ax.set_title(f"Issues by zone (top {min(heatmap_zones, p.shape[0])} zones)")
        ax.set_yticks(range(p.shape[0]))
        ax.set_yticklabels(p.index)
        ax.set_xticks(range(p.shape[1]))
        ax.set_xticklabels(p.columns, rotation=45, ha="right")
        fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="Count")

    # 4) Co-occurring issue pairs
    pairs = a.get("cooccurrence_pairs", pd.DataFrame())
    ax = axs[3]
    if pairs is None or pairs.empty:
        ax.text(0.5, 0.5, "cooccurrence_pairs is empty", ha="center", va="center")
        ax.set_axis_off()
    else:
        d = pairs.head(top_pairs).copy()
        d["pair"] = d["issue_a"] + " + " + d["issue_b"]
        ax.bar(d["pair"], d["zones_with_pair"])
        ax.set_title(f"Co-occurring issue pairs (top {min(top_pairs, len(d))})")
        ax.set_ylabel("Zones with pair")
        ax.tick_params(axis="x", rotation=60)

    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160, bbox_inches="tight")
    plt.close(fig)
    return buf.getvalue()


@app.get("/graph.png")
def graph(zone: str = Query(..., min_length=1, max_length=253)) -> Response:
    zone = zone.strip().rstrip(".")
    if not zone or any(c.isspace() for c in zone):
        raise HTTPException(status_code=400, detail="Invalid zone")

    # Build a 1-zone report -> analytics -> plot
    df = tool.report([zone])
    a = Analytics.compute(df)
    png = plot_analytics_2x2_to_png(a)
    return Response(content=png, media_type="image/png")
