# NOTE THIS IS NOT USED RIGHT NOW. Once I re-enable scanning on a list of domains, then I may add it back in
import io
from typing import Dict, Any


class DNSSECCharts:
    """
    Renders a 2x2 "dashboard" PNG from analytics DataFrames.

    Expected input:
      analytics: Dict[str, pandas.DataFrame]
        - counts_by_issue
        - severity_score_by_zone
        - issue_by_zone
        - cooccurrence_pairs

    Output:
      PNG bytes suitable for returning via FastAPI Response(content=..., media_type="image/png")
    """

    def __init__(
        self,
        top_issues: int = 12,
        top_zones: int = 15,
        heatmap_zones: int = 20,
        top_pairs: int = 10,
        figsize: tuple[int, int] = (16, 10),
        dpi: int = 160,
    ) -> None:
        self.top_issues = top_issues
        self.top_zones = top_zones
        self.heatmap_zones = heatmap_zones
        self.top_pairs = top_pairs
        self.figsize = figsize
        self.dpi = dpi

    @staticmethod
    def _lazy_import_plotting():
        """
        Import heavy plotting libs only when needed.

        Why:
        - Keeps FastAPI startup fast/light.
        - Lets you run the API without matplotlib/pandas unless you hit /graph.png.
        """
        import pandas as pd  # noqa: F401

        import matplotlib
        matplotlib.use("Agg")  # non-GUI backend safe for servers
        import matplotlib.pyplot as plt  # noqa: F401

        return pd, plt

    def render_dashboard_png(self, analytics: Dict[str, Any]) -> bytes:
        """
        Render the 2x2 dashboard as PNG bytes.

        We keep this method defensive:
        - If any expected DataFrame is missing/empty, we write a small note instead of failing.
        """
        pd, plt = self._lazy_import_plotting()

        fig, axs = plt.subplots(2, 2, figsize=self.figsize)
        axs = axs.ravel()

        # 1) Findings by issue
        counts_by_issue = analytics.get("counts_by_issue", pd.DataFrame())
        ax = axs[0]
        if counts_by_issue is None or counts_by_issue.empty:
            ax.text(0.5, 0.5, "counts_by_issue is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            d = counts_by_issue.head(self.top_issues)
            ax.bar(d["issue"], d["count"])
            ax.set_title(f"Findings by issue (top {min(self.top_issues, len(d))})")
            ax.set_ylabel("Count")
            ax.tick_params(axis="x", rotation=45)

        # 2) Severity score by zone
        sev = analytics.get("severity_score_by_zone", pd.DataFrame())
        ax = axs[1]
        if sev is None or sev.empty:
            ax.text(0.5, 0.5, "severity_score_by_zone is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            d = sev.head(self.top_zones)
            ax.bar(d["zone"], d["severity_score"])
            ax.set_title(f"Severity score by zone (top {min(self.top_zones, len(d))})")
            ax.set_ylabel("Severity score")
            ax.tick_params(axis="x", rotation=60)

        # 3) Heatmap: issues by zone
        pivot = analytics.get("issue_by_zone", pd.DataFrame())
        ax = axs[2]
        if pivot is None or pivot.empty:
            ax.text(0.5, 0.5, "issue_by_zone is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            totals = pivot.sum(axis=1).sort_values(ascending=False)
            p = pivot.loc[totals.head(self.heatmap_zones).index]
            im = ax.imshow(p.values, aspect="auto")
            ax.set_title(f"Issues by zone (top {min(self.heatmap_zones, p.shape[0])} zones)")
            ax.set_yticks(range(p.shape[0]))
            ax.set_yticklabels(p.index)
            ax.set_xticks(range(p.shape[1]))
            ax.set_xticklabels(p.columns, rotation=45, ha="right")
            fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="Count")

        # 4) Co-occurring issue pairs
        pairs = analytics.get("cooccurrence_pairs", pd.DataFrame())
        ax = axs[3]
        if pairs is None or pairs.empty:
            ax.text(0.5, 0.5, "cooccurrence_pairs is empty", ha="center", va="center")
            ax.set_axis_off()
        else:
            d = pairs.head(self.top_pairs).copy()
            d["pair"] = d["issue_a"] + " + " + d["issue_b"]
            ax.bar(d["pair"], d["zones_with_pair"])
            ax.set_title(f"Co-occurring issue pairs (top {min(self.top_pairs, len(d))})")
            ax.set_ylabel("Zones with pair")
            ax.tick_params(axis="x", rotation=60)

        plt.tight_layout()

        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=self.dpi, bbox_inches="tight")
        plt.close(fig)
        return buf.getvalue()
