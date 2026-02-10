# This is the analytics model. 
# It creates reports based on what errors are encountered

from itertools import combinations
from collections import Counter
from typing import Dict, Any, List, Optional
import pandas as pd

# Uses a data frame to build a summary of the findings
class ReportAnalyzer:

    def __init__(self):
        pass

    def analytics(self, df: pd.DataFrame) -> Dict[str, Any]:
        # Always return the same keys
        empty = {
            "counts_by_issue": pd.DataFrame(columns=["issue", "count"]),
            "worst_zones": pd.DataFrame(columns=["zone", "count", "issue_breakdown"]),
            "prioritized_queue": pd.DataFrame(columns=df.columns),
            "cooccurrence_pairs": pd.DataFrame(columns=["issue_a", "issue_b", "zones_with_pair"]),
        }
        if df is None or df.empty:
            return empty

        broken = df[df["issue"] != "OK"].copy()
        if broken.empty:
            return empty | {"prioritized_queue": df.copy()}

        counts_by_issue = (
            broken.groupby("issue")
                  .size()
                  .reset_index(name="count")
                  .sort_values("count", ascending=False)
        )

        # Worst zones + breakdown
        tmp = (
            broken.groupby(["zone", "issue"])
                  .size()
                  .reset_index(name="count")
                  .sort_values(["zone", "count", "issue"], ascending=[True, False, True])
        )

        zone_breakdown = (
            tmp.assign(issue_count=tmp["issue"] + ":" + tmp["count"].astype(str))
               .groupby("zone", as_index=False)["issue_count"]
               .agg("; ".join)
               .rename(columns={"issue_count": "issue_breakdown"})
        )

        worst_zones = (
            tmp.groupby("zone", as_index=False)["count"]
               .sum()
               .sort_values("count", ascending=False)
               .merge(zone_breakdown, on="zone", how="left")
        )

        # Prioritized queue: zone-level rollup sorted by severity count, then zone
        prioritized_queue = (
            tmp.groupby("zone", as_index=False)["count"]
               .sum()
               .sort_values(["count", "zone"], ascending=[False, True])
               .merge(zone_breakdown, on="zone", how="left")
        )

        # Co-occurrence pairs (correctly counts issue pairs per zone)
        issue_sets = (
            broken.groupby("zone")["issue"]
                  .agg(lambda s: sorted(set(s)))
        )
        pair_counts: Counter = Counter()
        for issues in issue_sets:
            for a, b in combinations(issues, 2):
                pair_counts[(a, b)] += 1

        if pair_counts:
            cooccurrence_pairs = pd.DataFrame(
                [{"issue_a": a, "issue_b": b, "zones_with_pair": c}
                 for (a, b), c in pair_counts.items()]
            ).sort_values("zones_with_pair", ascending=False)
        else:
            cooccurrence_pairs = empty["cooccurrence_pairs"]

        return {
            "counts_by_issue": counts_by_issue,
            "worst_zones": worst_zones,
            "prioritized_queue": prioritized_queue,
            "cooccurrence_pairs": cooccurrence_pairs,
        }
