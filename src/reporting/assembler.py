from typing import Any, Dict, List, Optional
from fastapi.encoders import jsonable_encoder
from .recommendations import Recommendations

class Assemble:
    """
    Combines outputs from multiple checkers into one consistent API response.

    Design intent:
      - Each checker focuses on detection (DNSSEC, MPIC, SPF, etc.)
      - The assembler is responsible for shaping results into a single response format:
          - JSON-safe output
          - unified findings list
          - recommendations
          - summary
    """

    def build(
        self,
        target: str,
        checks: Dict[str, Any],
        findings: Optional[List[Dict[str, Any]]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a unified response.

        Args:
            target: The DNS name being checked (already validated/normalized upstream).
            checks: Dict of check_name -> checker result object.
            findings: Optional pre-built findings list. If not provided, findings will be
                      collected from each check result under result["findings"].
            meta: Optional metadata (version, timings, etc.).

        Returns:
            A dict containing only JSON-safe values (dict/list/str/int/etc.).
        """

        # Convert each checker output into JSON-friendly structures so FastAPI can serialize.
        # This prevents "Object of type X is not JSON serializable" errors.
        checks_json: Dict[str, Any] = {name: self._to_json(value) for name, value in checks.items()}

        # Merge findings into one unified list (unless caller provided them).
        unified_findings = findings or self._collect_findings(checks_json)

        # Attach a "what to do next" recommendation to each finding.
        self._attach_recommendations(unified_findings)

        # Compute a small summary useful for UI badges and sorting.
        summary = self._summarize(unified_findings)

        response: Dict[str, Any] = {
            "target": target,
            "findings": unified_findings,
            "summary": summary,
            "meta": meta or {},
            # Keep raw check outputs available for debugging / richer UI screens.
            "checks": checks_json,
        }

        # Final safety pass: ensure *everything* in response is JSON-safe.
        return jsonable_encoder(response)

    def _to_json(self, obj: Any) -> Any:
        """
        Convert a checker result into JSON-friendly structures.

        - If the checker provides to_dict(), use it, but still run jsonable_encoder
          to handle nested non-JSON types (datetimes, enums, sets, etc.).
        - Otherwise, encode the object directly.
        """
        if hasattr(obj, "to_dict"):
            return jsonable_encoder(obj.to_dict())
        return jsonable_encoder(obj)

    def _collect_findings(self, checks_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Pull findings out of each check result and merge them into a single list.

        Expected convention:
          checks_json[check_name] is a dict that may include:
            { "findings": [ {..finding..}, {..finding..}, ... ] }

        Adds:
          - "check": check_name to each finding so the UI can group/filter by source.
        """
        out: List[Dict[str, Any]] = []

        for check_name, result in checks_json.items():
            # If a checker doesn't return a dict or doesn't include findings, treat as empty.
            findings = (result or {}).get("findings", []) if isinstance(result, dict) else []

            # Only iterate if it is actually a list.
            for f in findings if isinstance(findings, list) else []:
                if isinstance(f, dict):
                    f.setdefault("check", check_name)
                    out.append(f)

        return out

    def _attach_recommendations(self, findings: List[Dict[str, Any]]) -> None:
        """
        Add recommendations to findings.

        This is "best effort": recommendation lookup should never break the endpoint.
        """
        for f in findings:
            issue = (f.get("issue") or "").strip()
            try:
                f["recommendation"] = Recommendations.recommend(issue) if issue else ""
            except Exception:
                f["recommendation"] = ""

    def _summarize(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build a small summary for the UI:
          - counts by severity bucket
          - total findings
          - a simple score (0..100) where severe issues reduce the score
        """

        # Known buckets ensure the response always has consistent keys.
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}

        for f in findings:
            # Normalize severity to a lowercase string; anything unexpected becomes "unknown".
            sev = f.get("severity")
            sev = sev.lower() if isinstance(sev, str) else "unknown"

            # If a checker introduces a new severity label, count it instead of crashing.
            counts[sev] = counts.get(sev, 0) + 1

        total = sum(counts.values())

        # Simple scoring model: start at 100 and subtract penalties by severity.
        score = 100 - (counts["high"] * 20 + counts["medium"] * 10 + counts["low"] * 5)

        # Clamp score to 0..100.
        score = max(0, min(100, score))

        return {"issues": total, **counts, "score": score}
