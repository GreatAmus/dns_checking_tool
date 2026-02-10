
import argparse
import json
from typing import List
from dnssec_reporting import run_dnssec_report


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="DNSSEC checking tool (dig/delv based)")
    p.add_argument("zones", nargs="+", help="Zone names (e.g., example.com)")
    p.add_argument("--json", dest="as_json", action="store_true", help="Output JSON")
    args = p.parse_args(argv)

    df, a = run_dnssec_report(args.zones)

    if args.as_json:
        out = {
            "findings": df.to_dict(orient="records"),
            "analytics": {k: v.to_dict(orient="records") for k, v in a.items()},
        }
        print(json.dumps(out, indent=2))
    else:
        # simple console output
        if df.empty:
            print("No findings.")
        else:
            print(df.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
