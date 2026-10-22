"""CLI entry point for tmcheck."""
from __future__ import annotations

import argparse
import json
import sys

from tmcheck.core import (
    ModelError,
    load_model,
    validate,
    coverage_gaps,
    policy_findings,
    rank,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a threat model YAML file.")
    parser.add_argument("path", help="Path to the threat model YAML file")
    args = parser.parse_args()

    try:
        model = load_model(args.path)
    except ModelError:
        return 2

    issues = validate(model)
    gaps = coverage_gaps(model)
    policy = policy_findings(model)
    ranked = rank(model)

    output = {
        "issues": [{"ref": i.ref, "code": i.code, "message": i.message} for i in issues],
        "gaps": [{"ref": g.ref, "category": g.category} for g in gaps],
        "policy": [{"ref": p.ref, "code": p.code, "message": p.message} for p in policy],
        "ranked": [{"id": r.id, "score": r.score, "level": r.level} for r in ranked],
    }

    print(json.dumps(output, indent=2))

    if issues or policy:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())