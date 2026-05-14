#!/usr/bin/env python3
"""
Validates that analyzer JSON output conforms to the HW4 schema.

Usage:
    python3 run.py <skill-dir> | python3 validate.py
    python3 validate.py output.json
"""

import sys
import json

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

REQUIRED_FIELDS = {"id", "severity", "title", "description", "location", "cross_skill"}


def validate(findings: list[dict]) -> list[str]:
    """Return a list of error messages. Empty list means valid."""
    errors = []

    if not isinstance(findings, list):
        return ["Top-level value must be a JSON array."]

    seen_ids = set()

    for i, f in enumerate(findings):
        prefix = f"findings[{i}]"

        if not isinstance(f, dict):
            errors.append(f"{prefix}: must be a JSON object.")
            continue

        # Check required fields
        for field in REQUIRED_FIELDS:
            if field not in f:
                errors.append(f"{prefix}: missing required field '{field}'.")

        # Validate id uniqueness
        fid = f.get("id")
        if fid is not None:
            if fid in seen_ids:
                errors.append(f"{prefix}: duplicate id '{fid}'.")
            seen_ids.add(fid)

        # Validate severity
        sev = f.get("severity")
        if sev is not None and sev not in VALID_SEVERITIES:
            errors.append(
                f"{prefix}: severity '{sev}' not in {VALID_SEVERITIES}."
            )

        # Validate location
        loc = f.get("location")
        if loc is not None:
            if not isinstance(loc, dict):
                errors.append(f"{prefix}: 'location' must be an object.")
            elif "file" not in loc:
                errors.append(f"{prefix}: 'location' missing required field 'file'.")

        # Validate cross_skill is boolean
        cs = f.get("cross_skill")
        if cs is not None and not isinstance(cs, bool):
            errors.append(f"{prefix}: 'cross_skill' must be a boolean.")

    return errors


def main():
    # Read from file argument or stdin
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as fh:
            raw = fh.read()
    else:
        raw = sys.stdin.read()

    # Parse JSON
    try:
        findings = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"FAIL: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    errors = validate(findings)

    if errors:
        print(f"FAIL: {len(errors)} validation error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"OK: {len(findings)} finding(s), all valid.")
        sys.exit(0)


if __name__ == "__main__":
    main()
