#!/usr/bin/env python3
"""
HW4 Entry Point -- Agentic Skill Composition Analyzer

Usage:
    python3 run.py <path-to-skill-directory>

Outputs a JSON array of findings to stdout.
"""

import sys
import os
import json


def analyze(skill_dir: str) -> list[dict]:
    """
    Analyze a directory of skill files and return a list of findings.

    Each finding is a dict with at least these keys:
        id, severity, title, description, location (with "file"), cross_skill

    TODO: Implement your analysis here.
    """
    findings = []

    # List all skill files in the directory
    skill_files = sorted(
        f for f in os.listdir(skill_dir)
        if f.endswith(".md") and f.startswith("skill_")
    )

    if not skill_files:
        print(f"Warning: no skill files found in {skill_dir}", file=sys.stderr)
        return findings

    # Read skill contents
    skills = {}
    for fname in skill_files:
        with open(os.path.join(skill_dir, fname), "r") as fh:
            skills[fname] = fh.read()

    # ------------------------------------------------------------------
    # TODO: Replace the stub below with your actual analysis.
    #
    # The stub emits a single placeholder finding so that the JSON output
    # is structurally valid.  Your analyzer should produce real findings.
    # ------------------------------------------------------------------
    findings.append({
        "id": "FINDING-001",
        "severity": "info",
        "title": "Stub finding -- replace with real analysis",
        "description": (
            f"Found {len(skill_files)} skill file(s) in {skill_dir}. "
            "Implement your analysis to produce real findings."
        ),
        "location": {
            "file": skill_files[0],
        },
        "cross_skill": False,
    })

    return findings


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-skill-directory>", file=sys.stderr)
        sys.exit(1)

    skill_dir = sys.argv[1]

    if not os.path.isdir(skill_dir):
        print(f"Error: {skill_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    findings = analyze(skill_dir)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
