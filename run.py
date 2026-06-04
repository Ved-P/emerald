#!/usr/bin/env python3
"""
HW4 Entry Point -- Agentic Skill Composition Analyzer

Usage:
    python3 run.py <path-to-skill-directory> [--viz <out_dir>]

Outputs a JSON array of findings to stdout. The optional ``--viz`` flag
writes Graphviz .dot visualizations of the composed Epistemic DFA to the
given directory (does not affect stdout output).
"""

import argparse
import json
import os
import sys


def analyze(skill_dir: str, viz_dir: str | None = None) -> list[dict]:
    """
    Analyze a directory of skill files and return a list of findings.

    Delegates to ``analyzer.run`` which orchestrates the full pipeline:
    parser → extractor (Claude) → ESM builder → composer
           → DFA + Z3 checkers → reporter → verifier (Claude).
    """
    from analyzer import run as analyzer_run
    return analyzer_run(skill_dir, viz_dir=viz_dir)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    # Hand-roll a minimal parser that accepts the legacy positional form
    # ``run.py <dir>`` AND the new ``--viz`` form, without breaking
    # check.sh's strict `python3 run.py <harness>` invocation.
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("skill_dir", help="Path to a directory of skill_*.md files")
    parser.add_argument(
        "--viz",
        dest="viz_dir",
        default=None,
        help="Write Graphviz .dot files visualizing the composed ESM into this directory",
    )
    return parser.parse_args(argv)


def main():
    args = _parse_args(sys.argv[1:])

    if not os.path.isdir(args.skill_dir):
        print(f"Error: {args.skill_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    findings = analyze(args.skill_dir, viz_dir=args.viz_dir)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
