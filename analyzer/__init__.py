"""
Top-level analyzer pipeline:

    parser → extractor (LLM) → ESM builder → composer
           → DFA checker + Z3 checker → reporter → verifier (LLM)

Exposes a single ``run(harness_dir)`` function that returns a list of
JSON-ready finding dicts.

Optional kwargs let CLI callers request side outputs (visualizations)
without affecting the stdout JSON.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from .composer import compose
from .dfa_checker import dfa_check
from .esm import build_esm
from .extractor import extract
from .parser import parse_skill_file
from .reporter import produce_findings
from .verifier import verify_findings
from .z3_checker import z3_check


# Files that are obviously documentation, not skills. Used as a deny-list
# only when falling back from the benchmark-style ``skill_*.md`` convention
# to "any .md file in the directory".
_DOC_FILES_LOWER = {
    "readme.md", "changelog.md", "contributing.md", "license.md",
    "license", "code_of_conduct.md", "security.md", "notes.md",
}


def _discover_skill_files(harness_dir: str) -> list[str]:
    """Return the list of .md files to treat as skills, sorted.

    Strategy:
      1. Prefer ``skill_*.md`` (the assignment-benchmark convention).
      2. If none, fall back to all ``.md`` files in the directory,
         excluding obvious documentation files (README, CHANGELOG, etc.).
    """
    entries = sorted(os.listdir(harness_dir))
    skill_prefixed = [
        f for f in entries
        if f.endswith(".md") and f.startswith("skill_")
    ]
    if skill_prefixed:
        return skill_prefixed
    fallback = [
        f for f in entries
        if f.endswith(".md") and f.lower() not in _DOC_FILES_LOWER
    ]
    if fallback:
        print(
            f"Note: no skill_*.md files in {harness_dir}; "
            f"treating {len(fallback)} other .md file(s) as skills",
            file=sys.stderr,
        )
    return fallback


def run(
    harness_dir: str,
    *,
    viz_dir: str | None = None,
) -> list[dict[str, Any]]:
    if not os.path.isdir(harness_dir):
        print(f"Error: {harness_dir} is not a directory", file=sys.stderr)
        return []

    skill_files = _discover_skill_files(harness_dir)
    if not skill_files:
        print(f"Warning: no skill files found in {harness_dir}", file=sys.stderr)
        return []

    extractions = []
    esms = []
    skill_texts: dict[str, str] = {}
    for fname in skill_files:
        path = os.path.join(harness_dir, fname)
        partial = parse_skill_file(path)
        skill_texts[fname] = partial.raw_text
        extraction = extract(partial)
        extractions.append(extraction)
        esms.append(build_esm(extraction))

    composed = compose(esms)
    raw_findings = dfa_check(composed) + z3_check(composed)
    findings = produce_findings(raw_findings, harness_dir, composed)

    # Adversarial verification pass — drop refuted findings, downgrade
    # uncertain ones, embed concrete traces for confirmed ones.
    findings = verify_findings(findings, skill_texts)

    if viz_dir:
        from .visualize import render_harness
        render_harness(
            harness_dir=harness_dir,
            composed=composed,
            findings=findings,
            out_dir=viz_dir,
        )

    return findings
