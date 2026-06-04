"""
Adversarial verifier — judges each candidate finding REAL / REFUTED /
UNCERTAIN and constructs an exploit trace when REAL.

This is the "model-checker counterexample" pattern: the EDFA pipeline
produces candidate findings; the verifier independently inspects the
underlying skill files and either confirms with a trace or refutes.

Operates on the dict findings that come out of reporter.serialize, and
returns a filtered + annotated list:

  * REAL      → keep, attach trace to description, optionally upgrade
  * UNCERTAIN → keep, downgrade severity one level
  * REFUTED   → drop entirely

When the LLM is unavailable, the verifier is a passthrough (returns input
findings unchanged).
"""

from __future__ import annotations

import os
import sys

from . import llm
from .config import SEVERITY_ORDER


_VALID_VERDICTS = {"REAL", "REFUTED", "UNCERTAIN"}


_SYSTEM_PROMPT = """You are an adversarial security analyst verifying \
findings produced by a static analyzer for multi-agent skill compositions.

Your job is to refute, confirm, or label-as-uncertain each finding by \
reading the actual skill files. Default to refuted when in doubt about \
whether the data flow actually exists.

Return ONLY a JSON object matching the schema in the user message — no \
markdown fences, no commentary outside the JSON."""


_USER_PROMPT_TEMPLATE = """A static analyzer has flagged the following \
cross-skill vulnerability in a multi-agent harness. Verify it against the \
actual skill files.

=== FINDING ===
{finding_block}

=== SKILL FILES INVOLVED ===
{skill_files_block}

=== INSTRUCTIONS ===
Decide whether the finding is REAL, REFUTED, or UNCERTAIN.

A finding is REAL when ALL of the following hold:
  1. The trigger variable actually exists in the source skill (declared as \
input or output, or referenced in its Behavior).
  2. The trigger variable plausibly carries the claimed type of sensitive \
data, based on the source skill's description, examples in input docs, \
or aggregated sub-fields.
  3. The sink skill actually performs the claimed operation (e.g. an HTTP \
POST, SMTP send, SCP transfer) and the trigger variable's value reaches \
that operation.
  4. The destination is plausibly outside the trust boundary, given any \
URLs / hosts / channels named in the sink skill.

A finding is REFUTED when ANY of these hold:
  - The trigger variable is not actually used by the sink skill in the \
claimed operation.
  - The variable's content is clearly NOT what the finding claims \
(e.g. it's a status flag despite a credential-like name).
  - The data flow path is broken (no link from source to sink).
  - The "external" destination is clearly internal (intranet, localhost, etc.).

Otherwise mark UNCERTAIN.

If REAL, construct a concrete execution trace in 2–4 short sentences: \
what value enters the source skill, what is stored in the trigger \
variable, how it crosses the skill boundary, what bytes end up at the \
external endpoint.

Respond as JSON:
{{
  "verdict": "REAL" | "REFUTED" | "UNCERTAIN",
  "reason": "<one sentence>",
  "trace": "<2-4 sentences if REAL, empty string otherwise>"
}}"""


def verify_findings(
    findings: list[dict],
    extractions_by_file: dict[str, str],
) -> list[dict]:
    """
    Run the adversarial verifier on each finding.

    ``extractions_by_file`` maps skill_filename → raw skill text. This lets
    the verifier prompt include the actual source files of the involved
    skills.
    """
    # Honour an explicit opt-out for cases where the user wants the raw
    # analyzer findings without a verification pass.
    if os.environ.get("ANALYZER_SKIP_VERIFY") == "1":
        return findings

    if not llm.is_available() or not findings:
        return findings

    out: list[dict] = []
    for f in findings:
        verdict, reason, trace = _verify_one(f, extractions_by_file)
        if verdict == "REFUTED":
            print(
                f"# Verifier dropped {f.get('id')}: {reason}",
                file=sys.stderr,
            )
            continue
        if verdict == "UNCERTAIN":
            _downgrade_severity(f)
            if reason:
                f["description"] = (
                    f.get("description", "")
                    + f" Verifier note (uncertain): {reason}"
                ).strip()
        else:  # REAL or no-op
            if trace:
                f["description"] = (
                    f.get("description", "")
                    + f" Verified execution trace: {trace}"
                ).strip()
        out.append(f)

    # Reassign sequential IDs since we may have dropped findings
    for i, f in enumerate(out, start=1):
        f["id"] = f"FINDING-{i:03d}"
    return out


# ----------------------------------------------------------------------

def _verify_one(
    finding: dict, files: dict[str, str]
) -> tuple[str, str, str]:
    finding_block = _format_finding(finding)
    skill_files_block = _format_skill_files(finding, files)
    prompt = _USER_PROMPT_TEMPLATE.format(
        finding_block=finding_block,
        skill_files_block=skill_files_block,
    )
    raw = llm.call_llm(prompt, system=_SYSTEM_PROMPT, stage="verifier")
    if raw is None:
        return "REAL", "", ""  # passthrough when LLM is unavailable
    parsed = llm.parse_json_lenient(raw)
    if not isinstance(parsed, dict):
        return "REAL", "", ""
    verdict = parsed.get("verdict", "REAL")
    if verdict not in _VALID_VERDICTS:
        verdict = "REAL"
    reason = str(parsed.get("reason", ""))[:240]
    trace = str(parsed.get("trace", ""))[:600]
    return verdict, reason, trace


def _format_finding(finding: dict) -> str:
    lines = [
        f"id: {finding.get('id')}",
        f"severity: {finding.get('severity')}",
        f"title: {finding.get('title')}",
        f"cwe: {finding.get('cwe', '-')}",
        f"cross_skill: {finding.get('cross_skill')}",
        f"location: {finding.get('location', {})}",
        f"related_skills: {finding.get('related_skills', [])}",
        f"description: {finding.get('description', '')}",
    ]
    return "\n".join(lines)


def _format_skill_files(finding: dict, files: dict[str, str]) -> str:
    relevant = list(dict.fromkeys(finding.get("related_skills", [])))
    if not relevant:
        loc_file = finding.get("location", {}).get("file")
        if loc_file:
            relevant = [loc_file]
    blocks: list[str] = []
    for name in relevant:
        text = files.get(name)
        if not text:
            continue
        blocks.append(f"--- {name} ---\n{text.strip()}\n")
    if not blocks:
        return "(no skill file content available)"
    return "\n".join(blocks)


def _downgrade_severity(finding: dict) -> None:
    order = ["critical", "high", "medium", "low", "info"]
    sev = finding.get("severity")
    if sev not in order:
        finding["severity"] = "medium"
        return
    idx = order.index(sev)
    if idx + 1 < len(order):
        finding["severity"] = order[idx + 1]
