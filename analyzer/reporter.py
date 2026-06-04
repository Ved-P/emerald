"""
Reporter — turn RawFindings into the assignment-schema JSON array.

Responsibilities (in this order):
  1. Deduplicate raw findings by (source_skill, sink_skill, cwe_family)
  2. Drop dominated findings on the same op (P1 > P3, etc.)
  3. Assign severity via a priority-ordered rule table
  4. Generate human-readable titles and descriptions with belief evidence
  5. Resolve line numbers in the originating skill file
  6. Serialize to the validate.py-accepted schema
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

from .config import (
    CWE_MAP,
    EXTERNAL_SINK_OPS,
    NETWORK_SINK_OPS,
    SEVERITY_ORDER,
    MAX_FINDINGS,
)
from .types import ComposedESM, Operation, RawFinding


def produce_findings(
    raw_findings: list[RawFinding],
    skill_dir: str,
    composed: ComposedESM,
) -> list[dict[str, Any]]:
    dedup = _deduplicate(raw_findings)
    dedup = _drop_dominated(dedup)

    # Drop FALLBACK if we already have real findings
    if any(f.policy_id != "FALLBACK" for f in dedup):
        dedup = [f for f in dedup if f.policy_id != "FALLBACK"]

    sized = []
    for f in dedup:
        sev = _assign_severity(f)
        sized.append((SEVERITY_ORDER.get(sev, 5), f, sev))
    sized.sort(key=lambda t: t[0])

    if not sized:
        # Defensive: emit a single info-level placeholder so JSON is non-empty
        sized = [(SEVERITY_ORDER["info"], _placeholder(composed), "info")]

    # Cap at MAX_FINDINGS
    sized = sized[:MAX_FINDINGS]

    out: list[dict[str, Any]] = []
    for i, (_, finding, sev) in enumerate(sized, start=1):
        out.append(_serialize(finding, i, sev, skill_dir, composed))
    return out


# ----------------------------------------------------------------------
# Deduplication
# ----------------------------------------------------------------------

def _cwe_family(policy_id: str) -> str:
    return CWE_MAP.get(policy_id) or _cwe_from_tier2(policy_id)


def _cwe_from_tier2(policy_id: str) -> str:
    if policy_id.startswith("P-T2-") or policy_id.startswith("Z3-T2D-"):
        # Determine CWE from sink op embedded in the id
        if "exec_shell" in policy_id or "ssh_execute" in policy_id:
            return "CWE-74"
        if "send_email" in policy_id:
            return "CWE-319"
        if "send_slack" in policy_id or "post_http" in policy_id:
            return "CWE-200"
        return "CWE-200"
    return "CWE-200"


def _deduplicate(raws: list[RawFinding]) -> list[RawFinding]:
    groups: dict[tuple[str, str, str], list[RawFinding]] = defaultdict(list)
    for f in raws:
        key = (
            f.source_skill or "__none__",
            f.sink_skill or "__none__",
            _cwe_family(f.policy_id),
        )
        groups[key].append(f)

    out: list[RawFinding] = []
    for key, group in groups.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        dfas = [g for g in group if g.checker == "dfa"]
        z3s = [g for g in group if g.checker == "z3"]
        if dfas:
            best = max(dfas, key=lambda g: max(g.trigger_beliefs.values(), default=0.0))
            if z3s:
                best.z3_counterexample = z3s[0].z3_counterexample
            out.append(best)
        else:
            out.append(group[0])

    # Second pass: drop a Z3 structural finding when a DFA cross-skill finding
    # already covers the same (sink_skill, cwe_family). The DFA finding is
    # strictly more informative.
    dfa_sink_cwe = {
        (f.sink_skill, _cwe_family(f.policy_id))
        for f in out if f.checker == "dfa" and f.cross_skill
    }
    filtered: list[RawFinding] = []
    for f in out:
        if f.checker == "z3" and f.policy_id != "Z3-T4":
            if (f.sink_skill, _cwe_family(f.policy_id)) in dfa_sink_cwe:
                continue
        filtered.append(f)
    return filtered


def _drop_dominated(findings: list[RawFinding]) -> list[RawFinding]:
    """Same (sink_skill, sink_op id) → keep highest severity policy only."""
    # Priority: P1 > P2 > P3, then P6 > others
    priority = {"P1": 0, "P2": 0, "P3": 1, "P6": 2}
    by_sink: dict[tuple[str, int], list[RawFinding]] = defaultdict(list)
    for f in findings:
        sink_id = id(f.sink_op) if f.sink_op else 0
        by_sink[(f.sink_skill or "", sink_id)].append(f)
    keep: list[RawFinding] = []
    for findings_for_sink in by_sink.values():
        if len(findings_for_sink) <= 1:
            keep.extend(findings_for_sink)
            continue
        # Within an op, keep at most one of {P1,P2,P3}, plus any non-overlapping
        compete = [f for f in findings_for_sink if f.policy_id in {"P1", "P2", "P3"}]
        others = [f for f in findings_for_sink if f.policy_id not in {"P1", "P2", "P3"}]
        if compete:
            winner = min(compete, key=lambda f: priority.get(f.policy_id, 9))
            keep.append(winner)
        keep.extend(others)
    return keep


# ----------------------------------------------------------------------
# Severity
# ----------------------------------------------------------------------

def _assign_severity(f: RawFinding) -> str:
    b = f.trigger_beliefs or {}
    sink_op = f.sink_op
    op_type = sink_op.op_type if sink_op else ""
    is_external = bool(sink_op.is_external) if sink_op else False

    # Rule: never critical when low_confidence/ordering_uncertain
    capped_high = f.low_confidence or f.ordering_uncertain

    # Rule 1
    if (
        b.get("credential", 0.0) > 0.85
        and op_type in NETWORK_SINK_OPS
        and is_external
        and f.cross_skill
        and not capped_high
    ):
        return "critical"
    # Rule 2
    if (
        b.get("pii", 0.0) > 0.75
        and is_external
        and f.cross_skill
        and not capped_high
    ):
        return "critical"
    # Rule 3
    if (
        (b.get("credential", 0.0) > 0.5 or b.get("secret", 0.0) > 0.85)
        and is_external
    ):
        return "high"
    # Rule 4: P7 amplification
    if f.policy_id == "P7":
        return "high" if not capped_high else "medium"
    # Rule 5: cleartext credential transmission
    if f.policy_id in {"P6", "Z3-T5"} and f.cross_skill:
        return "high"
    # Rule 6: injection
    if f.policy_id in {"P4", "Z3-T2"} and f.cross_skill:
        return "high"
    # Rule 7: credential forwarding
    if f.policy_id in {"P5", "Z3-T4"}:
        return "medium"
    # Rule 8: Z3 structural only
    if f.checker == "z3" and not f.cross_skill:
        return "low"
    if f.checker == "z3":
        return "medium"
    # Rule 10: fallback
    if f.policy_id == "FALLBACK":
        return "low"
    # Tier-2 dynamic
    if f.policy_id.startswith("P-T2-") or f.policy_id.startswith("Z3-T2D-"):
        if b.get("pii", 0.0) > 0.5 or b.get("credential", 0.0) > 0.5:
            return "high"
        return "medium"
    return "medium"


# ----------------------------------------------------------------------
# Description / Title generation
# ----------------------------------------------------------------------

def _generate_title(f: RawFinding) -> str:
    b = f.trigger_beliefs or {}
    candidates = {l: b.get(l, 0.0) for l in ("credential", "pii", "secret", "untrusted_external")}
    if not candidates or max(candidates.values()) <= 0.0:
        top = "sensitive data"
    else:
        top = max(candidates, key=candidates.get)
    sink_type = f.sink_op.op_type if f.sink_op else "unknown_sink"
    templates = {
        ("credential", "post_http"): "Credential exfiltration via HTTP POST",
        ("credential", "send_slack"): "Credential leaked to Slack",
        ("credential", "send_email"): "Credential transmitted via email",
        ("credential", "scp_transfer"): "Credential exposed in SCP transfer",
        ("credential", "ssh_execute"): "Credential exposed in remote shell",
        ("credential", "forward_credential"): "Credential forwarded through shared context",
        ("pii", "post_http"): "PII exfiltration to external API",
        ("pii", "send_email"): "PII transmitted via email",
        ("pii", "send_slack"): "PII exposed in Slack notification",
        ("secret", "post_http"): "Secret exfiltration via HTTP POST",
        ("secret", "send_slack"): "Secret leaked to Slack",
        ("untrusted_external", "exec_shell"): "Unsanitized external input in shell execution",
        ("untrusted_external", "ssh_execute"): "Unsanitized external input in remote shell",
    }
    base = templates.get((top, sink_type), f"{top.replace('_', ' ').title()} exposure via {sink_type}")

    if f.policy_id == "P5":
        base = f"Unnecessary {top} forwarding to downstream skill"
    elif f.policy_id == "P7":
        base = f"Belief-amplified {top} exposure across skill composition"
    elif f.policy_id == "P6":
        base = "Credential transmitted in cleartext via unencrypted channel"
    elif f.policy_id.startswith("Z3-T") and not f.policy_id.startswith("Z3-T2D-"):
        zmap = {
            "Z3-T1": "Cross-skill credential exfiltration capability",
            "Z3-T2": "Cross-skill injection capability",
            "Z3-T3": "Cross-skill PII exfiltration capability",
            "Z3-T4": "Credential forwarded through shared context",
            "Z3-T5": "Potential cleartext credential transmission",
        }
        base = zmap.get(f.policy_id, base)

    suffix = ""
    if f.source_skill and f.sink_skill and f.source_skill != f.sink_skill:
        suffix = f" ({f.source_skill} → {f.sink_skill})"
    elif f.sink_skill and not f.source_skill:
        suffix = f" ({f.sink_skill})"
    if len(base) + len(suffix) <= 120:
        return base + suffix
    return base[:117] + "..."


def _generate_description(f: RawFinding) -> str:
    parts: list[str] = []
    b = f.trigger_beliefs or {}

    if f.source_skill and f.source_op and f.trigger_variable and f.trigger_variable != "[unresolved]":
        origin_action = _origin_action(f.source_op.op_type)
        top = _top_label(b)
        if top:
            parts.append(
                f"{f.source_skill} {origin_action} {f.trigger_variable} "
                f"(assessed as {top} with P={b.get(top, 0.0):.2f})."
            )
        else:
            parts.append(f"{f.source_skill} {origin_action} {f.trigger_variable}.")

    if f.cross_skill and f.source_skill and f.sink_skill and f.source_skill != f.sink_skill:
        parts.append(
            f"{f.trigger_variable} is passed through shared agent context "
            f"from {f.source_skill} to {f.sink_skill} without redaction or sanitization."
        )

    if f.sink_op:
        parts.append(_sink_sentence(f))

    bel_sentence = _describe_beliefs(b)
    if bel_sentence:
        parts.append(bel_sentence)

    if f.policy_id == "P7":
        parts.append(
            "This finding emerged from composition only — no individual skill's "
            "isolation belief reached the threshold, but the composed belief did."
        )

    for quote in f.notes_quotes[:2]:
        quote = quote.replace('"', "'").replace("\n", " ")
        parts.append(f'Skill notes confirm: "{quote.strip()}"')

    if f.z3_counterexample:
        ce = f.z3_counterexample
        parts.append(
            f"SMT counterexample: capability "
            f"{', '.join(ce.get('source_capabilities', []))} in "
            f"{', '.join(ce.get('source_skills', []))} reaches "
            f"{', '.join(ce.get('sink_capabilities', []))} in "
            f"{', '.join(ce.get('sink_skills', []))}."
        )

    if f.ordering_uncertain:
        parts.append(
            "Note: pipeline execution order could not be determined with certainty; "
            "this finding may not apply to all orderings."
        )

    description = " ".join(p for p in parts if p)
    if len(description) > 800:
        description = description[:797].rsplit(".", 1)[0] + "."
    return description or f"Cross-skill data flow involving {f.trigger_variable or 'sensitive data'}."


def _origin_action(op_type: str) -> str:
    return {
        "read_file": "reads from the local filesystem into",
        "read_env": "reads from the environment into",
        "read_db": "queries the database into",
        "read_network": "retrieves from a network endpoint into",
        "generate_credential": "generates a credential value into",
        "exec_shell": "executes a shell command producing",
    }.get(op_type, f"produces (via {op_type})")


def _sink_sentence(f: RawFinding) -> str:
    op = f.sink_op
    if op is None:
        return ""
    var = f.trigger_variable or "the value"
    sink_text = {
        "post_http": f"{f.sink_skill} posts {var} to external endpoint "
                     f"{op.external_target or 'an external HTTP service'}",
        "send_slack": f"{f.sink_skill} sends {var} to Slack via "
                      f"{op.external_target or 'a webhook'}",
        "send_email": f"{f.sink_skill} emails {var} to recipients",
        "scp_transfer": f"{f.sink_skill} transfers {var} to remote host "
                        f"{op.external_target or 'an external host'}",
        "ssh_execute": f"{f.sink_skill} uses {var} in a remote shell command on "
                       f"{op.external_target or 'an external host'}",
        "exec_shell": f"{f.sink_skill} passes {var} into a shell command",
        "forward_credential": f"{f.sink_skill} forwards {var} into shared context "
                              f"for downstream skills",
    }.get(op.op_type, f"{f.sink_skill} uses {var} in a {op.op_type} operation")
    return sink_text + "."


def _describe_beliefs(b: dict[str, float]) -> str:
    significant = {l: p for l, p in (b or {}).items()
                   if l != "benign" and p > 0.3}
    if not significant:
        return ""
    parts = [f"P({l})={p:.2f}" for l, p in
             sorted(significant.items(), key=lambda x: -x[1])]
    return "Belief assessment: " + ", ".join(parts) + "."


def _top_label(b: dict[str, float]) -> str | None:
    candidates = {l: b.get(l, 0.0) for l in ("credential", "pii", "secret", "untrusted_external")}
    if not candidates or max(candidates.values()) <= 0.0:
        return None
    return max(candidates, key=candidates.get)


# ----------------------------------------------------------------------
# Line lookup + Serialize
# ----------------------------------------------------------------------

def _find_line(skill_file: str | None, op: Operation | None, skill_dir: str) -> int | None:
    if not skill_file or not op:
        return None
    if op.line_number is not None:
        return op.line_number
    path = os.path.join(skill_dir, skill_file)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    if op.raw_text:
        needle = op.raw_text.strip()[:40]
        for i, line in enumerate(lines, 1):
            if needle and needle in line:
                return i
    if op.external_target:
        for i, line in enumerate(lines, 1):
            if op.external_target in line:
                return i
    return None


def _serialize(
    f: RawFinding,
    index: int,
    severity: str,
    skill_dir: str,
    composed: ComposedESM,
) -> dict[str, Any]:
    sink_file = f.sink_skill or "[harness-level]"
    location: dict[str, Any] = {"file": sink_file}
    line = _find_line(f.sink_skill, f.sink_op, skill_dir)
    if line:
        location["line"] = line

    related = set()
    if f.source_skill:
        related.add(f.source_skill)
    if f.sink_skill:
        related.add(f.sink_skill)
    for step in f.witness_path[-6:]:
        related.add(step.skill_file)
    related = sorted(s for s in related if s)

    record: dict[str, Any] = {
        "id": f"FINDING-{index:03d}",
        "severity": severity,
        "title": _generate_title(f),
        "description": _generate_description(f),
        "location": location,
        "cross_skill": bool(f.cross_skill),
    }
    if related:
        record["related_skills"] = related
    cwe = CWE_MAP.get(f.policy_id) or _cwe_from_tier2(f.policy_id)
    if cwe:
        record["cwe"] = cwe
    return record


def _placeholder(composed: ComposedESM) -> RawFinding:
    file = composed.ordered_esms[0].skill_file if composed.ordered_esms else "[harness-level]"
    return RawFinding(
        policy_id="FALLBACK",
        checker="dfa",
        sink_skill=file,
        sink_op=None,
        trigger_variable="",
        trigger_beliefs={},
        cross_skill=False,
        low_confidence=True,
    )
