"""
Z3 SMT capability lattice checker.

Belief-free, structure-only: encodes "skill A has capability X AND skill B
has capability Y AND A != B" as Z3 constraints. Each policy is checked
independently using push/pop. Gracefully no-ops when z3 isn't available.
"""

from __future__ import annotations

import sys

from .config import (
    EXTERNAL_SINK_OPS,
    NETWORK_SINK_OPS,
    SENSITIVE_SOURCE_OPS,
    TIER1_COVERED_PAIRS,
)
from .types import ComposedESM, Operation, RawFinding


def z3_check(composed: ComposedESM) -> list[RawFinding]:
    try:
        import z3  # type: ignore
    except ImportError:
        print("# z3 not available; skipping SMT checker", file=sys.stderr)
        return []

    findings: list[RawFinding] = []
    solver = z3.Solver()
    solver.set("timeout", 5000)

    # One boolean per (skill_file, capability) actually present in the harness.
    cap_vars: dict[tuple[str, str], z3.BoolRef] = {}
    for skill_file, caps in composed.skill_capabilities.items():
        for cap in caps:
            sanitized_skill = skill_file.replace(".", "_").replace("-", "_")
            v = z3.Bool(f"{sanitized_skill}__{cap}")
            cap_vars[(skill_file, cap)] = v
            solver.add(v == True)  # noqa: E712 — assert presence

    def any_skill_has(cap_set: set[str]) -> z3.BoolRef:
        matching = [v for (sk, cap), v in cap_vars.items() if cap in cap_set]
        return z3.Or(matching) if matching else z3.BoolVal(False)

    def skills_are_different(cap_set_a: set[str], cap_set_b: set[str]) -> z3.BoolRef:
        pairs = []
        for (sk_a, ca), va in cap_vars.items():
            if ca not in cap_set_a:
                continue
            for (sk_b, cb), vb in cap_vars.items():
                if cb not in cap_set_b:
                    continue
                if sk_a == sk_b:
                    continue
                pairs.append(z3.And(va, vb))
        return z3.Or(pairs) if pairs else z3.BoolVal(False)

    policies = [
        ("Z3-T1", "Cross-skill credential exfiltration path",
         skills_are_different({"read_file", "read_env", "generate_credential"},
                              set(EXTERNAL_SINK_OPS))),
        ("Z3-T2", "Cross-skill injection path",
         skills_are_different({"read_network"},
                              {"exec_shell", "ssh_execute"})),
        ("Z3-T3", "Cross-skill PII exfiltration path",
         skills_are_different({"read_db", "read_file"},
                              {"post_http", "send_email", "send_slack"})),
    ]
    if "forward_credential" in composed.joint_capabilities:
        policies.append((
            "Z3-T4",
            "Credential forwarded through shared context",
            any_skill_has({"forward_credential"}),
        ))
    policies.append((
        "Z3-T5",
        "Potential cleartext credential transmission",
        z3.And(
            any_skill_has({"send_email"}),
            any_skill_has(set(SENSITIVE_SOURCE_OPS)),
        ),
    ))

    # Tier 2 — dynamic policies for any (sensitive_source, external_sink) pair
    # whose pair isn't covered by Tier-1 boolean.
    for src in composed.joint_capabilities & SENSITIVE_SOURCE_OPS:
        for sink in composed.joint_capabilities & EXTERNAL_SINK_OPS:
            if (src, sink) in TIER1_COVERED_PAIRS:
                continue
            policies.append((
                f"Z3-T2D-{src}-{sink}",
                f"Cross-skill data flow: {src} → {sink}",
                skills_are_different({src}, {sink}),
            ))

    for pid, name, constraint in policies:
        solver.push()
        solver.add(constraint)
        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            src_skills, src_caps, sink_skills, sink_caps = _model_skills(
                cap_vars, model
            )
            source_skill, sink_skill = _pick_cross_skill_pair(src_skills, sink_skills)
            sink_op = _first_op_of_types(
                composed, sink_skill, sink_caps,
            ) if sink_skill else None
            source_op = _first_op_of_types(
                composed, source_skill, src_caps,
            ) if source_skill else None
            findings.append(RawFinding(
                policy_id=pid,
                checker="z3",
                sink_skill=sink_skill,
                sink_op=sink_op,
                source_skill=source_skill,
                source_op=source_op,
                trigger_variable=_trigger_var_for_pair(composed, source_skill, sink_skill),
                trigger_beliefs={l: 0.0 for l in ("credential", "secret", "pii", "untrusted_external")},
                cross_skill=bool(source_skill and sink_skill and source_skill != sink_skill),
                z3_counterexample={
                    "policy_name": name,
                    "source_skills": list(src_skills),
                    "source_capabilities": list(src_caps),
                    "sink_skills": list(sink_skills),
                    "sink_capabilities": list(sink_caps),
                },
            ))
        solver.pop()

    return findings


def _pick_cross_skill_pair(
    src_skills: list[str], sink_skills: list[str]
) -> tuple[str | None, str | None]:
    """Prefer a (source, sink) pair where the two skills are different."""
    for a in src_skills:
        for b in sink_skills:
            if a != b:
                return a, b
    source = src_skills[0] if src_skills else None
    sink = sink_skills[0] if sink_skills else None
    return source, sink


def _model_skills(cap_vars, model):
    src_skills: list[str] = []
    src_caps: list[str] = []
    sink_skills: list[str] = []
    sink_caps: list[str] = []
    for (sk, cap), v in cap_vars.items():
        val = model.eval(v, model_completion=True)
        if str(val) != "True":
            continue
        if cap in SENSITIVE_SOURCE_OPS:
            if sk not in src_skills:
                src_skills.append(sk)
            if cap not in src_caps:
                src_caps.append(cap)
        if cap in EXTERNAL_SINK_OPS:
            if sk not in sink_skills:
                sink_skills.append(sk)
            if cap not in sink_caps:
                sink_caps.append(cap)
    return src_skills, src_caps, sink_skills, sink_caps


def _first_op_of_types(
    composed: ComposedESM, skill_file: str | None, types: list[str]
) -> Operation | None:
    if not skill_file:
        return None
    type_set = set(types)
    for esm in composed.ordered_esms:
        if esm.skill_file != skill_file:
            continue
        for op in esm.operations:
            if op.op_type in type_set:
                return op
    return None


def _trigger_var_for_pair(
    composed: ComposedESM, source_skill: str | None, sink_skill: str | None
) -> str:
    if not source_skill or not sink_skill:
        return ""
    # Best shared variable between the two skills
    src_esm = next((e for e in composed.ordered_esms if e.skill_file == source_skill), None)
    sink_esm = next((e for e in composed.ordered_esms if e.skill_file == sink_skill), None)
    if not src_esm or not sink_esm:
        return ""
    shared = set(src_esm.outputs) & set(sink_esm.inputs)
    if not shared:
        return ""
    # Prefer the variable with highest composed credential/secret belief
    best = ""
    best_score = -1.0
    for var in shared:
        belief = composed.global_beliefs.get((sink_skill, var), {})
        score = max(belief.get(l, 0.0) for l in ("credential", "secret", "pii"))
        if score > best_score:
            best_score = score
            best = var
    return best
