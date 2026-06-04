"""
DFA reachability checker.

The composed ESMs form a simple linear DFA in execution order. We walk that
DFA, evaluating policies P1..P7 (plus dynamic Tier-2) at every operation
read site, and emit a RawFinding when a policy fires.
"""

from __future__ import annotations

from copy import deepcopy

from .config import (
    AMPLIFICATION_COMPOSED,
    AMPLIFICATION_DELTA,
    AMPLIFICATION_ISOLATION,
    EXEC_OPS,
    EXTERNAL_SINK_OPS,
    LABELS,
    NETWORK_SINK_OPS,
    SENSITIVE_SOURCE_OPS,
    THRESHOLD,
    THRESHOLD_TIER2,
    TIER1_COVERED_PAIRS,
)
from .types import ComposedESM, ESM, Operation, RawFinding, WitnessStep


def dfa_check(composed: ComposedESM) -> list[RawFinding]:
    findings: list[RawFinding] = []
    witness_log: list[WitnessStep] = []
    source_record: dict[str, tuple[str, Operation]] = {}

    for esm in composed.ordered_esms:
        for op in esm.operations:
            var = op.reads_variable
            if var is None:
                # Operation reads something that wasn't extractable.
                # Still log to witness, but skip belief checks.
                witness_log.append(WitnessStep(
                    skill_file=esm.skill_file,
                    operation=op,
                    variable="",
                    belief_at_step={},
                    description=_describe_step(esm, op, "", {}),
                ))
                _record_source(source_record, esm, op)
                continue

            belief = composed.global_beliefs.get(
                (esm.skill_file, var), _empty_belief()
            )
            step = WitnessStep(
                skill_file=esm.skill_file,
                operation=op,
                variable=var,
                belief_at_step=deepcopy(belief),
                description=_describe_step(esm, op, var, belief),
            )
            witness_log.append(step)
            _record_source(source_record, esm, op)

            # ----- Tier 1 policies -----
            if _matches_p1(op, belief, THRESHOLD):
                findings.append(_build_finding(
                    "P1", esm, op, var, belief, witness_log, composed, source_record,
                ))
            if _matches_p2(op, belief, THRESHOLD):
                findings.append(_build_finding(
                    "P2", esm, op, var, belief, witness_log, composed, source_record,
                ))
            if _matches_p3(op, belief, THRESHOLD):
                findings.append(_build_finding(
                    "P3", esm, op, var, belief, witness_log, composed, source_record,
                ))
            if _matches_p4(op, belief, THRESHOLD):
                findings.append(_build_finding(
                    "P4", esm, op, var, belief, witness_log, composed, source_record,
                ))
            if _matches_p6(op, belief, esm, THRESHOLD):
                findings.append(_build_finding(
                    "P6", esm, op, var, belief, witness_log, composed, source_record,
                ))

            # ----- Tier 2 dynamic policies -----
            for src_op, sink_op in _tier2_pairs(composed.joint_capabilities):
                if op.op_type != sink_op:
                    continue
                if not op.is_external:
                    continue
                sensitivity = max(
                    belief.get("credential", 0.0),
                    belief.get("secret", 0.0),
                    belief.get("pii", 0.0),
                )
                if sensitivity <= THRESHOLD_TIER2:
                    continue
                # Don't double-emit when Tier 1 already covered this op
                if _tier1_already_fired(findings, esm, op, var):
                    continue
                findings.append(_build_finding(
                    f"P-T2-{src_op}-{sink_op}",
                    esm, op, var, belief, witness_log, composed, source_record,
                    cwe_override="CWE-200",
                ))

    # ----- P5 — unnecessary credential forwarding -----
    findings += _p5_check(composed)

    # ----- P7 — belief amplification -----
    findings += _p7_check(composed)

    # If still nothing, fallback structural
    if not findings:
        findings += _fallback_check(composed)

    return findings


# ----------------------------------------------------------------------
# matching helpers
# ----------------------------------------------------------------------

def _matches_p1(op: Operation, belief: dict[str, float], theta: float) -> bool:
    return (
        op.op_type in {"post_http", "send_slack", "send_email", "scp_transfer", "ssh_execute"}
        and bool(op.is_external)
        and belief.get("credential", 0.0) > theta
    )


def _matches_p2(op: Operation, belief: dict[str, float], theta: float) -> bool:
    return (
        op.op_type in {"post_http", "send_slack", "send_email"}
        and bool(op.is_external)
        and belief.get("pii", 0.0) > theta
    )


def _matches_p3(op: Operation, belief: dict[str, float], theta: float) -> bool:
    return (
        op.op_type in {"post_http", "send_slack", "send_email"}
        and bool(op.is_external)
        and belief.get("secret", 0.0) > theta
        and belief.get("credential", 0.0) <= theta  # avoid P1 overlap
        and belief.get("pii", 0.0) <= theta
    )


def _matches_p4(op: Operation, belief: dict[str, float], theta: float) -> bool:
    return (
        op.op_type in EXEC_OPS
        and belief.get("untrusted_external", 0.0) > theta
    )


def _matches_p6(op: Operation, belief: dict[str, float], esm: ESM, theta: float) -> bool:
    return (
        op.op_type == "send_email"
        and esm_no_tls(esm)
        and (
            belief.get("credential", 0.0) > theta
            or belief.get("secret", 0.0) > theta
        )
    )


def esm_no_tls(esm: ESM) -> bool:
    # The Layer 1 parser tagged this on the partial; we re-derive from notes
    # text if needed for safety
    text = esm.notes.lower()
    return "port 25" in text or "tls is not required" in text or "starttls" in text


def _tier2_pairs(caps: frozenset[str]):
    sources = caps & SENSITIVE_SOURCE_OPS
    sinks = caps & EXTERNAL_SINK_OPS
    for s in sources:
        for k in sinks:
            if (s, k) in TIER1_COVERED_PAIRS:
                continue
            yield (s, k)


def _tier1_already_fired(
    findings: list[RawFinding], esm: ESM, op: Operation, var: str
) -> bool:
    for f in findings:
        if (
            f.policy_id in {"P1", "P2", "P3"}
            and f.sink_skill == esm.skill_file
            and f.sink_op is op
            and f.trigger_variable == var
        ):
            return True
    return False


# ----------------------------------------------------------------------
# P5 — unnecessary credential forwarding
# ----------------------------------------------------------------------

def _p5_check(composed: ComposedESM) -> list[RawFinding]:
    findings: list[RawFinding] = []
    esm_by_file = {e.skill_file: e for e in composed.ordered_esms}

    # Output variables exposed but never consumed downstream
    all_declared_inputs: set[str] = set()
    for e in composed.ordered_esms:
        all_declared_inputs.update(e.inputs)
    for e in composed.ordered_esms:
        for var in e.outputs:
            if var in e.inputs:
                continue  # handled by the pass-through forward_credential
            if var in all_declared_inputs:
                # Some downstream skill declares it as input -> link-based P5 below
                continue
            belief = e.beliefs.get(var, {})
            if belief.get("credential", 0.0) <= 0.5 and belief.get("secret", 0.0) <= 0.5:
                continue
            # Credential / secret exposed via shared context with no declared consumer
            findings.append(RawFinding(
                policy_id="P5",
                checker="dfa",
                sink_skill=e.skill_file,
                sink_op=_dummy_op(e.skill_file, "forward_credential", var),
                source_skill=e.skill_file,
                source_op=_first_source_op(e),
                trigger_variable=var,
                trigger_beliefs=deepcopy(belief),
                cross_skill=bool(composed.ordered_esms and len(composed.ordered_esms) > 1),
            ))

    for link in composed.links:
        belief = composed.global_beliefs.get(
            (link.to_skill, link.to_var), _empty_belief()
        )
        if belief.get("credential", 0.0) <= 0.5 and belief.get("secret", 0.0) <= 0.5:
            continue
        to_esm = esm_by_file.get(link.to_skill)
        if to_esm is None:
            continue
        # Is the variable consumed by a substantive op? "Substantive" =
        # anything other than forward_credential / write_log.
        consumed = False
        consumed_externally = False
        for op in to_esm.operations:
            if op.reads_variable != link.to_var:
                continue
            if op.op_type in {"forward_credential", "write_log"}:
                continue
            consumed = True
            if op.is_external or op.op_type in EXTERNAL_SINK_OPS:
                consumed_externally = True
                break
        if not consumed:
            from_esm = esm_by_file.get(link.from_skill)
            findings.append(RawFinding(
                policy_id="P5",
                checker="dfa",
                sink_skill=link.to_skill,
                sink_op=_dummy_op(link.to_skill, "forward_credential", link.to_var),
                source_skill=link.from_skill,
                source_op=_first_source_op(from_esm) if from_esm else None,
                trigger_variable=link.to_var,
                trigger_beliefs=deepcopy(belief),
                cross_skill=link.from_skill != link.to_skill,
            ))
        elif consumed_externally:
            # Strong signal: credential forwarded AND used in an external sink.
            # P1 will also fire on that sink op, but emit a P5 too at lower
            # severity so the structural finding is visible.
            pass
    return findings


# ----------------------------------------------------------------------
# P7 — belief amplification
# ----------------------------------------------------------------------

def _p7_check(composed: ComposedESM) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for (skill_file, var), composed_belief in composed.global_beliefs.items():
        composed_max = max(
            composed_belief.get(l, 0.0) for l in LABELS if l != "benign"
        )
        if composed_max < AMPLIFICATION_COMPOSED:
            continue
        # Max isolation belief for this variable across all skills that hold it
        isolation_maxes: list[float] = []
        for esm in composed.ordered_esms:
            iso = composed.isolation_beliefs.get((esm.skill_file, var))
            if not iso:
                continue
            isolation_maxes.append(
                max(iso.get(l, 0.0) for l in LABELS if l != "benign")
            )
        if not isolation_maxes:
            continue
        max_iso = max(isolation_maxes)
        if (
            max_iso < AMPLIFICATION_ISOLATION
            and composed_max - max_iso > AMPLIFICATION_DELTA
        ):
            # Find the sink op that triggered the high composed belief
            sink_skill, sink_op = _find_sink_for_var(composed, var)
            source_skill = _argmax_isolation(composed, var)
            findings.append(RawFinding(
                policy_id="P7",
                checker="dfa",
                sink_skill=sink_skill or skill_file,
                sink_op=sink_op,
                source_skill=source_skill,
                trigger_variable=var,
                trigger_beliefs=deepcopy(composed_belief),
                cross_skill=bool(source_skill and source_skill != (sink_skill or skill_file)),
            ))
    return findings


def _find_sink_for_var(composed: ComposedESM, var: str):
    for esm in composed.ordered_esms:
        for op in esm.operations:
            if op.reads_variable == var and op.op_type in EXTERNAL_SINK_OPS:
                return esm.skill_file, op
    return None, None


def _argmax_isolation(composed: ComposedESM, var: str) -> str | None:
    best: tuple[float, str] | None = None
    for (skill_file, v), beliefs in composed.isolation_beliefs.items():
        if v != var:
            continue
        m = max(beliefs.get(l, 0.0) for l in LABELS if l != "benign")
        if best is None or m > best[0]:
            best = (m, skill_file)
    return best[1] if best else None


# ----------------------------------------------------------------------
# Fallback — zero findings case
# ----------------------------------------------------------------------

def _fallback_check(composed: ComposedESM) -> list[RawFinding]:
    findings: list[RawFinding] = []
    has_source = bool(composed.joint_capabilities & SENSITIVE_SOURCE_OPS)
    has_sink = bool(composed.joint_capabilities & EXTERNAL_SINK_OPS)
    if not (has_source and has_sink):
        return findings
    source_skill = None
    source_op = None
    sink_skill = None
    sink_op = None
    for esm in composed.ordered_esms:
        for op in esm.operations:
            if op.op_type in SENSITIVE_SOURCE_OPS and source_op is None:
                source_skill, source_op = esm.skill_file, op
            if op.op_type in EXTERNAL_SINK_OPS and sink_op is None:
                sink_skill, sink_op = esm.skill_file, op
    if sink_skill and source_skill:
        findings.append(RawFinding(
            policy_id="FALLBACK",
            checker="dfa",
            sink_skill=sink_skill,
            sink_op=sink_op,
            source_skill=source_skill,
            source_op=source_op,
            trigger_variable="[unresolved]",
            trigger_beliefs={l: 0.0 for l in LABELS},
            cross_skill=source_skill != sink_skill,
            low_confidence=True,
        ))
    return findings


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

def _empty_belief() -> dict[str, float]:
    return {label: 0.0 for label in LABELS}


def _build_finding(
    policy_id: str,
    esm: ESM,
    op: Operation,
    var: str,
    belief: dict[str, float],
    witness_log: list[WitnessStep],
    composed: ComposedESM,
    source_record: dict[str, tuple[str, Operation]],
    cwe_override: str | None = None,
) -> RawFinding:
    source_skill = None
    source_op = None
    if var in source_record:
        source_skill, source_op = source_record[var]
    # Fall back to link-based attribution: if a link feeds `var` into this
    # skill, the upstream end of the link is the source.
    if source_skill is None and var:
        for link in composed.links:
            if link.to_skill == esm.skill_file and link.to_var == var:
                source_skill = link.from_skill
                source_op = _first_source_op_in(composed, link.from_skill)
                break
    # Final fallback: the most-upstream skill that declares this var as an output
    if source_skill is None and var:
        for e in composed.ordered_esms:
            if e.skill_file == esm.skill_file:
                break
            if var in e.outputs:
                source_skill = e.skill_file
                source_op = _first_source_op_in(composed, e.skill_file)
                break
    cross_skill = bool(source_skill and source_skill != esm.skill_file)
    # Even without an explicit source record, treat the finding as cross_skill
    # if at least two skills have a sensitive source / external sink split.
    if not cross_skill and composed.structurally_dangerous and op.op_type in EXTERNAL_SINK_OPS:
        cross_skill = True

    notes_quotes = _extract_notes_quotes(esm, var)
    return RawFinding(
        policy_id=policy_id,
        checker="dfa",
        sink_skill=esm.skill_file,
        sink_op=op,
        source_skill=source_skill,
        source_op=source_op,
        trigger_variable=var,
        trigger_beliefs=deepcopy(belief),
        witness_path=list(witness_log),
        notes_quotes=notes_quotes,
        cross_skill=cross_skill,
    )


def _record_source(
    record: dict[str, tuple[str, Operation]],
    esm: ESM,
    op: Operation,
) -> None:
    # Only record an op that *creates* sensitive content (read/generate ops)
    if op.op_type not in SENSITIVE_SOURCE_OPS:
        return
    target_var = op.writes_variable
    if not target_var:
        return
    if target_var in record:
        return  # first writer wins
    record[target_var] = (esm.skill_file, op)


def _describe_step(esm: ESM, op: Operation, var: str, belief: dict[str, float]) -> str:
    if not belief or not var:
        return f"{esm.skill_file}: {op.op_type}"
    top = max((l for l in LABELS if l != "benign"), key=lambda l: belief.get(l, 0.0))
    prob = belief.get(top, 0.0)
    if op.op_type == "read_file":
        return f"{esm.skill_file} reads file into {var} (P({top})={prob:.2f})"
    if op.op_type == "read_env":
        return f"{esm.skill_file} reads env var {var} (P({top})={prob:.2f})"
    if op.op_type == "post_http":
        return (
            f"{esm.skill_file} posts {var} to "
            f"{op.external_target or 'external endpoint'} (P({top})={prob:.2f})"
        )
    if op.op_type == "send_slack":
        return f"{esm.skill_file} sends {var} to Slack (P({top})={prob:.2f})"
    if op.op_type == "send_email":
        return f"{esm.skill_file} emails {var} (P({top})={prob:.2f})"
    if op.op_type == "forward_credential":
        return f"{esm.skill_file} forwards {var} into shared context"
    return f"{esm.skill_file}: {op.op_type} on {var} (P({top})={prob:.2f})"


def _extract_notes_quotes(esm: ESM, var: str) -> list[str]:
    if not esm.notes:
        return []
    out: list[str] = []
    for line in esm.notes.splitlines():
        line = line.strip("- *").strip()
        if not line:
            continue
        lower = line.lower()
        if any(k in lower for k in (
            "no sanit", "no redact", "no filter", "full", "without",
            "audit", "all detail", "raw", "in cleartext", "as-is",
            "fully automated", "ml accuracy", "no consent",
        )):
            out.append(line)
        elif var and var in line:
            out.append(line)
        if len(out) >= 2:
            break
    return out


def _dummy_op(skill_file: str, op_type: str, var: str) -> Operation:
    return Operation(
        op_type=op_type,
        reads_variable=var,
        writes_variable=var,
        external_target=None,
        is_external=False,
        line_number=None,
        raw_text=f"[inferred] {var}",
        skill_file=skill_file,
    )


def _first_source_op(esm: ESM | None) -> Operation | None:
    if esm is None:
        return None
    for op in esm.operations:
        if op.op_type in SENSITIVE_SOURCE_OPS:
            return op
    return None


def _first_source_op_in(composed: ComposedESM, skill_file: str) -> Operation | None:
    for esm in composed.ordered_esms:
        if esm.skill_file == skill_file:
            return _first_source_op(esm)
    return None
