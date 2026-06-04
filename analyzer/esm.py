"""
ESM builder — pure transformation from SkillExtraction to ESM.

Runs the three belief passes, injects forward_credential operations for
pass-through credentials (Revision #2), and snapshots isolation beliefs for
the P7 amplification check downstream.
"""

from __future__ import annotations

from .belief import (
    apply_aggregation,
    apply_hint,
    clamp_low_signal,
    empty_belief,
    name_prior,
    snapshot,
)
from .types import ESM, Operation, SkillExtraction


def build_esm(extraction: SkillExtraction) -> ESM:
    declared_in = [v.name for v in extraction.inputs]
    declared_out = [v.name for v in extraction.outputs]

    op_var_names: set[str] = set()
    for op in extraction.operations:
        if op.reads_variable:
            op_var_names.add(op.reads_variable)
        if op.writes_variable:
            op_var_names.add(op.writes_variable)

    all_vars: list[str] = []
    seen: set[str] = set()
    for name in declared_in + declared_out + list(extraction.inferred_vars) + sorted(op_var_names):
        if name and name not in seen:
            seen.add(name)
            all_vars.append(name)

    # ---- Pass 1: name heuristics ----
    beliefs: dict[str, dict[str, float]] = {}
    for var in all_vars:
        beliefs[var] = name_prior(var)

    # ---- Pass 2: sensitivity hints ----
    for hint in extraction.sensitivity_hints:
        if hint.variable not in beliefs:
            beliefs[hint.variable] = name_prior(hint.variable)
            all_vars.append(hint.variable)
        apply_hint(beliefs, hint)

    # ---- Pass 3: aggregations ----
    for agg in extraction.aggregations:
        # ensure inputs have priors so the union-bound contribution is real
        for in_var in agg.input_variables:
            if in_var not in beliefs:
                beliefs[in_var] = name_prior(in_var)
        if agg.output_variable not in beliefs:
            beliefs[agg.output_variable] = name_prior(agg.output_variable)
        apply_aggregation(beliefs, agg)

    clamp_low_signal(beliefs)

    operations = list(extraction.operations)
    capabilities = set(op.op_type for op in operations)

    # ---- structural forward_credential injection (P5/Pattern B) ----
    declared_input_set = set(declared_in)
    declared_output_set = set(declared_out)
    forward_targets: list[str] = []
    for var in declared_output_set:
        if var not in declared_input_set:
            continue  # not a pass-through
        b = beliefs.get(var, empty_belief())
        if b.get("credential", 0.0) > 0.5 or b.get("secret", 0.0) > 0.5:
            forward_targets.append(var)

    for var in forward_targets:
        operations.append(Operation(
            op_type="forward_credential",
            reads_variable=var,
            writes_variable=var,
            external_target=None,
            is_external=False,
            line_number=None,
            raw_text=f"[inferred] {var} is passed through to downstream skills",
            skill_file=extraction.skill_file,
        ))
        capabilities.add("forward_credential")

    isolation = snapshot(beliefs)

    esm = ESM(
        skill_file=extraction.skill_file,
        operations=operations,
        beliefs=beliefs,
        isolation_beliefs=isolation,
        capabilities=frozenset(capabilities),
        inputs=declared_in,
        outputs=declared_out,
        all_vars=all_vars,
        extraction_confidence=extraction.extraction_confidence,
        has_aggregations=bool(extraction.aggregations),
        notes=extraction.notes,
    )
    return esm
