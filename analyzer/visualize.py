"""
Visualization of the composed Epistemic DFA at operation granularity.

The composed ESM is a product automaton over per-skill operation sequences.
Each operation is a transition; visualizing one node per skill collapses
all of those transitions and over- or under-approximates the actual
capabilities. We instead emit:

  * One node per ``Operation`` in each skill's execution order.
  * One ``cluster_<skill>`` Graphviz subgraph per skill, grouping its ops.
  * Solid edges between sequential ops in the same skill — the intra-skill
    control flow.
  * Dashed cross-cluster edges from the op that *writes* a variable in
    skill A to the op that *reads* it in skill B — the actual data
    dependence, not just shared capability.
  * Sink-op nodes that policies fired on are highlighted in red.

Emits Graphviz DOT files (no python-graphviz dependency). Two files per
harness:

  * ``<harness>.dot``         — full op-level composition graph.
  * ``<harness>.witness.dot`` — one cluster per finding showing the
                                source-op → sink-op path that triggered it.

Render with:  ``dot -Tsvg <file>.dot -o <file>.svg``

Never writes to stdout — JSON output remains clean.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from .config import EXTERNAL_SINK_OPS, LABELS, SENSITIVE_SOURCE_OPS
from .types import ComposedESM, ESM, Operation


def render_harness(
    harness_dir: str,
    composed: ComposedESM,
    findings: list[dict],
    out_dir: str,
) -> list[str]:
    """Write .dot files describing the op-level ESM and the finding paths."""
    out_path = Path(out_dir)
    try:
        out_path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"# could not create viz dir {out_dir}: {exc}", file=sys.stderr)
        return []

    harness_name = Path(harness_dir.rstrip("/")).name
    main_path = out_path / f"{harness_name}.dot"
    witness_path = out_path / f"{harness_name}.witness.dot"

    bad_ops = _identify_bad_ops(composed, findings)
    op_node_ids = _assign_op_ids(composed)

    main_dot = _build_main_graph(harness_name, composed, op_node_ids, bad_ops)
    witness_dot = _build_witness_graph(
        harness_name, composed, findings, op_node_ids,
    )

    written: list[str] = []
    for path, content in ((main_path, main_dot), (witness_path, witness_dot)):
        try:
            path.write_text(content, encoding="utf-8")
            written.append(str(path))
        except OSError as exc:
            print(f"# could not write {path}: {exc}", file=sys.stderr)
    return written


# ======================================================================
# Op-id assignment & bad-state identification
# ======================================================================

OpKey = tuple[str, int]  # (skill_file, op_index)


def _assign_op_ids(composed: ComposedESM) -> dict[OpKey, str]:
    ids: dict[OpKey, str] = {}
    for esm in composed.ordered_esms:
        for i, _ in enumerate(esm.operations):
            ids[(esm.skill_file, i)] = f"{_safe_id(esm.skill_file)}__op{i}"
    return ids


def _identify_bad_ops(
    composed: ComposedESM, findings: list[dict]
) -> set[OpKey]:
    """An op is 'bad' if a policy fired on it. We map findings → ops by
    (skill_file, line_number); falling back to (skill_file, op_type)."""
    bad: set[OpKey] = set()
    for f in findings:
        sink_file = (f.get("location") or {}).get("file")
        if not sink_file:
            continue
        sink_line = (f.get("location") or {}).get("line")
        esm = _find_esm(composed, sink_file)
        if esm is None:
            continue
        matched = False
        # Match by line number first — most precise.
        if sink_line:
            for i, op in enumerate(esm.operations):
                if op.line_number == sink_line:
                    bad.add((esm.skill_file, i))
                    matched = True
                    break
        if matched:
            continue
        # Fall back: any external-sink op in the skill with belief > 0.5
        for i, op in enumerate(esm.operations):
            if op.op_type not in EXTERNAL_SINK_OPS:
                continue
            belief = _composed_belief(composed, esm.skill_file, op.reads_variable)
            if _danger_score(belief) > 0.5:
                bad.add((esm.skill_file, i))
                matched = True
                break
        if matched:
            continue
        # Last resort: first external-sink op
        for i, op in enumerate(esm.operations):
            if op.op_type in EXTERNAL_SINK_OPS:
                bad.add((esm.skill_file, i))
                break
    return bad


# ======================================================================
# Main graph
# ======================================================================

def _build_main_graph(
    name: str,
    composed: ComposedESM,
    op_ids: dict[OpKey, str],
    bad_ops: set[OpKey],
) -> str:
    lines: list[str] = []
    lines.append(f'digraph "{_safe_id(name)}" {{')
    lines.append('  graph [compound=true, rankdir=LR, fontname="Helvetica", '
                 'labelloc="t", '
                 f'label="Composed Epistemic DFA: {_escape(name)}"];')
    lines.append('  node  [fontname="Helvetica", shape=box, '
                 'style="rounded,filled", margin="0.15,0.07"];')
    lines.append('  edge  [fontname="Helvetica", fontsize=9];')
    lines.append("")

    # One cluster per skill, ops as nodes inside.
    for esm in composed.ordered_esms:
        lines.extend(_emit_skill_cluster(esm, composed, op_ids, bad_ops))
        lines.append("")

    # Cross-cluster data-dependence edges: writer-op in source → reader-op
    # in sink, one edge per (link, writer, reader) triple.
    lines.append("  // cross-skill data dependence")
    seen_edges: set[tuple[str, str, str]] = set()
    for link in composed.links:
        src_indices = _writer_op_indices(composed, link.from_skill, link.from_var)
        sink_indices = _reader_op_indices(composed, link.to_skill, link.to_var)
        if not src_indices:
            src_indices = [None]  # synthesize a per-cluster anchor edge
        if not sink_indices:
            sink_indices = [None]

        belief = composed.global_beliefs.get((link.to_skill, link.to_var), {})
        max_sens = _danger_score(belief)
        color, penwidth = _edge_style(max_sens)
        label = link.to_var
        top = _top_label(belief)
        if top:
            label = f"{label}\nP({top})={belief.get(top, 0.0):.2f}"

        for si in src_indices:
            for ti in sink_indices:
                src_node, src_cluster = _resolve_endpoint(
                    op_ids, link.from_skill, si,
                )
                tgt_node, tgt_cluster = _resolve_endpoint(
                    op_ids, link.to_skill, ti,
                )
                if not src_node or not tgt_node:
                    continue
                key = (src_node, tgt_node, link.to_var)
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                extras: list[str] = []
                if src_cluster:
                    extras.append(f'ltail=cluster_{src_cluster}')
                if tgt_cluster:
                    extras.append(f'lhead=cluster_{tgt_cluster}')
                extras_str = (", " + ", ".join(extras)) if extras else ""
                lines.append(
                    f'  "{src_node}" -> "{tgt_node}" '
                    f'[label="{_escape(label)}", color="{color}", '
                    f'style="dashed", penwidth={penwidth}{extras_str}];'
                )

    # Legend
    lines.append("")
    lines.append('  subgraph cluster_legend {')
    lines.append('    label="Legend";')
    lines.append('    style="dashed"; fontsize=10;')
    lines.append('    legend_source [label="sensitive source op", '
                 'fillcolor="#fff5d6"];')
    lines.append('    legend_sink   [label="external sink op", '
                 'fillcolor="#ffe0e0"];')
    lines.append('    legend_bad    [label="policy-flagged sink op", '
                 'fillcolor="#ff8080", color="#a00000", penwidth=2];')
    lines.append('    legend_fwd    [label="forward_credential (synthetic)", '
                 'fillcolor="#e0d0ff"];')
    lines.append('    legend_other  [label="other op", '
                 'fillcolor="#f0f0f0"];')
    lines.append('    legend_source -> legend_sink -> legend_bad -> '
                 'legend_fwd -> legend_other [style=invis];')
    lines.append('    legend_edge_high [shape=plaintext, '
                 'label="data dep ≥ 0.70", fontcolor="#a00000"];')
    lines.append('    legend_edge_med  [shape=plaintext, '
                 'label="data dep 0.50-0.69", fontcolor="#cc6600"];')
    lines.append('    legend_edge_low  [shape=plaintext, '
                 'label="data dep < 0.50", fontcolor="#666666"];')
    lines.append('  }')

    lines.append("}")
    return "\n".join(lines)


def _emit_skill_cluster(
    esm: ESM,
    composed: ComposedESM,
    op_ids: dict[OpKey, str],
    bad_ops: set[OpKey],
) -> list[str]:
    cluster_name = _safe_id(esm.skill_file)
    lines = [f'  subgraph cluster_{cluster_name} {{']
    is_source = esm.skill_file in composed.source_skills
    is_sink = esm.skill_file in composed.sink_skills
    cluster_fill = "#fafafa"
    if is_source and is_sink:
        cluster_fill = "#fff2e8"
    elif is_source:
        cluster_fill = "#fffaf0"
    elif is_sink:
        cluster_fill = "#fff6f6"
    role = []
    if is_source:
        role.append("source")
    if is_sink:
        role.append("sink")
    role_label = f" [{','.join(role)}]" if role else ""
    lines.append(
        f'    label="{_escape(esm.skill_file)}{role_label}";'
    )
    lines.append('    style="rounded,filled"; color="#555555";')
    lines.append(f'    fillcolor="{cluster_fill}"; fontsize=11;')

    if not esm.operations:
        empty_id = f"{cluster_name}__empty"
        lines.append(
            f'    "{empty_id}" [label="(no operations detected)", '
            'fillcolor="#eaeaea", style="rounded,filled,dashed"];'
        )
        lines.append("  }")
        return lines

    # One node per op
    for i, op in enumerate(esm.operations):
        node_id = op_ids[(esm.skill_file, i)]
        belief = _composed_belief(composed, esm.skill_file, op.reads_variable)
        is_bad = (esm.skill_file, i) in bad_ops
        fill = _op_fill_color(op, belief, is_bad)
        border = _op_border(is_bad)
        label = _op_label(op, belief)
        lines.append(
            f'    "{node_id}" [label="{_escape(label)}", '
            f'fillcolor="{fill}"{border}];'
        )

    # Sequential edges
    for i in range(len(esm.operations) - 1):
        from_id = op_ids[(esm.skill_file, i)]
        to_id = op_ids[(esm.skill_file, i + 1)]
        lines.append(
            f'    "{from_id}" -> "{to_id}" '
            f'[color="#888888", arrowsize=0.7];'
        )

    lines.append("  }")
    return lines


# ======================================================================
# Witness graph (per-finding focused view)
# ======================================================================

def _build_witness_graph(
    name: str,
    composed: ComposedESM,
    findings: list[dict],
    op_ids: dict[OpKey, str],
) -> str:
    lines: list[str] = []
    lines.append(f'digraph "{_safe_id(name)}_witness" {{')
    lines.append('  graph [compound=true, rankdir=LR, fontname="Helvetica", '
                 f'labelloc="t", label="Witness paths: {_escape(name)}"];')
    lines.append('  node  [fontname="Helvetica", shape=box, '
                 'style="rounded,filled", margin="0.12,0.06"];')
    lines.append('  edge  [fontname="Helvetica", fontsize=9];')
    lines.append("")

    if not findings:
        lines.append('  empty [label="No findings to display", '
                     'fillcolor="#dddddd"];')
        lines.append("}")
        return "\n".join(lines)

    for i, finding in enumerate(findings, start=1):
        sink_file = (finding.get("location") or {}).get("file")
        sink_line = (finding.get("location") or {}).get("line")
        sink_esm = _find_esm(composed, sink_file) if sink_file else None

        # Identify the sink op for this finding
        sink_op_idx = _match_op_by_line(sink_esm, sink_line) if sink_esm else None

        # Source skill / op — best-effort derive from related_skills
        related = list(finding.get("related_skills", []))
        source_file = None
        for s in related:
            if s != sink_file:
                source_file = s
                break
        source_esm = _find_esm(composed, source_file) if source_file else None
        source_op_idx = _first_source_op_index(source_esm) if source_esm else None

        cluster = f"cluster_finding_{i}"
        title_line = (
            f'{finding.get("id", "?")} · {finding.get("severity", "")} · '
            f'{_short(finding.get("title", ""), 60)}'
        )
        lines.append(f'  subgraph {cluster} {{')
        lines.append(f'    label="{_escape(title_line)}";')
        lines.append('    style="rounded"; color="#555555"; fontsize=10;')

        # Source op (or skill placeholder)
        src_node = f"f{i}_src"
        if source_esm and source_op_idx is not None:
            op = source_esm.operations[source_op_idx]
            src_label = (
                f"{source_esm.skill_file}\n{_op_label(op, _composed_belief(composed, source_esm.skill_file, op.reads_variable))}"
            )
        else:
            src_label = f"{source_file or '(unknown source)'}\n(source op inferred)"
        lines.append(f'    "{src_node}" [label="{_escape(src_label)}", '
                     'fillcolor="#fff5d6"];')

        # Sink op
        sink_node = f"f{i}_sink"
        if sink_esm and sink_op_idx is not None:
            op = sink_esm.operations[sink_op_idx]
            sink_label = (
                f"{sink_esm.skill_file}\n{_op_label(op, _composed_belief(composed, sink_esm.skill_file, op.reads_variable))}"
            )
        elif sink_file:
            sink_label = f"{sink_file}\n(sink op)"
        else:
            sink_label = "(unknown sink)"
        lines.append(
            f'    "{sink_node}" [label="{_escape(sink_label)}", '
            f'fillcolor="#ff8080", color="#a00000", penwidth=2];'
        )

        lines.append(
            f'    "{src_node}" -> "{sink_node}" '
            f'[color="#a00000", penwidth=2.0, style="dashed"];'
        )
        lines.append("  }")

    lines.append("}")
    return "\n".join(lines)


# ======================================================================
# Lookup / matching helpers
# ======================================================================

def _find_esm(composed: ComposedESM, skill_file: str | None) -> ESM | None:
    if not skill_file:
        return None
    for e in composed.ordered_esms:
        if e.skill_file == skill_file:
            return e
    return None


def _writer_op_indices(
    composed: ComposedESM, skill_file: str, var: str
) -> list[int]:
    esm = _find_esm(composed, skill_file)
    if not esm:
        return []
    explicit = [i for i, op in enumerate(esm.operations)
                if op.writes_variable == var]
    if explicit:
        return explicit
    # Fallback: any source-type op in this skill — the data presumably
    # came from there even if writes_variable wasn't set during extraction.
    for i, op in enumerate(esm.operations):
        if op.op_type in SENSITIVE_SOURCE_OPS:
            return [i]
    return []


def _reader_op_indices(
    composed: ComposedESM, skill_file: str, var: str
) -> list[int]:
    esm = _find_esm(composed, skill_file)
    if not esm:
        return []
    return [i for i, op in enumerate(esm.operations) if op.reads_variable == var]


def _resolve_endpoint(
    op_ids: dict[OpKey, str], skill_file: str, op_index: int | None,
) -> tuple[str | None, str | None]:
    """Resolve an endpoint to (node_id, cluster_for_compound_edge_or_None).

    When op_index is None, the caller didn't pin a specific op — we anchor
    the edge to the cluster (via ltail/lhead) by picking *some* node and
    returning the cluster name."""
    cluster_name = _safe_id(skill_file)
    if op_index is not None and (skill_file, op_index) in op_ids:
        return op_ids[(skill_file, op_index)], None
    # Pick the first op in this skill as a stand-in
    for (sf, idx), node_id in op_ids.items():
        if sf == skill_file:
            return node_id, cluster_name
    return None, None


def _match_op_by_line(esm: ESM | None, line: int | None) -> int | None:
    if esm is None or line is None:
        return None
    for i, op in enumerate(esm.operations):
        if op.line_number == line:
            return i
    return None


def _first_source_op_index(esm: ESM | None) -> int | None:
    if esm is None:
        return None
    for i, op in enumerate(esm.operations):
        if op.op_type in SENSITIVE_SOURCE_OPS:
            return i
    return 0 if esm.operations else None


# ======================================================================
# Belief / labelling helpers
# ======================================================================

def _composed_belief(
    composed: ComposedESM, skill_file: str, var: str | None,
) -> dict[str, float]:
    if not var:
        return {}
    return composed.global_beliefs.get((skill_file, var), {})


def _danger_score(belief: dict[str, float]) -> float:
    return max(
        (belief.get(l, 0.0) for l in LABELS if l != "benign"),
        default=0.0,
    )


def _top_label(belief: dict[str, float]) -> str | None:
    candidates = {
        l: belief.get(l, 0.0)
        for l in ("credential", "pii", "secret", "untrusted_external")
    }
    if not candidates or max(candidates.values()) <= 0.0:
        return None
    return max(candidates, key=candidates.get)


def _op_fill_color(op: Operation, belief: dict[str, float], is_bad: bool) -> str:
    if is_bad:
        return "#ff8080"
    if op.op_type == "forward_credential":
        return "#e0d0ff"
    if op.op_type in EXTERNAL_SINK_OPS:
        return "#ffe0e0"
    if op.op_type in SENSITIVE_SOURCE_OPS:
        return "#fff5d6"
    return "#f0f0f0"


def _op_border(is_bad: bool) -> str:
    return ', color="#a00000", penwidth=2' if is_bad else ""


def _op_label(op: Operation, belief: dict[str, float]) -> str:
    parts: list[str] = [op.op_type]
    var_line: list[str] = []
    if op.reads_variable:
        var_line.append(op.reads_variable)
    if op.writes_variable and op.writes_variable != op.reads_variable:
        var_line.append(f"→ {op.writes_variable}")
    if var_line:
        parts.append(" ".join(var_line))
    if op.external_target:
        target = op.external_target
        if len(target) > 40:
            target = target[:37] + "…"
        parts.append(f"to {target}")
    if op.is_external and not op.external_target:
        parts.append("(external)")
    top = _top_label(belief)
    if top and belief.get(top, 0.0) > 0.3:
        parts.append(f"P({top})={belief[top]:.2f}")
    return "\n".join(parts)


def _edge_style(max_sens: float) -> tuple[str, str]:
    if max_sens >= 0.70:
        return "#a00000", "2.5"
    if max_sens >= 0.50:
        return "#cc6600", "1.8"
    return "#888888", "1.0"


# ======================================================================
# String helpers
# ======================================================================

def _safe_id(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def _escape(text: str) -> str:
    # Backslashes are intentional (Graphviz \n escapes); only double-quote
    # needs escaping inside DOT label strings.
    return text.replace('"', '\\"')


def _short(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else (text[: max_len - 1] + "…")
