"""
Composer: discover cross-skill variable links, topologically order skills,
propagate beliefs forward across boundaries, build joint capability sets.

Uses exact variable-name matching as the primary linkage strategy. When no
exact links exist between a pair of skills the composer falls back to a
filename-alphabetical ordering and marks findings as ordering_uncertain.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy

from .config import EXTERNAL_SINK_OPS, LABELS, SENSITIVE_SOURCE_OPS
from .types import ComposedESM, ESM, VariableLink


def compose(esms: list[ESM]) -> ComposedESM:
    links = _discover_exact_links(esms)
    ordered, ordering_method, ordering_confidence = _order_skills(esms, links)

    global_beliefs: dict[tuple[str, str], dict[str, float]] = {}
    isolation_beliefs: dict[tuple[str, str], dict[str, float]] = {}
    for esm in ordered:
        for var, dist in esm.beliefs.items():
            global_beliefs[(esm.skill_file, var)] = deepcopy(dist)
        for var, dist in esm.isolation_beliefs.items():
            isolation_beliefs[(esm.skill_file, var)] = deepcopy(dist)

    # Propagate forward across each link, in dependency order
    name_to_index = {e.skill_file: i for i, e in enumerate(ordered)}
    sorted_links = sorted(
        links,
        key=lambda l: (
            name_to_index.get(l.from_skill, 0),
            name_to_index.get(l.to_skill, 0),
        ),
    )
    for link in sorted_links:
        from_key = (link.from_skill, link.from_var)
        to_key = (link.to_skill, link.to_var)
        if from_key not in global_beliefs:
            continue
        if to_key not in global_beliefs:
            global_beliefs[to_key] = {l: 0.0 for l in LABELS}
        src = global_beliefs[from_key]
        for label in LABELS:
            global_beliefs[to_key][label] = max(
                global_beliefs[to_key][label],
                src.get(label, 0.0) * link.confidence,
            )

    skill_capabilities = {e.skill_file: e.capabilities for e in ordered}
    joint_capabilities: frozenset[str]
    if ordered:
        joint_capabilities = frozenset.union(*(e.capabilities for e in ordered))
    else:
        joint_capabilities = frozenset()

    source_skills = frozenset(
        e.skill_file for e in ordered if e.capabilities & SENSITIVE_SOURCE_OPS
    )
    sink_skills = frozenset(
        e.skill_file for e in ordered if e.capabilities & EXTERNAL_SINK_OPS
    )
    structurally_dangerous = bool(source_skills) and bool(sink_skills) and bool(
        source_skills - sink_skills or sink_skills - source_skills
    )

    return ComposedESM(
        ordered_esms=ordered,
        global_beliefs=global_beliefs,
        isolation_beliefs=isolation_beliefs,
        links=links,
        joint_capabilities=joint_capabilities,
        skill_capabilities=skill_capabilities,
        ordering_confidence=ordering_confidence,
        ordering_method=ordering_method,
        structurally_dangerous=structurally_dangerous,
        source_skills=source_skills,
        sink_skills=sink_skills,
    )


def _discover_exact_links(esms: list[ESM]) -> list[VariableLink]:
    links: list[VariableLink] = []
    by_file = {e.skill_file: e for e in esms}
    output_by_var: dict[str, list[str]] = defaultdict(list)
    for e in esms:
        for v in e.outputs:
            output_by_var[v].append(e.skill_file)

    for to_esm in esms:
        for v in to_esm.inputs:
            sources = output_by_var.get(v, [])
            for src in sources:
                if src == to_esm.skill_file:
                    continue
                links.append(VariableLink(
                    from_skill=src,
                    from_var=v,
                    to_skill=to_esm.skill_file,
                    to_var=v,
                    link_type="exact",
                    confidence=1.0,
                ))
    return links


def _order_skills(
    esms: list[ESM], links: list[VariableLink]
) -> tuple[list[ESM], str, float]:
    by_file = {e.skill_file: e for e in esms}
    if not esms:
        return [], "none", 1.0

    # Build graph: from_skill -> set(to_skill)
    graph: dict[str, set[str]] = defaultdict(set)
    in_degree: dict[str, int] = {e.skill_file: 0 for e in esms}
    for link in links:
        if link.to_skill in graph[link.from_skill]:
            continue
        graph[link.from_skill].add(link.to_skill)
        in_degree[link.to_skill] = in_degree.get(link.to_skill, 0) + 1

    # Kahn's
    queue = sorted(name for name, d in in_degree.items() if d == 0)
    ordered_names: list[str] = []
    while queue:
        node = queue.pop(0)
        ordered_names.append(node)
        for neighbour in sorted(graph[node]):
            in_degree[neighbour] -= 1
            if in_degree[neighbour] == 0:
                queue.append(neighbour)

    method = "topological"
    confidence = 1.0
    if len(ordered_names) < len(esms):
        # Cycle — drop semantic links first. We only have exact links here,
        # so just fall back to alphabetical and tag uncertain.
        ordered_names = sorted(e.skill_file for e in esms)
        method = "alphabetical_cycle_fallback"
        confidence = 0.4
    elif not links:
        method = "alphabetical_no_links"
        confidence = 0.5

    ordered = [by_file[name] for name in ordered_names]
    return ordered, method, confidence
