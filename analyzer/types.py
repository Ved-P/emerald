"""
Shared dataclasses passed between pipeline stages.

Defining them in one place avoids circular imports between parser, extractor,
belief, esm, composer, and the checkers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Variable:
    name: str
    description: str = ""
    source: str = "declared_input"  # or 'declared_output' / 'inferred'


@dataclass
class Operation:
    op_type: str
    reads_variable: Optional[str] = None
    writes_variable: Optional[str] = None
    external_target: Optional[str] = None
    is_external: Optional[bool] = False
    line_number: Optional[int] = None
    raw_text: str = ""
    skill_file: str = ""


@dataclass
class Aggregation:
    output_variable: str
    input_variables: list[str]
    evidence: str = ""


@dataclass
class SensitivityHint:
    variable: str
    contains: str  # one of LABELS
    confidence: float
    reason: str = ""


@dataclass
class PartialExtraction:
    """Output of Layer 1 — pure regex parsing of one skill file."""

    skill_file: str
    raw_text: str
    purpose: str = ""
    behavior: str = ""
    notes: str = ""
    inputs: list[Variable] = field(default_factory=list)
    outputs: list[Variable] = field(default_factory=list)
    code_blocks: list[str] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    referenced_caps_vars: list[str] = field(default_factory=list)
    aggregation_language: bool = False
    no_tls: bool = False


@dataclass
class SkillExtraction:
    """Layer 1 + Layer 2 merged result for one skill."""

    skill_file: str
    raw_text: str
    purpose: str
    behavior: str
    notes: str
    inputs: list[Variable]
    outputs: list[Variable]
    operations: list[Operation]
    capabilities: frozenset[str]
    aggregations: list[Aggregation]
    sensitivity_hints: list[SensitivityHint]
    no_tls: bool
    extraction_confidence: float
    inferred_vars: list[str] = field(default_factory=list)


@dataclass
class ESM:
    """Epistemic state machine for one skill — coarse states, beliefs, ops."""

    skill_file: str
    states: frozenset = field(default_factory=lambda: frozenset({"idle", "active", "done"}))
    initial_state: str = "idle"
    operations: list[Operation] = field(default_factory=list)
    beliefs: dict[str, dict[str, float]] = field(default_factory=dict)
    isolation_beliefs: dict[str, dict[str, float]] = field(default_factory=dict)
    capabilities: frozenset[str] = field(default_factory=frozenset)
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    all_vars: list[str] = field(default_factory=list)
    extraction_confidence: float = 1.0
    has_aggregations: bool = False
    notes: str = ""


@dataclass
class VariableLink:
    from_skill: str
    from_var: str
    to_skill: str
    to_var: str
    link_type: str = "exact"  # 'exact' | 'semantic' | 'inferred'
    confidence: float = 1.0


@dataclass
class ComposedESM:
    ordered_esms: list[ESM]
    global_beliefs: dict[tuple[str, str], dict[str, float]]
    isolation_beliefs: dict[tuple[str, str], dict[str, float]]
    links: list[VariableLink]
    joint_capabilities: frozenset[str]
    skill_capabilities: dict[str, frozenset[str]]
    ordering_confidence: float = 1.0
    ordering_method: str = "topological"
    structurally_dangerous: bool = False
    source_skills: frozenset[str] = field(default_factory=frozenset)
    sink_skills: frozenset[str] = field(default_factory=frozenset)


@dataclass
class WitnessStep:
    skill_file: str
    operation: Operation
    variable: str
    belief_at_step: dict[str, float]
    description: str


@dataclass
class RawFinding:
    policy_id: str
    checker: str  # 'dfa' | 'z3'
    sink_skill: Optional[str] = None
    sink_op: Optional[Operation] = None
    source_skill: Optional[str] = None
    source_op: Optional[Operation] = None
    trigger_variable: str = ""
    trigger_beliefs: dict[str, float] = field(default_factory=dict)
    witness_path: list[WitnessStep] = field(default_factory=list)
    notes_quotes: list[str] = field(default_factory=list)
    cross_skill: bool = False
    ordering_uncertain: bool = False
    low_confidence: bool = False
    z3_counterexample: Optional[dict] = None
