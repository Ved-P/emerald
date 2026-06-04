"""
Three-pass belief seeding:

  Pass 1: name heuristics — case-insensitive regex over variable names
  Pass 2: sensitivity hints from the extractor (LLM or heuristic) — capped at 0.95
  Pass 3: aggregation union-bound — P(L|agg) = 1 - prod(1 - P(L|in_i))

Pessimistic principle: passes only ever raise label probabilities, never
lower them.
"""

from __future__ import annotations

import re
from copy import deepcopy

from .config import LABELS
from .types import Aggregation, SensitivityHint


_NAME_PRIORS: tuple[tuple[re.Pattern, dict[str, float]], ...] = (
    (re.compile(r"(?:TOKEN|API[_-]?KEY|SECRET[_-]?KEY|PRIVATE[_-]?KEY|PASSWORD|PASSWD|ROUTING[_-]?KEY|API[_-]?SECRET)", re.IGNORECASE),
     {"credential": 0.92, "secret": 0.05, "pii": 0.01, "untrusted_external": 0.01}),
    (re.compile(r"(?:ACCESS[_-]?KEY|AUTH(?![_-]?LOG)|BEARER|CREDENTIAL)", re.IGNORECASE),
     {"credential": 0.70, "secret": 0.25, "pii": 0.01, "untrusted_external": 0.01}),
    (re.compile(r"\bSECRET\b", re.IGNORECASE),
     {"credential": 0.45, "secret": 0.70, "pii": 0.01, "untrusted_external": 0.01}),
    (re.compile(r"(?:SSN|SOCIAL[_-]?SECURITY|TAX[_-]?ID)", re.IGNORECASE),
     {"credential": 0.01, "secret": 0.02, "pii": 0.98, "untrusted_external": 0.01}),
    (re.compile(r"(?:SALARY|WAGE|COMPENSATION)", re.IGNORECASE),
     {"credential": 0.01, "secret": 0.10, "pii": 0.85, "untrusted_external": 0.01}),
    (re.compile(r"(?:EMAIL|PHONE|ADDRESS)", re.IGNORECASE),
     {"credential": 0.01, "secret": 0.01, "pii": 0.60, "untrusted_external": 0.10}),
    (re.compile(r"(?:EMPLOYEE|CUSTOMER|PATIENT|PROVISIONED[_-]?USER|USER[_-]?DATA|PERSON)", re.IGNORECASE),
     {"credential": 0.10, "secret": 0.10, "pii": 0.65, "untrusted_external": 0.10}),
    (re.compile(r"(?:DIAGNOSTICS|ENV[_-]?VARS?|ENVIRON|BUILD[_-]?ENV)", re.IGNORECASE),
     {"credential": 0.35, "secret": 0.55, "pii": 0.25, "untrusted_external": 0.10}),
    (re.compile(r"(?:METRICS[_-]?DATA|METRICS_PAYLOAD)", re.IGNORECASE),
     {"credential": 0.20, "secret": 0.30, "pii": 0.05, "untrusted_external": 0.10}),
    (re.compile(r"(?:PAYLOAD|REPORT|SUMMARY|CONTEXT|RESPONSE|RESULTS?)", re.IGNORECASE),
     {"credential": 0.10, "secret": 0.15, "pii": 0.20, "untrusted_external": 0.35}),
    (re.compile(r"(?:LOG|HISTORY)", re.IGNORECASE),
     {"credential": 0.20, "secret": 0.30, "pii": 0.20, "untrusted_external": 0.05}),
    (re.compile(r"(?:LINT|REPORT|REVIEW)", re.IGNORECASE),
     {"credential": 0.05, "secret": 0.10, "pii": 0.05, "untrusted_external": 0.35}),
    (re.compile(r"(?:PATH|DIR|URL|HOST|ENDPOINT|HOOK|HOOK[_-]?URL)", re.IGNORECASE),
     {"credential": 0.02, "secret": 0.08, "pii": 0.01, "untrusted_external": 0.20}),
    (re.compile(r"(?:STATUS|COUNT|FLAG|BOOL|RESULT[_-]?CODE|TIMESTAMP)", re.IGNORECASE),
     {"credential": 0.01, "secret": 0.02, "pii": 0.01, "untrusted_external": 0.05, "benign": 0.95}),
)

_DEFAULT_PRIOR = {"credential": 0.05, "secret": 0.08, "pii": 0.08, "untrusted_external": 0.15}


def empty_belief() -> dict[str, float]:
    return {label: 0.0 for label in LABELS}


def name_prior(name: str) -> dict[str, float]:
    """Pass 1: name heuristics."""
    belief = empty_belief()
    matched = False
    for pat, values in _NAME_PRIORS:
        if pat.search(name):
            for k, v in values.items():
                belief[k] = max(belief.get(k, 0.0), v)
            matched = True
            break  # first match wins per the spec
    if not matched:
        for k, v in _DEFAULT_PRIOR.items():
            belief[k] = max(belief.get(k, 0.0), v)
    return belief


def apply_hint(beliefs: dict[str, dict[str, float]], hint: SensitivityHint) -> None:
    """Pass 2: amplify the named label via an extractor hint."""
    if hint.variable not in beliefs:
        return
    label = hint.contains
    if label not in LABELS:
        return
    amplified = min(hint.confidence * 0.95, 0.95)
    beliefs[hint.variable][label] = max(beliefs[hint.variable][label], amplified)


def apply_aggregation(
    beliefs: dict[str, dict[str, float]], agg: Aggregation
) -> None:
    """
    Pass 3: union-bound update for an aggregating output variable.

    For each label L:
        P(L | out) = 1 - prod_{i in inputs}(1 - P(L | input_i))
    Then max-merge with existing belief for `out` (pessimistic principle).
    """
    out = agg.output_variable
    if out not in beliefs:
        return
    contributors: list[dict[str, float]] = []
    for in_var in agg.input_variables:
        if in_var in beliefs:
            contributors.append(beliefs[in_var])
        else:
            # Seed an ephemeral prior from the input's name and union it in
            contributors.append(name_prior(in_var))
    if not contributors:
        return
    for label in LABELS:
        if label == "benign":
            continue
        complement = 1.0
        for c in contributors:
            complement *= (1.0 - c.get(label, 0.0))
        agg_belief = 1.0 - complement
        beliefs[out][label] = max(beliefs[out][label], agg_belief)


def snapshot(beliefs: dict[str, dict[str, float]]) -> dict[str, dict[str, float]]:
    return deepcopy(beliefs)


def clamp_low_signal(beliefs: dict[str, dict[str, float]]) -> None:
    """Variables with no significant label belief get a high 'benign' marker."""
    for var, b in beliefs.items():
        if max(b.get(l, 0.0) for l in LABELS if l != "benign") < 0.1:
            b["benign"] = max(b.get("benign", 0.0), 0.9)
