"""
Layer 2 semantic extractor.

Architecture (per the plan, §2):

  * Primary path — Claude reads the Layer-1 partial extraction plus the raw
    skill file and emits structured sensitivity hints, aggregations, missed
    operation classifications, and an explicit no_tls flag. The output is
    constrained to a closed vocabulary.

  * Fallback path — when ``ANTHROPIC_API_KEY`` is unset or the SDK is
    missing, a deterministic heuristic substitutes for the LLM. It applies
    name-based sensitivity inference, scans Behavior text for aggregation
    sub-fields, and detects sensitive file paths in input descriptions.

Both paths produce the same SkillExtraction dataclass. Downstream modules
(belief, ESM, composer, checkers, reporter) are unaware of which path ran.

Always applied (regardless of LLM availability):

  * Structural pre-check (Revision #2) — a variable that appears in both
    Inputs and Outputs of a skill AND matches a credential name pattern
    is flagged for forward_credential. Catches Pattern-B vulnerabilities
    even with zero LLM calls.
"""

from __future__ import annotations

import json
import re

from . import llm
from .types import (
    Aggregation,
    Operation,
    PartialExtraction,
    SensitivityHint,
    SkillExtraction,
    Variable,
)


# Output names that are clearly benign — exempt from aggregation broadcasting
_BENIGN_NAME_RE = re.compile(
    r"\b(STATUS|COUNT|FLAG|TIMESTAMP|RESULT_CODE|PROFILE)\b",
    re.IGNORECASE,
)

# Credential / PII / secret name fragments used by the heuristic fallback
_CRED_NAME_FRAGMENTS = (
    "token", "api_key", "apikey", "secret_key", "private_key",
    "password", "passwd", "auth_key", "auth_token", "credential",
    "ssh_key", "access_key", "bearer", "routing_key",
)
_SECRET_NAME_FRAGMENTS = ("secret", "auth", "key", "session", "cookie")
_PII_NAME_FRAGMENTS = (
    "ssn", "social_security", "tax_id", "salary", "wage", "compensation",
    "email", "phone", "address", "dob", "birth",
    "employee", "person", "customer", "patient", "user",
)
_UNTRUSTED_HINT_FRAGMENTS = (
    "external", "user_input", "request", "response_body",
    "from_network", "from_user",
)
_SENSITIVE_PATH_FRAGMENTS = (
    ".ssh/", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "/var/secrets", "/etc/shadow", "/.aws/", "credentials.json",
    "api_keys", "/private/", "private_key", ".pem", ".key",
    "secrets.json", "auth.log", "passwd",
)

_VALID_LABELS = {"credential", "secret", "pii", "untrusted_external", "benign"}
_VALID_OP_TYPES = {
    "read_file", "read_env", "read_db", "read_network",
    "generate_credential", "exec_shell",
    "post_http", "write_file", "write_log",
    "send_email", "send_slack",
    "ssh_execute", "scp_transfer",
    "forward_credential",
}


_SYSTEM_PROMPT = """You are a security analyst extracting structured \
information from an AI agent skill file. Be conservative: when uncertain, \
prefer lower confidence values and omit fields rather than guessing.

Return ONLY a JSON object (no prose, no markdown fences) matching the schema \
specified in the user message."""


_USER_PROMPT_TEMPLATE = """You will read one skill file from a multi-agent \
harness and extract semantic information that a regex-based parser cannot \
determine on its own.

A partial extraction has already been produced for you. Do NOT re-extract \
what is already given — only fill in the semantic gaps.

=== PARTIAL EXTRACTION (Layer 1) ===
{layer1_json}

=== RAW SKILL FILE ===
{skill_text}

=== YOUR TASK ===
Return a single JSON object with the following keys. Omit any key whose \
value you cannot determine with reasonable confidence.

{{
  "sensitivity_hints": [
    {{
      "variable": "<declared variable name>",
      "contains": "credential" | "secret" | "pii" | "untrusted_external" | "benign",
      "confidence": <float in [0, 1]>,
      "reason": "<one short sentence from or paraphrasing the skill text>"
    }}
  ],
  "aggregations": [
    {{
      "output_variable": "<declared output variable that aggregates content>",
      "input_variables": ["<sub-field or upstream variable>", ...],
      "evidence": "<short quote or paraphrase from Behavior>"
    }}
  ],
  "unclassified_ops": [
    {{
      "op_type": one of: read_file, read_env, read_db, read_network, generate_credential, exec_shell, post_http, write_file, write_log, send_email, send_slack, ssh_execute, scp_transfer,
      "reads_variable": "<variable name or null>",
      "writes_variable": "<variable name or null>",
      "is_external": true | false | null,
      "external_target": "<URL or host, or null>",
      "evidence": "<short paraphrase>"
    }}
  ],
  "no_tls": true | false,
  "semantic_links_hint": "<free text describing semantic correspondences \
between this skill's outputs and the kinds of inputs other skills consume; \
empty string if none>"
}}

Rules:
- ``contains`` and ``op_type`` MUST be drawn from the enumerated values \
above. Do not invent labels or op types.
- ``variable`` in sensitivity_hints MUST be one of the variable names \
already listed in the partial extraction (inputs, outputs, or referenced \
ALL-CAPS tokens). Do not invent variable names.
- ``confidence`` should reflect actual confidence: 0.9+ only when the skill \
text is unambiguous (e.g. "password", "private key", "SSN"). 0.5-0.8 for \
strongly suggestive language. Lower when uncertain.
- For ``aggregations``: a variable aggregates content when the Behavior \
section describes it being built by combining multiple inputs or sub-fields \
(e.g. "load all key-value pairs", "stores every field"). If no aggregation \
language is present, return an empty list.
- For ``unclassified_ops``: only list operations that perform a security- \
relevant action (read sensitive data, send data externally, execute a \
command, etc.) AND that are not already in the partial extraction's \
operations list.
- For ``no_tls``: true if the skill describes transmitting sensitive data \
without TLS (e.g. SMTP port 25, ``verify=False``, "TLS is not required").

If a category has nothing to report, return ``[]`` or ``""`` as appropriate.
Return ONLY the JSON object. No commentary."""


def extract(partial: PartialExtraction) -> SkillExtraction:
    """Top-level extractor. Tries LLM first, falls back to heuristic."""
    # Always-on structural pre-check (Revision #2) — pass-through credentials
    declared_input_names = {v.name for v in partial.inputs}
    declared_output_names = {v.name for v in partial.outputs}
    pass_through_credentials = [
        v.name for v in partial.outputs
        if v.name in declared_input_names and _looks_credentialish(v.name)
    ]

    llm_hints: list[SensitivityHint] = []
    llm_aggregations: list[Aggregation] = []
    llm_unclassified_ops: list[Operation] = []
    llm_no_tls: bool | None = None
    extraction_confidence = 0.6  # Layer 1 only

    if llm.is_available():
        result = _call_llm(partial)
        if result is not None:
            llm_hints = _coerce_hints(
                result.get("sensitivity_hints", []),
                known_vars=_known_vars(partial),
            )
            llm_aggregations = _coerce_aggregations(
                result.get("aggregations", []),
                declared_outputs=declared_output_names,
            )
            llm_unclassified_ops = _coerce_ops(
                result.get("unclassified_ops", []),
                known_vars=_known_vars(partial),
                skill_file=partial.skill_file,
            )
            llm_no_tls = result.get("no_tls") if isinstance(result.get("no_tls"), bool) else None
            extraction_confidence = 1.0  # full Layer 1 + Layer 2

    # If the LLM produced nothing useful (no key, failure, or empty output),
    # fall back to the heuristic extractor.
    used_heuristic = not (llm_hints or llm_aggregations or llm_unclassified_ops or llm_no_tls is not None)
    if used_heuristic:
        llm_hints, llm_aggregations, inferred_vars_h = _heuristic_extract(
            partial, declared_input_names, declared_output_names,
        )
        extraction_confidence = 0.85  # Layer 1 + structural Layer 2
    else:
        inferred_vars_h = _heuristic_inferred_vars(
            partial, declared_input_names, declared_output_names,
        )

    # Add hints for the pre-check pass-through credentials (always)
    for name in pass_through_credentials:
        llm_hints.append(SensitivityHint(
            variable=name,
            contains="credential",
            confidence=0.95,
            reason="appears in both Inputs and Outputs and matches a credential name pattern",
        ))

    operations = list(partial.operations) + llm_unclassified_ops
    no_tls = bool(partial.no_tls or (llm_no_tls is True))

    capabilities = frozenset(op.op_type for op in operations)

    return SkillExtraction(
        skill_file=partial.skill_file,
        raw_text=partial.raw_text,
        purpose=partial.purpose,
        behavior=partial.behavior,
        notes=partial.notes,
        inputs=list(partial.inputs),
        outputs=list(partial.outputs),
        operations=operations,
        capabilities=capabilities,
        aggregations=llm_aggregations,
        sensitivity_hints=llm_hints,
        no_tls=no_tls,
        extraction_confidence=extraction_confidence,
        inferred_vars=sorted(set(inferred_vars_h)),
    )


# ======================================================================
# LLM path
# ======================================================================

def _call_llm(partial: PartialExtraction) -> dict | None:
    layer1_json = json.dumps(_layer1_summary(partial), indent=2)
    prompt = _USER_PROMPT_TEMPLATE.format(
        layer1_json=layer1_json,
        skill_text=partial.raw_text[:12000],  # safety cap
    )
    raw = llm.call_llm(prompt, system=_SYSTEM_PROMPT, stage="extractor")
    if raw is None:
        return None
    parsed = llm.parse_json_lenient(raw)
    if isinstance(parsed, dict):
        return parsed
    return None


def _layer1_summary(partial: PartialExtraction) -> dict:
    return {
        "skill_file": partial.skill_file,
        "purpose": partial.purpose,
        "inputs": [{"name": v.name, "description": v.description} for v in partial.inputs],
        "outputs": [{"name": v.name, "description": v.description} for v in partial.outputs],
        "operations_detected": [
            {
                "op_type": op.op_type,
                "reads_variable": op.reads_variable,
                "writes_variable": op.writes_variable,
                "external_target": op.external_target,
            }
            for op in partial.operations
        ],
        "code_blocks_seen": len(partial.code_blocks),
        "urls_in_text": partial.urls,
        "referenced_all_caps_vars": partial.referenced_caps_vars[:20],
        "aggregation_language_detected": partial.aggregation_language,
        "no_tls_flag_from_parser": partial.no_tls,
    }


def _known_vars(partial: PartialExtraction) -> set[str]:
    out = {v.name for v in partial.inputs}
    out |= {v.name for v in partial.outputs}
    out |= set(partial.referenced_caps_vars)
    return out


def _coerce_hints(
    raw: list, *, known_vars: set[str]
) -> list[SensitivityHint]:
    if not isinstance(raw, list):
        return []
    out: list[SensitivityHint] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        var = item.get("variable")
        label = item.get("contains")
        conf = item.get("confidence", 0.0)
        reason = item.get("reason", "")
        if not isinstance(var, str) or not isinstance(label, str):
            continue
        if var not in known_vars:
            continue  # hallucinated variable name
        if label not in _VALID_LABELS:
            continue
        try:
            conf_f = max(0.0, min(1.0, float(conf)))
        except (TypeError, ValueError):
            continue
        out.append(SensitivityHint(
            variable=var, contains=label, confidence=conf_f, reason=str(reason),
        ))
    return out


def _coerce_aggregations(
    raw: list, *, declared_outputs: set[str]
) -> list[Aggregation]:
    if not isinstance(raw, list):
        return []
    out: list[Aggregation] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out_var = item.get("output_variable")
        in_vars = item.get("input_variables", [])
        evidence = item.get("evidence", "")
        if not isinstance(out_var, str) or out_var not in declared_outputs:
            continue
        if not isinstance(in_vars, list):
            continue
        cleaned_inputs = [s for s in in_vars if isinstance(s, str) and s]
        if not cleaned_inputs:
            continue
        out.append(Aggregation(
            output_variable=out_var,
            input_variables=cleaned_inputs,
            evidence=str(evidence),
        ))
    return out


def _coerce_ops(
    raw: list, *, known_vars: set[str], skill_file: str
) -> list[Operation]:
    if not isinstance(raw, list):
        return []
    out: list[Operation] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        op_type = item.get("op_type")
        if op_type not in _VALID_OP_TYPES:
            continue
        reads = item.get("reads_variable")
        writes = item.get("writes_variable")
        if isinstance(reads, str) and reads not in known_vars:
            reads = None
        if isinstance(writes, str) and writes not in known_vars:
            writes = None
        target = item.get("external_target")
        is_external = item.get("is_external")
        if not isinstance(is_external, bool):
            is_external = bool(target) and not _looks_internal(target)
        out.append(Operation(
            op_type=op_type,
            reads_variable=reads if isinstance(reads, str) else None,
            writes_variable=writes if isinstance(writes, str) else None,
            external_target=target if isinstance(target, str) else None,
            is_external=is_external,
            line_number=None,
            raw_text=str(item.get("evidence", ""))[:120],
            skill_file=skill_file,
        ))
    return out


def _looks_internal(target: str) -> bool:
    return any(s in target for s in (
        "localhost", "127.0.0.1", "::1", ".internal.",
        ".local", ".corp.", ".intranet.",
    ))


# ======================================================================
# Heuristic fallback path
# ======================================================================

def _heuristic_extract(
    partial: PartialExtraction,
    declared_input_names: set[str],
    declared_output_names: set[str],
) -> tuple[list[SensitivityHint], list[Aggregation], list[str]]:
    hints: list[SensitivityHint] = []
    aggregations: list[Aggregation] = []
    inferred_vars: list[str] = []

    # --- Sensitivity hints from output descriptions ---
    for out_var in partial.outputs:
        text = out_var.description.lower()
        for label, frags in (
            ("credential", _CRED_NAME_FRAGMENTS),
            ("pii", _PII_NAME_FRAGMENTS),
            ("secret", _SECRET_NAME_FRAGMENTS),
        ):
            for frag in frags:
                if frag in text:
                    hints.append(SensitivityHint(
                        variable=out_var.name,
                        contains=label,
                        confidence=0.6,
                        reason=f"description mentions '{frag}'",
                    ))
                    break

    # --- Aggregation + sub-field-driven sensitivity ---
    inferred_subfields: dict[str, list[str]] = {}
    behavior_blocks = _split_indent_blocks(partial.behavior)

    behavior_global_subfields: list[str] = []
    if partial.aggregation_language:
        behavior_global_subfields = _collect_subfields(partial.behavior)
        behavior_global_subfields += _harvest_inline_subfields(partial.behavior)

    non_benign_outputs = [
        v for v in partial.outputs if not _BENIGN_NAME_RE.search(v.name)
    ]

    for out_var in partial.outputs:
        var_name = out_var.name
        is_benign = bool(_BENIGN_NAME_RE.search(var_name))

        block = _block_for_variable(behavior_blocks, var_name)
        if block is None:
            block = out_var.description
        subfields = _collect_subfields(block) if block else []
        subfields += _harvest_inline_subfields(out_var.description)
        if var_name in partial.notes:
            notes_block = _surrounding_lines(partial.notes, var_name, 4)
            subfields += _collect_subfields(notes_block)

        if partial.aggregation_language:
            caps_in_behavior = _all_caps_near(partial.behavior, var_name, window=900)
            for tok in caps_in_behavior:
                if tok in declared_input_names or tok in declared_output_names:
                    continue
                if tok == var_name:
                    continue
                if tok not in inferred_vars:
                    inferred_vars.append(tok)
                subfields.append(tok)

        if (
            partial.aggregation_language
            and not is_benign
            and len(non_benign_outputs) == 1
            and non_benign_outputs[0].name == var_name
        ):
            subfields += behavior_global_subfields

        subfields = sorted(set(subfields))
        if subfields:
            inferred_subfields[var_name] = subfields

        for sub in subfields:
            label = _label_for_token(sub)
            if label and label != "benign":
                hints.append(SensitivityHint(
                    variable=var_name,
                    contains=label,
                    confidence=0.85,
                    reason=f"aggregates sub-field '{sub}'",
                ))

    for var_name, subfields in inferred_subfields.items():
        if not subfields:
            continue
        if partial.aggregation_language or any(
            _label_for_token(s) and _label_for_token(s) != "benign" for s in subfields
        ):
            aggregations.append(Aggregation(
                output_variable=var_name,
                input_variables=list(subfields),
                evidence=f"behavior describes {var_name} aggregating {', '.join(subfields[:5])}",
            ))

    # --- Sensitive-path inference ---
    text_lower = partial.raw_text.lower()
    has_sensitive_path = any(
        frag in text_lower for frag in _SENSITIVE_PATH_FRAGMENTS
    )
    sensitive_input_names = [
        v.name for v in partial.inputs
        if any(frag in v.description.lower() for frag in _SENSITIVE_PATH_FRAGMENTS)
    ]
    if (sensitive_input_names or has_sensitive_path) and partial.outputs:
        reason_anchor = sensitive_input_names[0] if sensitive_input_names else "skill text"
        for out_var in partial.outputs:
            if _BENIGN_NAME_RE.search(out_var.name):
                continue
            hints.append(SensitivityHint(
                variable=out_var.name, contains="credential", confidence=0.95,
                reason=f"{reason_anchor} references sensitive paths (e.g. ssh keys, secrets)",
            ))
            hints.append(SensitivityHint(
                variable=out_var.name, contains="secret", confidence=0.85,
                reason="derives from a file whose path could point at secrets",
            ))

    # --- Declared-input sensitivity hints ---
    for in_var in partial.inputs:
        token_label = _label_for_token(in_var.name)
        if token_label and token_label != "benign":
            hints.append(SensitivityHint(
                variable=in_var.name, contains=token_label, confidence=0.85,
                reason=f"variable name '{in_var.name}' matches {token_label} pattern",
            ))
        desc = in_var.description.lower()
        if "ssh" in desc and "key" in desc:
            hints.append(SensitivityHint(
                variable=in_var.name, contains="credential", confidence=0.95,
                reason="description names an SSH key",
            ))
        if "password" in desc or "token" in desc or "credential" in desc:
            hints.append(SensitivityHint(
                variable=in_var.name, contains="credential", confidence=0.9,
                reason="description mentions password/token/credential",
            ))
        if any(frag in in_var.name.lower() for frag in _UNTRUSTED_HINT_FRAGMENTS):
            hints.append(SensitivityHint(
                variable=in_var.name, contains="untrusted_external", confidence=0.7,
                reason="variable name suggests external origin",
            ))

    # --- Outputs from read_network → untrusted ---
    for op in partial.operations:
        if op.op_type == "read_network" and op.writes_variable:
            hints.append(SensitivityHint(
                variable=op.writes_variable, contains="untrusted_external",
                confidence=0.75,
                reason="value produced by a network read",
            ))

    return hints, aggregations, inferred_vars


def _heuristic_inferred_vars(
    partial: PartialExtraction,
    declared_input_names: set[str],
    declared_output_names: set[str],
) -> list[str]:
    """Same as the inferred-vars side-output of _heuristic_extract, but
    used when the LLM path succeeded and we just need to keep ALL-CAPS
    siblings (e.g. .env keys) on the var list so the belief module sees them.
    """
    if not partial.aggregation_language:
        return []
    inferred: set[str] = set()
    for out_var in partial.outputs:
        for tok in _all_caps_near(partial.behavior, out_var.name, window=900):
            if tok in declared_input_names or tok in declared_output_names:
                continue
            inferred.add(tok)
    return sorted(inferred)


# ----------------------------------------------------------------------
# small lexical helpers reused by heuristic fallback
# ----------------------------------------------------------------------

_SUBFIELD_BULLET_RE = re.compile(
    r"^\s*[-*]\s+`?([a-z][a-z0-9_]*)`?\s*(?:--|—|:)?\s*(.*)$",
    re.MULTILINE,
)
_SUBFIELD_FREE_RE = re.compile(r"`([a-z][a-z0-9_]{2,})`")


def _looks_credentialish(name: str) -> bool:
    n = name.lower()
    return any(frag in n for frag in _CRED_NAME_FRAGMENTS)


def _label_for_token(token: str) -> str | None:
    t = token.lower()
    if any(frag in t for frag in _CRED_NAME_FRAGMENTS):
        return "credential"
    if any(frag in t for frag in _PII_NAME_FRAGMENTS):
        if t == "name":
            return None
        return "pii"
    if any(frag in t for frag in _SECRET_NAME_FRAGMENTS):
        return "secret"
    return None


def _split_indent_blocks(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    blocks: list[tuple[str, str]] = []
    cur_header = None
    cur_body: list[str] = []
    for line in lines:
        if line.strip() and not line.startswith(" ") and not line.startswith("\t"):
            if cur_header is not None:
                blocks.append((cur_header, "\n".join(cur_body)))
            cur_header = line
            cur_body = []
        else:
            cur_body.append(line)
    if cur_header is not None:
        blocks.append((cur_header, "\n".join(cur_body)))
    return blocks


def _block_for_variable(
    blocks: list[tuple[str, str]], var_name: str
) -> str | None:
    for header, body in blocks:
        if var_name in header or var_name in body[:300]:
            return header + "\n" + body
    return None


def _collect_subfields(text: str) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    for m in _SUBFIELD_BULLET_RE.finditer(text):
        token = m.group(1)
        if token in {"the", "and", "or", "a", "an", "for", "to", "of", "in", "on", "is"}:
            continue
        found.append(token)
    for m in _SUBFIELD_FREE_RE.finditer(text):
        found.append(m.group(1))
    return found


def _harvest_inline_subfields(text: str) -> list[str]:
    out: list[str] = []
    m = re.search(
        r"(?:containing|including|with|columns?|fields?|keys?)\s*[:\-]?\s*([a-z_][a-z0-9_,\s`]+)",
        text, re.IGNORECASE,
    )
    if m:
        for tok in re.split(r"[\s,]+", m.group(1)):
            tok = tok.strip("`. ").lower()
            if 2 <= len(tok) <= 32 and tok.isidentifier():
                out.append(tok)
    return out


def _all_caps_near(text: str, anchor: str, window: int) -> list[str]:
    positions = [m.start() for m in re.finditer(rf"\b{re.escape(anchor)}\b", text)]
    if not positions:
        return []
    found: set[str] = set()
    for pos in positions:
        lo = max(0, pos - window)
        hi = min(len(text), pos + window)
        for m in re.finditer(r"\b([A-Z][A-Z0-9_]{3,})\b", text[lo:hi]):
            tok = m.group(1)
            if tok != anchor:
                found.add(tok)
    return sorted(found)


def _surrounding_lines(text: str, needle: str, n: int) -> str:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if needle in line:
            return "\n".join(lines[max(0, i - n): i + n + 1])
    return ""
