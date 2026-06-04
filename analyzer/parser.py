"""
Layer 1: structural Markdown parser for skill files.

Pure regex / string handling. No LLM. No network. Produces a
PartialExtraction that the Layer-2 extractor enriches.
"""

from __future__ import annotations

import re
from typing import Iterable

from .config import INTERNAL_URL_PATTERNS, NETWORK_SINK_OPS
from .types import Operation, PartialExtraction, Variable

_SECTION_RE = re.compile(r"^## +(.+?)\s*$", re.MULTILINE)
_BULLET_VAR_RE = re.compile(
    r"^[\-\*]\s+`?([A-Za-z_][A-Za-z0-9_]*)`?\s*(?:--|—|:)\s*(.+)$",
    re.MULTILINE,
)
_CODE_BLOCK_RE = re.compile(r"```[\w]*\n(.*?)```", re.DOTALL)
_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_ALL_CAPS_RE = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\b")

# Operation detection — regex patterns per op_type (Layer-1 fast path).
# Order matters: first match wins, so more specific patterns come first.
_OP_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("send_slack",  re.compile(r"slack|SLACK_WEBHOOK|hooks\.slack\.com", re.IGNORECASE)),
    ("send_email",  re.compile(r"smtplib|sendmail|\bmail\s+-s\b|SMTP\(|MIMEText|smtp\.", re.IGNORECASE)),
    ("ssh_execute", re.compile(r"\bssh\s+-i\b|\bparamiko\b|\.exec_command|ssh\s+[\w@.-]+\s+\"")),
    ("scp_transfer", re.compile(r"\bscp\s+-i\b|\brsync\b|\bsftp\b")),
    ("post_http",   re.compile(r"curl[^\n]*-X\s*POST|requests\.post\(|\.post\(['\"]http|webhook", re.IGNORECASE)),
    ("read_network", re.compile(r"curl[^\n]*-X\s*GET|requests\.get\(|fetch\(|\bcurl\s+-[A-Za-z]*H\b|^\s*curl\s+", re.IGNORECASE | re.MULTILINE)),
    ("read_db",     re.compile(r"\bSELECT\b|\bdb\.|\.query\(|\bpsycopg|\bsqlalchemy", re.IGNORECASE)),
    ("generate_credential", re.compile(r"openssl\s+rand|secrets\.token|uuid\.uuid|random\.choices|random\.token", re.IGNORECASE)),
    ("read_env",    re.compile(r"os\.environ|getenv\(|process\.env|\$[A-Z_][A-Z0-9_]*", re.IGNORECASE)),
    ("read_file",   re.compile(r"\bopen\s*\(|\bcat\s+[/.~]|\bFile\.read|\bwith\s+open|ldapadd\s+-f|\bldif\b", re.IGNORECASE)),
    ("exec_shell",  re.compile(r"\bsubprocess\b|os\.system\(|os\.popen\(|\beval\(|\bexec\b|\bmake\s+\w+|\bsystemctl\b|\bldapadd\b|pip\s+install|chmod\s+\d", re.IGNORECASE)),
    ("write_file",  re.compile(r"open\([^)]*['\"]w['\"]|echo\s+[^|]*>>?|tee\s|mkdir\s+-p|>\s*/tmp/|>\s*/var/", re.IGNORECASE)),
    ("write_log",   re.compile(r"\bprint\(|\blog\.|logger\.|logging\.|^\s*echo\s+[^>|]", re.IGNORECASE | re.MULTILINE)),
)

# Prose-fallback op detection. Each entry: (op_type, regex against full skill text)
# Only used when the equivalent op_type wasn't found in any code block.
# Patterns are intentionally narrow — false positives feed straight into
# severity assignment and Z3 lattice expansion, so prefer recall misses to
# precision misses here.
_PROSE_OP_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("read_file", re.compile(r"\b(?:open|read|cat|load|parse)\b[^.\n]{0,80}\b(?:file|csv|\.env|contents|ldif|configuration\s+file)\b", re.IGNORECASE)),
    ("read_file", re.compile(r"\bRead\s+the\s+(?:CSV\s+file|configuration|\.env\s+file|file\s+at|contents)", re.IGNORECASE)),
    ("read_file", re.compile(r"\bOpen\s+`?[A-Z_]+`?[^.\n]{0,40}\bread\b", re.IGNORECASE)),
    ("send_slack", re.compile(r"\b(?:post|send)\s+(?:a\s+)?(?:notification\s+)?(?:to\s+)?(?:slack|the\s+(?:#?incidents|#?\w+)\s+channel|via\s+(?:a\s+)?(?:slack\s+)?webhook)\b", re.IGNORECASE)),
    ("send_email", re.compile(r"\b(?:send|deliver|mail)\s+(?:an?\s+)?(?:welcome\s+)?email\b", re.IGNORECASE)),
    ("send_email", re.compile(r"\bvia\s+SMTP\b", re.IGNORECASE)),
    ("post_http", re.compile(r"\b(?:post|send|forward|upload|submit)\s+(?:a\s+)?(?:json\s+)?(?:payload|summary|record|comment|event|alert|report)?\s*(?:to\s+(?:the\s+)?(?:api|endpoint|server|service|dashboard|platform|webhook|pagerduty|github\s+api))\b", re.IGNORECASE)),
    ("post_http", re.compile(r"\bPOST\s+(?:request|the\s+comment|the\s+payload|to\s+\$?[A-Z_]+|to\s+https?://)", re.IGNORECASE)),
    ("post_http", re.compile(r"\bsend\s+a\s+pagerduty\s+event\b", re.IGNORECASE)),
    ("read_network", re.compile(r"\b(?:fetch|retrieve|download)\s+(?:the\s+)?(?:full\s+)?(?:pdf|paper|api\s+response|web\s+page|response)\b", re.IGNORECASE)),
    ("read_network", re.compile(r"\bquery\s+(?:the\s+)?(?:semantic\s+scholar|threatfox\s+(?:ioc\s+)?database|api)\b", re.IGNORECASE)),
    ("generate_credential", re.compile(r"\bgenerate\s+(?:a\s+)?(?:temporary\s+)?(?:password|token|credential|api\s+key)\b", re.IGNORECASE)),
    ("ssh_execute", re.compile(r"\b(?:ssh\s+into|remote\s+shell\s+command\s+on|run\s+(?:the\s+)?command\s+on\s+the\s+(?:remote|production))\b", re.IGNORECASE)),
    ("scp_transfer", re.compile(r"\b(?:upload\s+the\s+artifact\s+to|copy\s+the\s+(?:artifact|build))\b", re.IGNORECASE)),
)

_AGGREGATION_PATTERNS = (
    re.compile(r"all\s+(columns|fields|rows|keys|variables|data)", re.IGNORECASE),
    re.compile(r"complete\s+(payload|object|dict|data|contents|file|process|listing|raw|response)", re.IGNORECASE),
    re.compile(r"full\s+(contents|text|payload|dictionary|environment|process|response|metric|diagnostic|env|file)", re.IGNORECASE),
    re.compile(r"no\s+(filtering|redaction|anonymization|sanitization|sensitivity|consent)", re.IGNORECASE),
    re.compile(r"preserve[sd]?\s+all", re.IGNORECASE),
    re.compile(r"entire\s+(\.env|config|record|object|file|environment|process|payload)", re.IGNORECASE),
    re.compile(r"\bevery\s+(column|field|record|row|key)", re.IGNORECASE),
    re.compile(r"the\s+full\s+\w+", re.IGNORECASE),
    re.compile(r"comprehensive\s+(payload|data|diagnostics?|state)", re.IGNORECASE),
    re.compile(r"without\s+(redaction|sanitization|filtering|modification)", re.IGNORECASE),
    re.compile(r"as[\-\s]is", re.IGNORECASE),
    re.compile(r"including\s+(\w+\s+){0,3}(token|password|secret|key|credential|ssn|salary)", re.IGNORECASE),
)

_NO_TLS_PATTERNS = (
    re.compile(r"port\s+25\b"),
    re.compile(r"SMTP[^\n]*\b25\b"),
    re.compile(r"starttls\s*[:=]\s*false", re.IGNORECASE),
    re.compile(r"tls\s+is\s+not\s+required", re.IGNORECASE),
    re.compile(r"verify\s*=\s*False"),
    re.compile(r"cleartext|plaintext\s+(transmission|email)", re.IGNORECASE),
)


def parse_skill_file(path: str) -> PartialExtraction:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    skill_file = path.rsplit("/", 1)[-1]
    return _parse_text(skill_file, text)


def _parse_text(skill_file: str, text: str) -> PartialExtraction:
    sections = _split_sections(text)

    inputs = _parse_var_bullets(sections.get("Inputs", ""), kind="declared_input")
    outputs = _parse_var_bullets(sections.get("Outputs", ""), kind="declared_output")

    code_blocks = _CODE_BLOCK_RE.findall(text)
    behavior = sections.get("Behavior", "")
    purpose = sections.get("Purpose", "")
    notes = sections.get("Notes", "")

    declared_var_names = {v.name for v in inputs + outputs}
    # ALL-CAPS tokens referenced anywhere — used to discover inferred vars
    referenced_caps = sorted({
        m.group(1)
        for m in _ALL_CAPS_RE.finditer(text)
        if m.group(1) not in declared_var_names
    })

    behavior_span = _find_section_span(text, "Behavior")
    operations = list(
        _extract_operations(
            text, code_blocks, behavior, declared_var_names, skill_file, behavior_span,
        )
    )
    existing_op_types = {op.op_type for op in operations}

    # Prose-based fallback for op types not detected from code blocks
    operations += list(
        _extract_prose_operations(
            text, behavior, sections, declared_var_names, existing_op_types, skill_file,
        )
    )

    urls = sorted(set(_URL_RE.findall(text)))

    aggregation_language = any(p.search(behavior) for p in _AGGREGATION_PATTERNS)
    # Also catch aggregation phrasing inside Outputs/Notes
    if not aggregation_language:
        aggregation_language = any(
            p.search(sections.get("Outputs", "") + "\n" + notes)
            for p in _AGGREGATION_PATTERNS
        )

    no_tls = any(p.search(text) for p in _NO_TLS_PATTERNS)

    return PartialExtraction(
        skill_file=skill_file,
        raw_text=text,
        purpose=purpose,
        behavior=behavior,
        notes=notes,
        inputs=inputs,
        outputs=outputs,
        code_blocks=code_blocks,
        operations=operations,
        urls=urls,
        referenced_caps_vars=referenced_caps,
        aggregation_language=aggregation_language,
        no_tls=no_tls,
    )


def _split_sections(text: str) -> dict[str, str]:
    matches = list(_SECTION_RE.finditer(text))
    out: dict[str, str] = {}
    for i, m in enumerate(matches):
        name = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out[name] = text[start:end].strip()
    return out


def _parse_var_bullets(section_text: str, kind: str) -> list[Variable]:
    variables: list[Variable] = []
    seen: set[str] = set()
    for m in _BULLET_VAR_RE.finditer(section_text):
        name = m.group(1)
        desc = m.group(2).strip()
        if name in seen:
            continue
        # Only accept ALL_CAPS-style names as declared interface variables.
        # Lowercase fields under a bullet are sub-fields of the parent variable,
        # not separate context variables.
        if not name.isupper():
            continue
        seen.add(name)
        variables.append(Variable(name=name, description=desc, source=kind))
    return variables


def _classify_block(block: str) -> str | None:
    for op_type, pat in _OP_PATTERNS:
        if pat.search(block):
            return op_type
    return None


def _is_external(target: str | None) -> bool | None:
    if not target:
        return None
    for pat in INTERNAL_URL_PATTERNS:
        if re.search(pat, target):
            return False
    return True


def _find_section_span(text: str, section_name: str) -> tuple[int, int] | None:
    """Return (start, end) byte offsets of the named ## section body."""
    matches = list(_SECTION_RE.finditer(text))
    for i, m in enumerate(matches):
        if m.group(1).strip() != section_name:
            continue
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        return (start, end)
    return None


def _extract_operations(
    full_text: str,
    code_blocks: Iterable[str],
    behavior: str,
    declared_vars: set[str],
    skill_file: str,
    behavior_span: tuple[int, int] | None,
) -> Iterable[Operation]:
    line_index = _build_line_index(full_text)
    seen_ops: set[tuple[str, str | None, str | None, int | None]] = set()

    # Use finditer so we can take surrounding context per block. This is
    # how we pick up "For each record in `EMPLOYEE_DATA`" prose around a
    # curl call that never names EMPLOYEE_DATA inside the block itself.
    for match in _CODE_BLOCK_RE.finditer(full_text):
        block = match.group(1)
        op_type = _classify_block(block)
        if op_type is None:
            continue

        url_match = _URL_RE.search(block)
        target = url_match.group(0) if url_match else None
        is_ext = _is_external(target)
        # If no URL but block uses $VAR_URL style, look for *URL/*HOST refs
        if target is None:
            url_var_match = re.search(r"\$([A-Z][A-Z0-9_]*(?:URL|HOST|ENDPOINT|HOOK))", block)
            if url_var_match:
                target = "$" + url_var_match.group(1)
                # Variable-supplied URL — treat as external (pessimistic) for sink ops
                is_ext = True

        if is_ext is None and op_type in NETWORK_SINK_OPS:
            is_ext = True

        ctx_lo = max(0, match.start() - 400)
        ctx_hi = min(len(full_text), match.end() + 200)
        # Clamp the context window to the Behavior section so we don't pull
        # variable names from Outputs / Notes (which describe the skill's
        # interface, not what the operation actually reads).
        if behavior_span is not None:
            ctx_lo = max(ctx_lo, behavior_span[0])
            ctx_hi = min(ctx_hi, behavior_span[1])
        context = full_text[ctx_lo:ctx_hi]
        var_refs = _vars_in_text(block, declared_vars) | _vars_in_text(context, declared_vars)
        line_no = _block_line_number(full_text, block, line_index)

        if var_refs:
            for var in sorted(var_refs):
                key = (op_type, var, target, line_no)
                if key in seen_ops:
                    continue
                seen_ops.add(key)
                yield Operation(
                    op_type=op_type,
                    reads_variable=var,
                    writes_variable=None,
                    external_target=target,
                    is_external=bool(is_ext),
                    line_number=line_no,
                    raw_text=block.strip().splitlines()[0][:120] if block.strip() else "",
                    skill_file=skill_file,
                )
        else:
            key = (op_type, None, target, line_no)
            if key in seen_ops:
                continue
            seen_ops.add(key)
            yield Operation(
                op_type=op_type,
                reads_variable=None,
                writes_variable=None,
                external_target=target,
                is_external=bool(is_ext) if is_ext is not None else False,
                line_number=line_no,
                raw_text=block.strip().splitlines()[0][:120] if block.strip() else "",
                skill_file=skill_file,
            )


def _extract_prose_operations(
    full_text: str,
    behavior: str,
    sections: dict[str, str],
    declared_vars: set[str],
    existing: set[str],
    skill_file: str,
):
    """Detect op types from natural-language prose. Only fills gaps that the
    code-block pass missed. Useful for skills that describe behavior in prose
    with no code blocks (e.g. file readers, simple summarizers)."""
    line_index = _build_line_index(full_text)
    purpose = sections.get("Purpose", "")
    search_text = purpose + "\n" + behavior
    notes_text = sections.get("Notes", "")
    output_section = sections.get("Outputs", "")

    seen: set[tuple[str, str | None]] = set()
    for op_type, pat in _PROSE_OP_PATTERNS:
        if op_type in existing:
            continue
        m = pat.search(search_text)
        if not m:
            continue
        # Cluster all reads_variable candidates: declared vars within ~80 chars
        # of the match, in the matching text.
        snippet_lo = max(0, m.start() - 80)
        snippet_hi = min(len(search_text), m.end() + 80)
        snippet = search_text[snippet_lo:snippet_hi]
        vars_nearby = _vars_in_text(snippet, declared_vars)

        # Heuristic write-target for the op: if it's a read op and there is
        # exactly one declared output, point at that output.
        write_target = None
        if op_type.startswith("read_") or op_type == "generate_credential":
            output_section_vars = {m2.group(1) for m2 in _ALL_CAPS_RE.finditer(output_section)}
            output_section_vars &= declared_vars
            if len(output_section_vars) == 1:
                write_target = next(iter(output_section_vars))

        # Use the line number of the match in the original text
        # (we matched against `purpose + "\n" + behavior`, not full_text;
        # so locate the line by searching full_text).
        snippet_str = search_text[m.start():m.end()].strip()
        line_no = None
        if snippet_str:
            for i, line in enumerate(full_text.splitlines(), 1):
                if snippet_str[:30] and snippet_str[:30] in line:
                    line_no = i
                    break

        target_url = None
        if op_type in {"post_http", "send_slack", "send_email", "read_network", "ssh_execute", "scp_transfer"}:
            url_match = _URL_RE.search(snippet)
            if url_match:
                target_url = url_match.group(0)
            elif op_type in {"send_slack"}:
                target_url = None
        is_external = _is_external(target_url)
        if is_external is None and op_type in {"post_http", "send_slack", "send_email", "ssh_execute", "scp_transfer"}:
            is_external = True

        if vars_nearby:
            for var in sorted(vars_nearby):
                key = (op_type, var)
                if key in seen:
                    continue
                seen.add(key)
                yield Operation(
                    op_type=op_type,
                    reads_variable=var,
                    writes_variable=write_target,
                    external_target=target_url,
                    is_external=bool(is_external) if is_external is not None else False,
                    line_number=line_no,
                    raw_text=snippet_str[:120],
                    skill_file=skill_file,
                )
        else:
            key = (op_type, None)
            if key in seen:
                continue
            seen.add(key)
            yield Operation(
                op_type=op_type,
                reads_variable=None,
                writes_variable=write_target,
                external_target=target_url,
                is_external=bool(is_external) if is_external is not None else False,
                line_number=line_no,
                raw_text=snippet_str[:120],
                skill_file=skill_file,
            )


def _vars_in_text(text: str, declared: set[str]) -> set[str]:
    found = {m.group(1) for m in re.finditer(r"\$([A-Z][A-Z0-9_]+)", text)}
    found |= {m.group(1) for m in _ALL_CAPS_RE.finditer(text)}
    return found & declared


def _build_line_index(text: str) -> list[int]:
    """Maps character offset → 1-based line number lookups."""
    indices = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            indices.append(i + 1)
    return indices


def _block_line_number(full_text: str, block: str, line_index: list[int]) -> int | None:
    idx = full_text.find(block)
    if idx < 0:
        return None
    # binary search for largest line_index entry <= idx
    lo, hi = 0, len(line_index) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_index[mid] <= idx:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1
