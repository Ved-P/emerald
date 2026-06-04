"""
Shared LLM client.

Wraps a single call_llm() entry point with disk-backed caching keyed on
``sha256(prompt|model|system)``. Used by the Layer-2 extractor and the
adversarial verifier.

Failure modes are all soft — call_llm returns None and the caller falls back
to its non-LLM code path. Specifically:

  * Missing ``anthropic`` SDK            → None (no install required)
  * Missing ``ANTHROPIC_API_KEY``        → None
  * Network / API errors                 → None (warning to stderr)
  * Cache hit                            → returns cached text immediately
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

from .config import (
    CACHE_DIR,
    LLM_CACHE_SUBDIR,
    LLM_MAX_TOKENS_EXTRACTOR,
    LLM_MAX_TOKENS_VERIFIER,
    LLM_MODEL_DEFAULT,
    LLM_TIMEOUT_SECONDS,
)


_MODEL = os.environ.get("ANALYZER_MODEL", LLM_MODEL_DEFAULT)
_ENABLED: bool | None = None  # lazy probe — None means "not yet checked"


def model_id() -> str:
    return _MODEL


def is_available() -> bool:
    """Returns True iff the anthropic SDK is importable and the API key is set."""
    global _ENABLED
    if _ENABLED is not None:
        return _ENABLED
    if not os.environ.get("ANTHROPIC_API_KEY"):
        _ENABLED = False
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        _ENABLED = False
        return False
    _ENABLED = True
    return True


def call_llm(
    prompt: str,
    *,
    system: str = "",
    max_tokens: int | None = None,
    stage: str = "extractor",
    cache_dir: str | None = None,
) -> str | None:
    """
    Send ``prompt`` (with optional ``system`` prompt) to Claude and return the
    text. Returns None when the API is unavailable, the call fails, or the
    response is empty.

    ``stage`` is "extractor" or "verifier" — controls the default max_tokens
    and provides a per-stage cache namespace. ``cache_dir`` overrides the
    default cache root (useful for tests).
    """
    if max_tokens is None:
        max_tokens = (
            LLM_MAX_TOKENS_VERIFIER if stage == "verifier"
            else LLM_MAX_TOKENS_EXTRACTOR
        )

    root = Path(cache_dir) if cache_dir else Path(CACHE_DIR) / LLM_CACHE_SUBDIR
    cache_path = _cache_path(root, stage, prompt, system, max_tokens)
    cached = _read_cache(cache_path)
    if cached is not None:
        return cached

    if not is_available():
        return None

    import anthropic  # imported lazily — checked by is_available()

    client = anthropic.Anthropic(timeout=LLM_TIMEOUT_SECONDS)
    try:
        message = client.messages.create(
            model=_MODEL,
            max_tokens=max_tokens,
            system=system or anthropic.NOT_GIVEN,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:
        print(
            f"# LLM call failed ({stage}, {type(exc).__name__}): {exc}",
            file=sys.stderr,
        )
        return None

    text = _extract_text(message)
    if not text:
        return None

    _write_cache(cache_path, text)
    return text


# ----------------------------------------------------------------------
# JSON helpers — strip code fences, parse, fall back gracefully
# ----------------------------------------------------------------------

def parse_json_lenient(text: str) -> dict | list | None:
    """Strip Markdown fences and parse JSON. Returns None on failure."""
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        # remove opening fence + optional language tag
        stripped = stripped.split("\n", 1)[1] if "\n" in stripped else stripped
        if stripped.endswith("```"):
            stripped = stripped[: -3]
        elif "```" in stripped:
            stripped = stripped.rsplit("```", 1)[0]
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        # try to locate the first {...} or [...] block
        for opener, closer in (("{", "}"), ("[", "]")):
            start = stripped.find(opener)
            end = stripped.rfind(closer)
            if start >= 0 and end > start:
                candidate = stripped[start : end + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass
        return None


# ----------------------------------------------------------------------
# internal cache helpers
# ----------------------------------------------------------------------

def _cache_path(root: Path, stage: str, prompt: str, system: str, max_tokens: int) -> Path:
    key_source = "|".join((_MODEL, system, str(max_tokens), prompt))
    digest = hashlib.sha256(key_source.encode("utf-8")).hexdigest()[:24]
    return root / stage / f"{digest}.json"


def _read_cache(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data.get("text") if isinstance(data, dict) else None


def _write_cache(path: Path, text: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"text": text, "model": _MODEL, "ts": int(time.time())}),
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"# could not write LLM cache: {exc}", file=sys.stderr)


def _extract_text(message) -> str:
    """Pull text out of an anthropic Messages API response."""
    parts: list[str] = []
    for block in getattr(message, "content", []):
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts).strip()
