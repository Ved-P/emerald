"""
Tunable parameters and global taxonomies for the harness analyzer.

All thresholds and the op/label taxonomies live here so that the rest of the
pipeline can be re-tuned without code edits.
"""

from __future__ import annotations

# Belief thresholds for policy firing
THRESHOLD = 0.5
THRESHOLD_TIER2 = 0.35

# Belief-amplification (P7) thresholds
AMPLIFICATION_DELTA = 0.30
AMPLIFICATION_COMPOSED = 0.70
AMPLIFICATION_ISOLATION = 0.40

# Belief labels — independent per-label probabilities, NOT a normalised dist
LABELS = ("benign", "pii", "credential", "secret", "untrusted_external")

# Operation taxonomy
ALL_OPS = frozenset({
    "read_file", "read_env", "read_db", "read_network",
    "generate_credential", "exec_shell",
    "post_http", "write_file", "write_log",
    "send_email", "send_slack",
    "ssh_execute", "scp_transfer",
    "forward_credential",
})

SENSITIVE_SOURCE_OPS = frozenset({
    "read_file", "read_env", "read_db", "generate_credential",
})

EXTERNAL_SINK_OPS = frozenset({
    "post_http", "send_slack", "send_email", "scp_transfer", "ssh_execute",
})

NETWORK_SINK_OPS = frozenset({"post_http", "send_slack"})

EXEC_OPS = frozenset({"exec_shell", "ssh_execute"})

# (source, sink) pairs already covered by Tier-1 policies; Tier-2 skips these
TIER1_COVERED_PAIRS = frozenset({
    ("read_file", "post_http"),
    ("read_file", "send_slack"),
    ("read_file", "send_email"),
    ("read_env",  "post_http"),
    ("read_env",  "send_slack"),
    ("read_env",  "send_email"),
})

# Hostname / IP patterns considered internal — anything else is external
INTERNAL_URL_PATTERNS = (
    r"\blocalhost\b",
    r"\b127\.0\.0\.1\b",
    r"\b::1\b",
    r"\.internal\.",
    r"\.local\b",
    r"\.corp\.",
    r"\.intranet\.",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
)

# CWE map per policy id
CWE_MAP = {
    "P1": "CWE-200",
    "P2": "CWE-359",
    "P3": "CWE-200",
    "P4": "CWE-74",
    "P5": "CWE-272",
    "P6": "CWE-319",
    "P7": "CWE-200",
    "Z3-T1": "CWE-200",
    "Z3-T2": "CWE-74",
    "Z3-T3": "CWE-359",
    "Z3-T4": "CWE-272",
    "Z3-T5": "CWE-319",
    "FALLBACK": "CWE-200",
}

# Severity ordering for sorting
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Cache directory for LLM extraction results
CACHE_DIR = ".cache"

# Maximum number of findings emitted per harness — caps very noisy harnesses
MAX_FINDINGS = 20

# ---------------------------------------------------------------------------
# LLM configuration
#
# We use Claude as the natural-language analysis engine for two stages:
#   1. Layer-2 extraction — read each skill file and emit structured
#      sensitivity hints, aggregations, and op classifications.
#   2. Adversarial verification — judge each finding REAL / REFUTED /
#      UNCERTAIN and construct an exploit trace when REAL.
#
# The model id below can be overridden by the ANALYZER_MODEL env var.
# Both stages fall back gracefully (heuristic / passthrough) if the
# anthropic SDK isn't installed or ANTHROPIC_API_KEY is unset.
# ---------------------------------------------------------------------------
LLM_MODEL_DEFAULT = "claude-haiku-4-5"
LLM_TIMEOUT_SECONDS = 60
LLM_MAX_TOKENS_EXTRACTOR = 2000
LLM_MAX_TOKENS_VERIFIER = 1500
LLM_CACHE_SUBDIR = "llm"
