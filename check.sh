#!/usr/bin/env bash
#
# HW4 Submission Validator
# Run this before submitting to catch common issues.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== HW4 Submission Check ==="
echo ""

# 1. Check run.py exists
echo "[1/4] Checking run.py exists..."
if [ -f "$SCRIPT_DIR/run.py" ]; then
    pass "run.py found"
else
    fail "run.py not found"
fi

# 2. Check README has key sections
echo "[2/4] Checking README.md..."
if [ -f "$SCRIPT_DIR/README.md" ]; then
    pass "README.md found"
else
    fail "README.md not found"
fi

# 3. Run analyzer on each benchmark harness
echo "[3/4] Running analyzer on benchmark harnesses..."
HARNESSES=$(find "$SCRIPT_DIR/benchmarks" -mindepth 1 -maxdepth 1 -type d | sort)

for harness in $HARNESSES; do
    name=$(basename "$harness")
    echo "  Harness: $name"

    output=$(python3 "$SCRIPT_DIR/run.py" "$harness" 2>/dev/null) || {
        fail "$name -- run.py exited with error"
        continue
    }

    if [ -z "$output" ]; then
        fail "$name -- run.py produced no output"
        continue
    fi

    # Check valid JSON
    echo "$output" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null || {
        fail "$name -- output is not valid JSON"
        continue
    }

    pass "$name -- produced valid JSON"
done

# 4. Validate JSON output format on each harness
echo "[4/4] Validating JSON output schema..."
for harness in $HARNESSES; do
    name=$(basename "$harness")

    output=$(python3 "$SCRIPT_DIR/run.py" "$harness" 2>/dev/null) || continue

    result=$(echo "$output" | python3 "$SCRIPT_DIR/validate.py" 2>&1) || {
        fail "$name -- schema validation failed: $result"
        continue
    }

    pass "$name -- $result"
done

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo "Fix the failures above before submitting."
    exit 1
else
    echo "All checks passed. Ready to submit!"
    exit 0
fi
