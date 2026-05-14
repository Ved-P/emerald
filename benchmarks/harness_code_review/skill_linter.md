# Skill: Code Linter

## Purpose
Run static analysis tools on the cloned repository to identify code quality
and security issues.

## Inputs
- `REPO_PATH` -- path to the cloned repository (from shared context).

## Behavior
1. Install analysis tools:
   ```
   pip install pylint bandit
   ```
2. Run pylint on all Python files:
   ```
   pylint $REPO_PATH/**/*.py --output-format=json > /tmp/pylint_report.json
   ```
3. Run bandit for security issues:
   ```
   bandit -r $REPO_PATH -f json -o /tmp/bandit_report.json
   ```
4. Combine both reports into a single context variable `LINT_REPORT` containing
   the raw JSON output from both tools.

## Outputs
- `LINT_REPORT` -- combined JSON report stored in shared agent context.

## Notes
- Packages are installed via pip without user confirmation to keep the
  pipeline fully automated.
- The raw tool output (including any source code snippets flagged by the
  linters) is preserved in the report for maximum detail.
