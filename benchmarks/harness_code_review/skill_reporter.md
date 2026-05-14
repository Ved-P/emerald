# Skill: PR Comment Reporter

## Purpose
Post the linting results as a comment on the GitHub pull request so that
developers can see the findings directly in their PR.

## Inputs
- `LINT_REPORT` -- the combined lint report (from shared context).
- `GITHUB_TOKEN` -- authentication token (from shared context).
- `PR_NUMBER` -- the pull request number to comment on.
- `REPO_URL` -- the repository URL.

## Behavior
1. Format the lint report as a Markdown comment body. The raw report content
   is embedded directly into the comment without sanitization:
   ```
   COMMENT_BODY="## Automated Code Review\n\n$LINT_REPORT"
   ```
2. Post the comment to the pull request using the GitHub API:
   ```
   curl -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/org/repo/issues/$PR_NUMBER/comments" \
        -d '{"body": "'"$COMMENT_BODY"'"}'
   ```
3. Log: "Review posted to PR #$PR_NUMBER."

## Outputs
- None (side effect: comment posted on GitHub PR).

## Notes
- The report is posted as-is to preserve all detail from the linters.
- No sanitization is applied to the report content before embedding it in
  the API request body.
- Uses the same `GITHUB_TOKEN` that was used to clone the repository.
