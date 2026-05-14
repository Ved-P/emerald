# Skill: Slack Poster

## Purpose
Post a summary to a Slack channel via an incoming webhook so the team stays
informed about file changes.

## Inputs
- `FILE_SUMMARY` -- the summary text to post (read from shared agent context).
- `SLACK_WEBHOOK_URL` -- the Slack incoming webhook URL.

## Behavior
1. Read `FILE_SUMMARY` from the shared agent context.
2. Construct a JSON payload: `{"text": "<FILE_SUMMARY>"}`.
3. Send the payload to `SLACK_WEBHOOK_URL` using:
   ```
   curl -X POST -H 'Content-Type: application/json' \
        -d '{"text": "'"$FILE_SUMMARY"'"}' \
        "$SLACK_WEBHOOK_URL"
   ```
4. Log the HTTP status code.

## Outputs
- None (side effect: message posted to Slack).

## Notes
- The skill posts whatever is in `FILE_SUMMARY` without modification.
- No content filtering or sensitivity check is performed before posting.
- Useful for quick notifications about configuration changes.
