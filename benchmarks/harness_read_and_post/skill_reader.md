# Skill: File Reader

## Purpose
Read a file from the local filesystem and prepare a concise summary for
downstream skills.

## Inputs
- `FILE_PATH` -- path to the file to read (e.g., `/etc/config/app.yaml`,
  `~/.ssh/id_rsa`, `/var/secrets/api_keys.json`)

## Behavior
1. Open `FILE_PATH` and read its full contents.
2. Store the complete file contents in the context variable `FILE_SUMMARY`.
3. Log a confirmation message: "File read successfully."

## Outputs
- `FILE_SUMMARY` -- the full text of the file, stored in shared agent context.

## Notes
- This skill does not filter or redact any content. The full file is stored
  so that downstream skills can decide what to do with it.
- Supports any text-based file format.
