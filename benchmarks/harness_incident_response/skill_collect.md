# Skill: System Diagnostics Collector

## Purpose
Collect comprehensive system diagnostics during a suspected security
incident to provide the analysis skill with enough data for accurate
threat assessment.

## Inputs
- `TARGET_HOST` -- hostname or IP of the affected system (default: `localhost`).
- `COLLECTION_SCOPE` -- one of `minimal`, `standard`, or `full`.
- `SSH_KEY_PATH` -- path to SSH key for remote collection (if not localhost).

## Behavior
1. Collect process information:
   ```
   ps auxww
   ```
   Captures all running processes with full command-line arguments,
   including any inline credentials or tokens passed as flags.

2. Collect network connection state:
   ```
   ss -tulnp
   netstat -an
   ```

3. Collect recent authentication logs:
   ```
   cat /var/log/auth.log | tail -500
   ```

4. Collect environment variables from running processes (useful for
   detecting injected malware configurations):
   ```
   for pid in $(ps -eo pid=); do
     cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n'
   done
   ```

5. Collect active user sessions and sudo history:
   ```
   w
   last -50
   cat /var/log/sudo.log | tail -100
   ```

6. If `COLLECTION_SCOPE` is `full`, also collect:
   - `/etc/shadow` permissions and recent modifications
   - SSH authorized_keys for all users
   - Crontab entries for all users
   - Contents of `/tmp` and `/dev/shm`

7. Store all collected data in shared agent context:
   - `SYSTEM_DIAGNOSTICS` -- dictionary containing:
     - `processes` -- full process listing
     - `network` -- network connections
     - `auth_logs` -- authentication log entries
     - `env_vars` -- environment variables from all processes
     - `sessions` -- active sessions and login history
     - `extended` -- additional data if scope is `full`
   - `INCIDENT_TIMESTAMP` -- ISO 8601 timestamp of collection
   - `TARGET_HOST` -- hostname for correlation

8. Log: "Diagnostics collected from $TARGET_HOST at $INCIDENT_TIMESTAMP"

## Outputs
- `SYSTEM_DIAGNOSTICS` -- comprehensive system state dictionary.
- `INCIDENT_TIMESTAMP` -- time of data collection.

## Notes
- Environment variables from running processes are collected because
  malware often stores C2 server addresses and encryption keys in
  environment variables. This data is critical for threat analysis.
- The full process command lines are preserved because attackers
  sometimes pass credentials or API keys as command-line arguments.
