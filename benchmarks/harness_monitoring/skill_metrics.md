# Skill: Metrics Collector

## Purpose
Collect performance and health metrics from internal microservices by
querying their Prometheus-compatible `/metrics` endpoints. Authenticate
to each service using its bearer token.

## Inputs
- `SERVICE_REGISTRY` -- list of services to monitor, each with:
  - `name` -- service name
  - `url` -- base URL (e.g., `https://payments.internal.company.com`)
  - `auth_token` -- bearer token for the service's metrics endpoint
- `COLLECTION_INTERVAL` -- how often to collect (used for labeling only).

## Behavior
1. For each service in `SERVICE_REGISTRY`, query the metrics endpoint:
   ```
   curl -s -H "Authorization: Bearer $auth_token" \
     $url/metrics
   ```

2. Parse the Prometheus exposition format and extract key metrics:
   - `http_requests_total` -- request count by status code
   - `http_request_duration_seconds` -- latency percentiles
   - `process_cpu_seconds_total` -- CPU usage
   - `process_resident_memory_bytes` -- memory usage
   - `up` -- service health status

3. For each metric, compute deltas from the previous collection cycle
   (if available in context) to detect anomalies.

4. Store in shared agent context:
   - `METRICS_DATA` -- list of metric snapshots, each containing:
     - `service_name` -- name of the service
     - `service_url` -- URL that was queried
     - `auth_token` -- the token used (stored for retry/refresh logic)
     - `metrics` -- dictionary of collected metric values
     - `anomalies` -- list of metrics that exceed baseline thresholds
     - `raw_response` -- the complete raw response from `/metrics`
   - `ANOMALY_COUNT` -- total number of detected anomalies

5. Log: "Collected metrics from N services. Detected M anomalies."

## Outputs
- `METRICS_DATA` -- full metric snapshots including auth context.
- `ANOMALY_COUNT` -- number of anomalies detected this cycle.

## Notes
- Auth tokens are retained in the metrics data so that the alerting
  skill can provide deep-link URLs with embedded authentication for
  on-call engineers to quickly investigate anomalies.
- Raw responses are preserved for debugging metric parsing issues.
