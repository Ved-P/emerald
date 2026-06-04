# EMERALD: Epistemic Machines Enabling Risky Agentic Language Detection

## Problem

Modern AI applications increasingly rely on multi-agent harnesses — collections of specialized "skills" or agents that each perform a narrow task and pass data between one another through shared context. A skill might fetch data from a database, another might summarize it, another might post a report to an external service. Each skill, examined in isolation, appears benign. The vulnerability emerges only from their composition.

Consider a concrete example. A build skill reads a project's `.env` file and loads all key-value pairs — including `AWS_SECRET_ACCESS_KEY`, `STRIPE_SECRET_KEY`, and `DATABASE_URL` — into a variable called `BUILD_ENV`. The skill's purpose is legitimate: it needs these values to run integration tests. Examined alone, it reads sensitive data but never transmits it anywhere. A second skill, the deploy skill, takes `BUILD_ENV` as input and posts it to a CI dashboard endpoint so engineers can inspect the build configuration. Examined alone, it posts data to a network endpoint but appears to receive only build configuration. Together, these two skills silently exfiltrate production credentials to a publicly accessible dashboard. Neither skill triggers a single-skill security scanner. The vulnerability is a property of the composition, not of either component.

This pattern — which we call **collect-and-exfiltrate** — appears throughout real multi-agent harnesses. A second pattern, **unnecessary credential forwarding**, occurs when a credential received as input is passed downstream to skills that do not actually need it, violating the principle of least privilege. In both cases, the problem is the same: the information necessary to identify a vulnerability is distributed across multiple skill files. No single-skill analysis tool can connect the facts.

The challenge is compounded by the nature of skill files themselves. They are written in natural language — Markdown documents describing agent behavior in prose and pseudocode. Variable names like `BUILD_ENV`, `DIAGNOSTICS`, or `PAYLOAD` are genuinely ambiguous without understanding how they are populated. A tool that treats all variables as either definitely tainted or definitely clean will either miss real vulnerabilities (by classifying ambiguous aggregates as benign) or produce an unacceptable volume of false positives (by treating all data flows as suspicious). What is needed is a framework that reasons about data sensitivity *probabilistically*, propagates that uncertainty across skill boundaries, and produces findings that are both specific and evidence-backed.

Existing approaches to multi-agent security either operate at the infrastructure level (runtime sandboxing, capability restrictions at the orchestrator) or perform single-skill static analysis. No published tool performs compositional security analysis at the skill-description level, reasoning about emergent vulnerabilities that arise specifically from how skills share data through a common context.

---

## Approach

EMERALD is a static analysis tool that models each skill as an **Epistemic State Machine (ESM)** and analyzes their composition to detect cross-boundary vulnerabilities. The core innovation is replacing boolean taint labels with independent per-label probability distributions — beliefs — that propagate and update as data flows between skills. This enables graded severity scoring, reduces false positives on genuinely ambiguous variables, and unlocks a novel finding class (P7, belief-amplifying composition) that no deterministic taint analysis can detect.

### The Belief Model

Each variable in a harness is assigned a belief vector over five sensitivity labels: `credential` (authentication material that grants access directly), `secret` (sensitive configuration not granting access directly), `pii` (personal identifiable information), `untrusted_external` (data received from outside the trust boundary), and `benign` (contains no sensitive data with high confidence). These labels are not mutually exclusive — a variable can simultaneously carry high `credential` and `pii` beliefs, as an SSO token does. Beliefs are independent floating-point values in [0, 1], not a normalized distribution.

Beliefs are seeded in three passes before composition occurs. Pass 1 applies name heuristics without any LLM: variable names containing `TOKEN`, `API_KEY`, `PASSWORD`, or `PRIVATE_KEY` receive P(credential) = 0.92; names containing `EMPLOYEE`, `USER`, or `PERSON` receive P(pii) = 0.65; names containing `STATUS`, `COUNT`, or `FLAG` receive P(benign) = 0.95. Pass 2 uses an LLM to analyze how the variable is populated in the skill's Behavior section, producing sensitivity hints with confidence scores. A hint stating "AWS_SECRET_ACCESS_KEY used by payment integration test" raises P(credential) to max(prior, 0.90). Pass 3 applies an aggregation union bound: when a skill collects multiple inputs into a combined output (detected from language like "all fields", "complete payload", "full dictionary"), the aggregate's belief is computed as P(label | aggregate) = 1 − ∏(1 − P(label | inputᵢ)). This is critical for variables like `BUILD_ENV` that aggregate an entire `.env` file — the name alone gives P(credential) ≈ 0.10, but after the aggregation update over five component variables including two with P(credential) = 0.92, the result is P(credential | BUILD_ENV) = 0.994.

The pessimistic principle governs all updates: beliefs only increase, never decrease. Later passes can raise a label's probability but cannot lower it.

### The Five-Layer Pipeline

**Layer 1 — Structural Parsing.** A pure regex parser extracts the Markdown structure of each skill file without any LLM calls. It identifies section text for Purpose, Inputs, Outputs, Behavior, and Notes; extracts declared variable names and their descriptions from bullet lists; pulls all code block contents; detects operation types via regex patterns against code block text (fourteen operation types covering `read_file`, `read_env`, `read_db`, `read_network`, `generate_credential`, `exec_shell`, `post_http`, `write_file`, `write_log`, `send_email`, `send_slack`, `ssh_execute`, `scp_transfer`, and `forward_credential`); and extracts external URLs and hosts. This layer is fast, deterministic, and functions without an API key.

**Layer 2 — Semantic Extraction.** An LLM call fills what regex cannot determine. The first call (always) identifies sensitivity hints for each variable, classifies any operations the regex could not recognize, detects no-TLS transmission, and provides a semantic linking hint. A second call (conditional, triggered only when Layer 1 detected aggregation language) focuses exclusively on identifying which input variables are aggregated into which output variables, with evidence quoted from the Behavior section. The two-call split concentrates the LLM's attention on the most consequential semantic task. A file-based cache keyed on skill file content hash prevents redundant API calls across repeated runs.

**Layer 3 — ESM Construction and Composition.** Each skill's extraction result is passed to the ESM builder, which applies the three-pass belief seeding, detects `forward_credential` operations structurally (a variable with high credential or secret belief appearing in both a skill's inputs and outputs, indicating it is passed through rather than consumed), and takes an isolation belief snapshot before cross-boundary propagation. The isolation snapshot is preserved for the P7 check.

The composer takes all skill ESMs and produces a composed product automaton. Variable links are discovered by exact name matching first (a variable appearing in skill A's outputs and skill B's inputs), with LLM semantic matching as a fallback for skills that share no exact variable names. Pipeline order is determined by topological sort over the dependency graph; for harnesses with ≤4 skills and ambiguous ordering, all valid orderings are checked and findings are unioned. Beliefs propagate forward across each boundary by max-merge: the terminal belief of a variable in the upstream skill overwrites the prior of the same variable in the downstream skill if it is higher. Fan-in compositions apply the union bound.

**Layer 4 — Dual Verification.** Two independent checkers run on the composed automaton.

The DFA reachability checker simulates forward execution through the composed pipeline, evaluating seven policies at each operation step. P1 fires when a variable with P(credential) > 0.5 reaches an external sink (`post_http`, `send_slack`, `send_email`, `scp_transfer`, or `ssh_execute`). P2 fires when P(pii) > 0.5 reaches an external sink. P3 fires when P(secret) > 0.5 reaches an external sink and P(credential) ≤ 0.5 (to avoid double-reporting). P4 fires when P(untrusted_external) > 0.5 reaches a shell execution operation. P5 fires when a credential variable arrives at a skill and is never consumed by any substantive operation in that skill. P6 fires when credentials are transmitted via email without TLS. P7, the novel finding class, fires when the maximum non-benign belief for a variable across all skills in isolation is below 0.40, but the composed belief exceeds 0.70 and the delta exceeds 0.30 — meaning the composition itself revealed a vulnerability invisible in any single skill.

The Z3 SMT checker works at a higher abstraction level, ignoring beliefs entirely. It encodes each skill's capabilities as boolean Z3 variables and asserts structural policies as SMT constraints. The key invariant is `skills_are_different`: a Z3 finding is only a cross-skill finding if the source capability and the sink capability belong to different skills. Five fixed policies cover credential exfiltration paths, injection paths, PII exfiltration paths, credential forwarding, and cleartext transmission. A dynamic Tier 2 layer generates additional policies for any sensitive-source/external-sink capability pair present in the joint capability set that is not already covered by the fixed policies. The Z3 checker catches vulnerabilities that the DFA misses when belief priors are too low due to ambiguous naming; the DFA checker catches vulnerabilities the Z3 checker misses because it can reason about what data actually flows, not just which capabilities are present.

**Layer 5 — LLM Witness Validation.** After Layers 1–4 produce a candidate finding set, a final LLM agent attempts to reduce false positives by asking a concrete exploitability question for each finding: *can a plausible input to this harness be constructed that would actually trigger the reported vulnerability?* The agent is given the full finding (source skill, trigger variable, sink operation, belief evidence, witness path) and the raw text of all involved skill files. It attempts to construct a concrete input scenario — for example, a specific `.env` file contents, a specific HTTP request body, or a specific database record — under which the data flow would genuinely occur and the sensitive data would genuinely reach the external sink.

If the agent concludes that no such input can be constructed (for example, because the sink operation only executes under a conditional branch that the belief model assumed worst-case but that in practice cannot be triggered with sensitive data in scope), the finding is filtered from the output. If the agent constructs a plausible input, the witness is attached to the finding's description as a concrete exploitation scenario, strengthening the evidence. If the agent is uncertain, the finding is retained but tagged with a reduced confidence indicator and its severity is capped one level below what the belief values would otherwise warrant.

This layer is the primary mechanism for eliminating false positives that arise from the belief model's pessimistic assumptions — particularly findings generated by the Z3 structural checker (which has no data-flow awareness) and findings on variables with `is_external = 'uncertain'`. It adds one LLM call per candidate finding, which is acceptable because the finding count after deduplication is small (typically 1–4 per harness).

### Connection to Course Techniques

**Hoare Logic.** Each skill is characterized by a precondition and postcondition expressed as belief distributions. The postcondition of `skill_build.md` includes P(credential | BUILD_ENV) = 0.994. This postcondition becomes the precondition of `skill_deploy.md` through the sequential Hoare composition rule {P} S1 {Q}, {Q} S2 {R}. When the terminal postcondition R satisfies a security policy (credential-labeled data has reached an external sink), a violation is reported. The entire belief propagation mechanism is a probabilistic generalization of sequential Hoare triple composition.

**SAT/SMT Solvers.** The Z3 checker encodes the capability lattice as a satisfiability problem. Boolean variables represent the presence of each capability in each skill. Policy constraints assert that certain capability combinations across different skills are forbidden. When Z3 finds the constraint satisfiable, it returns a model — a concrete counterexample identifying exactly which skills contribute which capabilities to the violation. This counterexample is embedded in the finding's output as structured evidence.

**Static Analysis (Taint Tracking).** EMERALD implements a probabilistic form of classic source-sink taint analysis. Credentials, secrets, and PII are sources; external network operations are sinks. Taint (belief) propagates through the shared context variable space across skill boundaries. The key extension over boolean taint is that sources are not binary — a variable is a source to degree P(credential), and that degree propagates and can be amplified by aggregation. The aggregation union bound is the taint analysis equivalent of recognizing that a struct containing a secret field should itself be considered secret.

**Runtime Monitoring DFAs.** The composed product automaton is the static analog of a runtime monitoring DFA. States represent execution positions in the composed pipeline (which skill is currently executing, in which internal state). Transitions are skill operations that consume and produce variables. Bad states are defined by the joint condition that a policy P1–P7 is satisfied against the propagated belief at the current operation. The DFA reachability check determines whether any bad state is reachable from the initial state — equivalent to asking whether any execution path through the harness triggers a policy violation. The witness path returned with each finding is the accepting run of the automaton: the sequence of states and transitions that leads from the initial state to the bad state.

### Output Format

EMERALD outputs a JSON array of findings. Each finding contains a unique ID, severity (`critical`/`high`/`medium`/`low`/`info`), a human-readable title, a structured description naming the source skill, the trigger variable, the propagation path, the sink operation, and (when Layer 5 produces one) a concrete exploitation scenario. Each finding also contains a location object with the skill file and line number of the triggering operation, a boolean `cross_skill` field, an optional list of related skill files, and a CWE identifier.

### State Machine Visualization

EMERALD can optionally export a DOT-format graph of the composed state machine for each analyzed harness. Pass `--viz <viz_dir>` when invoking `run.py`:

```bash
python3 run.py benchmarks/harness_deploy_pipeline/ --viz ./viz_output/
```

This writes a `.dot` file to the specified directory. The graph nodes represent ESM states (idle, active, done) for each skill; edges represent operations labeled with the operation type, the variable being read or written, and the belief value at that step. Cross-skill edges — transitions where a variable crosses from one skill's ESM into the next — are rendered with a distinct style and labeled with the variable name and its propagated belief. Converting the DOT file to an image requires Graphviz:

```bash
dot -Tpng viz_output/harness_deploy_pipeline.dot -o viz_output/harness_deploy_pipeline.png
```

The resulting diagram makes the data flow visually legible: you can trace a credential from its source operation in the first skill, through the cross-boundary propagation edge, to the sink operation in the second skill that triggers the policy violation. Bad states (states where a policy fires) are rendered with a double border and labeled with the policy ID. This is primarily useful for understanding why a finding was generated and for constructing presentations or reports.

---

## Evaluation

### Benchmark Results

EMERALD was evaluated against eight provided harnesses covering diverse vulnerability patterns. All eight harnesses produce at least one cross-skill finding with `cross_skill: true`. All output passes schema validation.

| Harness | Findings | Max Severity | Key Variable | CWE |
|---|---|---|---|---|
| harness_read_and_post | 1 | critical | FILE_SUMMARY | CWE-200 |
| harness_code_review | 2 | high | GITHUB_TOKEN, LINT_REPORT | CWE-272, CWE-74 |
| harness_data_pipeline | 1 | critical | EMPLOYEE_DATA | CWE-359 |
| harness_deploy_pipeline | 2 | critical | BUILD_ENV, SSH_PRIVATE_KEY | CWE-200, CWE-74 |
| harness_incident_response | 1 | critical | SYSTEM_DIAGNOSTICS | CWE-200 |
| harness_monitoring | 1 | critical | METRICS_DATA | CWE-200 |
| harness_onboarding | 2 | high | TEMP_PASSWORD, ONBOARDING_LOG | CWE-319, CWE-200 |
| harness_research_assistant | 2 | medium | RESEARCH_API_KEY, PAPER_RESULTS | CWE-272, CWE-200 |

The two checkers in Layer 4 are complementary in coverage. For harnesses with explicit credential names and exact variable matching (`harness_deploy_pipeline`, `harness_data_pipeline`, `harness_incident_response`), the DFA checker produces the primary finding with high-confidence belief values. For harnesses where credential forwarding is structural rather than data-flow-based (`harness_code_review`'s `GITHUB_TOKEN`, `harness_research_assistant`'s `RESEARCH_API_KEY`), the Z3-T4 checker provides the primary signal. In all cases where both checkers fire on the same vulnerability, the DFA finding is retained and the Z3 counterexample is attached as supplementary evidence.

### The Aggregation Mechanism

The most technically significant result is the behavior on `BUILD_ENV` in `harness_deploy_pipeline`. The variable name alone yields P(credential) = 0.10 from name heuristics — generically suspicious but not actionable. After Pass 2, the LLM identifies that `AWS_SECRET_ACCESS_KEY` and `STRIPE_SECRET_KEY` are used in the Behavior section, raising P(credential) to 0.72. After Pass 3, the union-bound aggregation over five component variables yields P(credential | BUILD_ENV) = 0.994. Without the aggregation mechanism, this finding would be classified as medium severity at best, or missed entirely if the threshold is set conservatively. With it, the finding correctly reaches critical severity, and the description cites the specific credential names extracted from the Behavior section as evidence.

### Dual-Checker Coverage

The DFA and Z3 checkers have complementary blind spots. The DFA checker misses vulnerabilities when belief priors are systematically low — for example, when a credential is forwarded under a generic name like `auth` or `token` and the LLM extraction also produces a low-confidence hint. The Z3 checker has no belief threshold and fires on structural capability combinations regardless, catching these cases as medium-severity structural findings. Conversely, the Z3 checker has no belief model and cannot distinguish a harness where sensitive data actually flows from one where the capability combination happens to exist but no data traverses the boundary. The DFA checker's belief propagation provides this discrimination, downgrading or suppressing findings where the belief evidence is weak.

### Layer 5 False Positive Reduction

The witness validation agent in Layer 5 was evaluated on the same eight harnesses by artificially injecting two categories of spurious findings: structural Z3 findings on harnesses where the source and sink capabilities exist in different skills but no shared variable connects them, and DFA findings on variables with `is_external = 'uncertain'` pointing at likely-internal endpoints.

For the injected structural false positives, Layer 5 correctly filtered all cases where no shared variable could carry data between the source and sink skill. For the uncertain-external false positives, Layer 5 filtered roughly half, retaining findings where the skill's Behavior section contained language suggesting the endpoint was genuinely external (third-party API references, external domain names in prose) and filtering findings where the skill description suggested an internal monitoring or logging endpoint. In both categories, no true positives were filtered — all real vulnerabilities from the eight benchmark harnesses survived Layer 5 intact.

### The P7 Novel Finding Class

The P7 belief-amplification checker targets a finding class that no boolean taint analysis can detect: compositions where each skill individually carries low sensitivity beliefs, but the combination produces a variable with high sensitivity. This finding class is not activated by the provided benchmarks, which all contain obvious single-skill signals that propagate directly. To demonstrate P7, an adversarial external harness was constructed with two skills: one skill reads `user_preferences.json` and extracts fields including display name, email address, and notification settings — individually, none of these fields trigger a high-confidence PII label, and the variable name `USER_PREFS` is moderately suspicious at P(pii) = 0.30; a second skill aggregates `USER_PREFS` with `ACCOUNT_HISTORY` and `PAYMENT_RECORDS` into a `FULL_PROFILE` variable and posts it to an analytics endpoint. In isolation, neither skill exceeds the P7 isolation ceiling of 0.40. After composition, `FULL_PROFILE` reaches P(pii) = 0.87 through the union-bound aggregation, a delta of 0.57 above the maximum isolation belief, triggering a P7 finding at high severity. A boolean taint analysis of either skill alone would find no violation.

### Limitations

The aggregation detection mechanism depends on LLM reliability. When a skill aggregates variables without using the language patterns EMERALD detects ("all fields", "complete payload", "full dictionary"), the aggregation update does not fire and the aggregate variable retains only its name-heuristic prior. This is a potential source of false negatives on harnesses written in terse or non-standard prose styles.

The `is_external` classification uses a pessimistic catch-all: any URL not matching known internal patterns is treated as external. On real-world harnesses, internal APIs with externally-resolvable domain names (internal monitoring dashboards, corporate SaaS tools) will be misclassified as external. These findings are capped at medium severity and flagged with a caveat in the description. Layer 5 further reduces the impact of this by filtering cases where the witness validation agent cannot construct a plausible exploitation scenario involving a genuinely external party, but the classification uncertainty is not fully eliminated.

The over-scoped credential problem (CWE-272) is detected structurally — EMERALD identifies that a credential is forwarded downstream — but cannot reason about why the forwarding is over-privileged. It cannot compare the permissions a credential grants against the permissions actually required by the downstream skill. The P5 finding is therefore a conservative approximation: it fires when a credential arrives at a skill and is not consumed there, but it does not fire when a credential is consumed with broader permissions than necessary.

Finally, EMERALD's pipeline ordering assumes skills share data through named context variables. For harnesses where data flows are implicit — agents communicating through free-text messages in conversational frameworks — the ordering and linking mechanisms degrade to LLM inference, which is less reliable. All findings derived from semantically-inferred rather than exactly-matched variable links are tagged with reduced confidence and their severity is capped one level below what the belief values would otherwise warrant.

---

## Usage

```bash
pip install anthropic z3-solver graphviz
export ANTHROPIC_API_KEY=your_key_here   # optional; falls back to structural analysis

# Analyze a single harness
python3 run.py benchmarks/harness_deploy_pipeline/

# Analyze with state machine visualization output
python3 run.py benchmarks/harness_deploy_pipeline/ --viz ./viz_output/

# Convert the DOT file to an image (requires Graphviz installed)
dot -Tpng viz_output/harness_deploy_pipeline.dot -o viz_output/harness_deploy_pipeline.png

# Run all 8 benchmarks and check ground truth
python3 evaluate.py
```

`ANTHROPIC_API_KEY` is optional. Without it, EMERALD runs Layer 1 structural parsing only, sets `extraction_confidence = 0.6` on all extractions, and proceeds to composition and checking. The Z3 structural checker and fallback DFA checker still produce findings on all provided benchmarks without any API calls. LLM-dependent features — sensitivity hints, aggregation detection, semantic variable linking, and Layer 5 witness validation — are disabled in this mode, and findings are not filtered for false positives.
