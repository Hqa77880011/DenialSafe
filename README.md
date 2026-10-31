# DenialSafe

Implementation of **Public-view robust authorization recourse**. The source provides the manuscript's symbolic robust synthesis, independent checks, six comparison mechanisms, component-removal diagnostics, public channel/cache experiments and actual Cedar/Balana-backed local execution. It does not contain the original PolicyRecourse corpus or the evidence behind the manuscript's numerical tables.

## Install and functional checks

```bash
python -m pip install -e .
python -m unittest discover -s tests
python -m denialsafe prepare --count 6 --seed 17 --output data/cases.jsonl
python -m denialsafe suite --data data/cases.jsonl --output runs/comparison
```

Python >=3.11 and Z3 are required. Local validation used Windows/Python 3.13.5 with project-local Z3 and optional native engines. CPU smoke commands use one thread. No model training or LLM inference is required. Choose fresh output paths; retained records are not silently overwritten.

## Public model and action grammar

Each JSONL case supplies `id`, `family`/`cluster`, `public`, `request` and an offline actual-policy label (`secret_index`, `secret_assignment` or `actual_policy`). The isolated `channel.Service` API accepts only the public view and request. Actual policies are passed only to the explicitly secret-dependent experimental controls and to the current PDP/executor.

A public family is either `policies: [concrete policies]` or `skeleton` plus finite typed `holes`. A skeleton value `{"hole":"threshold"}` references `holes.threshold`. Synthesis keeps hole indices symbolic instead of materializing their Cartesian product. Policy interpretation supports typed equalities, membership, minimum/maximum, required fields and deny clauses. The rule form supports Boolean `allow_rules`/`deny_rules`, all/any/not/present and eq/ne/in/subset/numeric comparisons. Rule policies use deny overrides, an applicable allow, and distinct Permit/Deny/Indeterminate/NotApplicable categories. Missing values and ill-typed numeric comparisons never become permit. Boolean values differ from integers.

`history` contains published request/decision pairs with their full published category. Unobserved historical attributes may be declared as typed hole references, rather than passing their actual private values. `hidden_request_fields` quantifies current private attributes over public finite domains. The synthesizer never receives their actual values. History updates create separate public typed observation holes; private historical values are not printed or treated as a new public observation. Inconsistent history returns PUBLIC_CONFLICT; solver uncertainty abstains.

`actions` maps stable public IDs to literal `set`/`remove` transitions, public cost, `user_executable`, optional typed `preconditions` and `required_rights`. Bounded sequences retain intermediate preconditions and can repeat a primitive. Principal, tenant, provenance, rights, declared `protected_fields` and hidden request attributes cannot be modified by access recourse. Optional `scope_loss_weights` adds actual retained-set loss to the public objective. `process_actions` is a separate workflow grammar: applying for approval creates no permission and cannot be certified as access.

Public ordering is total cost followed by lexicographic action IDs. `max_depth`, `time_budget_seconds`, `candidate_budget` and `solver_timeout_ms` are explicit bounds. SAT counterexamples stay internal. UNKNOWN, checker disagreement and exhausted budgets never release an uncertified repair. `optimal` is true only when every lexicographic optimization objective is established; a certified feasible result may omit a global minimum claim.

## Core and comparison matrix

| Configuration | Actual mechanism |
|---|---|
| `denialsafe` | SMT least legal sequence under public seed models, universal counterexample query, CEGIS, independent decision formula/checker |
| `decision_only` (B1) | Published decision endpoint without action utility |
| `true_policy` (B2) | Lowest-cost feasible actual-policy counterfactual; explicit secret-dependent control |
| `redacted_repair` (B3) | Fixed administrator redaction of B2 action IDs/instructions; action selection still depends on the actual policy |
| `public_templates` (B4) | Public goal/conditional templates solved with the full legal primitive grammar, public-state Pareto pruning, history and full robust certification |
| `exact_robust` (B5) | Independent concrete family enumeration, public decision cache and (cost, depth, ID) state dominance; exact optimum when completed |
| `causal_adaptation` (B6) | Actual-policy Boolean feature intervention, sufficient feature assignment, minimum-contingency responsibility, and a separate legal-action realization of that feature assignment |
| `sampled_policies` | Removes universal verification; deliberately can emit nonrobust repairs |
| `no_feasibility` | Removes requester feasibility; deliberately can emit illegal repairs |
| `secret_tie_break` | Secret-dependent tie selection among universally valid repairs |

B6 is the manuscript's experimental causal adaptation. It is not presented as an unmodified reproduction of the cited policy-feature causal framework. Its feature explanation is selected by feature change, then mapped to executable actions; it is not B2 renamed with an added label. B3, B6 and secret tie-breaking intentionally retain actual-policy dependence and must not be offered by the isolated public-only service.

The independent finite interpreter (`oracle.py`) separately rebuilds transition legality and policy combination. Small families enumerate every policy/private-context assignment. Larger certificate checks rebuild an independent symbolic decision formula and ask for counterexamples. Synthesis and checking share trusted typed IR primitives and a solver, not a memoized safe decision or a portable solver proof. Differential tests compare both encodings, the concrete oracle and actual PDP calls over the declared native fragment.

## Metrics, plots and inference

```bash
python -m denialsafe evaluate --records runs/comparison/denialsafe/records.jsonl --output runs/evaluated.json
python -m denialsafe.statistics --records runs/comparison/denialsafe/records.jsonl --reference runs/comparison/exact_robust/records.jsonl --resamples 10000 --seed 17 --primary coverage --output runs/paired.json
python -m denialsafe plot --inputs runs/comparison/denialsafe runs/comparison/exact_robust --metrics coverage robust_validity synthesis_ms --output runs/figures
```

All-denial valid-access coverage and robust coverage have separate counts. Actual/robust validity, illegal/nonrobust action rates and repair cost are conditional on emitted access repairs; process guidance has its own group. Null means an inapplicable/unsupported denominator. Unsupported imported pairs remain denominator records using `supported:false` and `unsupported_reason`; they are not relabeled safe. Summary files retain per-case statistics and explicit micro counts.

Same-view content is exhaustively compared across compatible secret assignments. `matched_view_secret_gain` is the exact uniform finite-hypothesis Bayes recovery improvement from partitioning candidates by deterministic output; it is not a trained attack or a manuscript number. Pairwise distinguishing accuracy compares fixed hypotheses. Family bootstrap uses independent family clusters; one eligible family does not generate a bootstrap interval. Whole-case `latency_ms` includes offline label/confidentiality enumeration. `synthesis_ms` and measured stage costs are narrower; neither is a padded server wall-time guarantee. RSS is a resident sample, not a process peak.

## Adaptive, cache, channel and timing entries

These commands use one JSON case object, including `probe_domains` for attack requests:

```bash
python -m denialsafe attack --case case.json --visibility white --budget 100 --methods denialsafe redacted_repair causal_adaptation --output attack.json
python -m denialsafe attack --case case.json --visibility black --budget 10 --trajectory --output trajectories.json
python -m denialsafe cache --case case.json --repeats 5 --controlled-channel --output cache.json
python -m denialsafe benchmark --case case.json --calls 100 --restarts 5 --warmup 30 --seconds 120 --cache cold --output timing.json
python -m denialsafe scale --case case.json --dimensions 2 --values 2 --actions 10 --rules 10 --budgets 1 --depths 2 --output scale.jsonl
```

Matched attacks give every method the identical declassified decision history. Black-box random probes, gray-box public cost/guard observations and white-box hypothesis-splitting probes retain every request/response. Separate end-to-end trajectories select requests per method; their total recovery is not called incremental explanation leakage. Hidden actual request values remain in offline labels, never in published history.

`Service` caches only public-only methods. Keys bind the full canonical public request, epoch, history, grammar, costs and budget. Positive hits recheck legality and robustness; reported hit-stage time measures that recheck rather than repeating a cached synthesis timing. Optional application-owned HMAC keys attach deterministic certified records without adding actual-policy data. History/epoch changes produce new keys and clear old-epoch observations when using `update_history`.

The controlled channel emits a fixed byte count and delays to a public-size/budget-dependent release bucket. It records padding, actual release time and overruns. OS scheduling, resource contention and the actual PDP remain outside a strict timing-isolation guarantee. Certificate bytes, status, instructions and action IDs are serialized by a fixed renderer; internal counterexamples, policy IDs, solver counts and secret-aware diagnostics are excluded from the certified public path.

Timing launches genuinely fresh worker processes. Consistency, candidate optimization, verifier, independent checker, causal analysis, cache recheck, release delay, online CPU/wall and percentile costs are measured where applicable. Warmups and measurement periods are explicit. The small local 2-process/3-call checks are functional validation, not the full paper's 16-core/120-second campaign. Scale generation emits real coupled hole, rule and action structures; it does not fabricate performance values.

## Actual Cedar and Balana

The native adapter translates the typed total common fragment (required fields, Boolean/string/signed-64 equality, membership, integer bounds, deny overrides) and invokes real engines. Unsupported names, missing/ill-typed inputs, floating-point extensions and other language constructs abstain rather than being called native equivalents. No full Cedar/XACML parser claim is made.

```bash
# Java/Maven can be portable application-local installations.
mvn -f native/balana/pom.xml package dependency:copy-dependencies
python -m denialsafe native-check --case case.json --backend cedar --executable /path/to/cedar --output cedar.json
python -m denialsafe native-check --case case.json --backend balana --executable /path/to/java --classpath "native/balana/target/classes:native/balana/target/dependency/*" --output balana.json
```

On Windows separate classpath entries with `;`. The original Java bridge uses the real Balana PDP API and sends engine logs to stderr. Native input/output files and raw decision categories are retained. The declared published projection maps Cedar Allow to Permit, and Balana NotApplicable to Deny for this total conjunctive policy fragment; Indeterminate is retained. It does not collapse the full published history category of a different native profile. Native tests require `DENIALSAFE_CEDAR`, `DENIALSAFE_JAVA` and/or `DENIALSAFE_BALANA_CLASSPATH`. CI compiles and runs Balana. External licenses/versions are recorded in `native/THIRD_PARTY.md`; upstream engine code is not renamed or vendored.

## Actual action execution and workflow

`runtime.Executor(database, root, key, objects, pdp)` owns the live registry/policy epoch, trusted identity attributes, one-use MFA evidence, pending workflows and durable effect receipts. `objects` maps IDs to application-owned paths and scopes. Only registered IDs and paths beneath `root` can be exported. Current native policy is evaluated again for the transformed request and each actual object before file I/O; narrowing selects the corresponding real scope. The key and actual private identity/policy data never enter the public synthesis API.

Trusted operations are `install`, `set_identity` and `grant_mfa`. Actual user operations are `execute` and `process`; the application supplies an authenticated principal. Existing MFA state needs a nonexpired trusted identity session; a completion primitive needs actual unexpired one-use factor evidence. Current private identity values are checked against their declared public domains and are passed only to the actual PDP. A client cannot overwrite them in the public request. Changed epoch/grammar/request/signature fails binding; approval submission persists PENDING and never authorizes access.

The `execute` CLI reads an application-owned config (`database`, `root`, `key_file`, `objects`, optional `native_pdp`) and an explicit operation JSON. The signing key is read from its local file and is not printed. It supports the same operations; diagnostic method selection is not part of this executor API. An optional native PDP config supplies backend/executable/classpath/output. SQLite serializes current identity/epoch checks with local file authorization. Authorized earlier file writes are not claimed to roll back atomically with SQLite after a crash; arbitrary Python/OS sandboxing and remote distributed transactions are not claimed.

## Validation boundary

Locally exercised: 24 tests including both symbolic encodings vs independent enumeration, hidden current/history attributes, repeated primitive feasibility, all six comparison mechanisms and three distinct diagnostics, genuine policy-feature causal interventions, public cache/channel serialization, actual MFA/scoped protected-byte export and durable receipts, private identity rejection, pending workflow, and actual Cedar 4.14.0/Balana 1.2.24 calls with no native skips when configured. Six seed-17 cases cover robust-solvable/process-only/no-robust groups across all 10 configurations. Fresh-process short timings, white-box/matched-history attacks, controlled channel cache regimes, scale generation/run, retained-record evaluation, 10000 paired family resamples and PNG/CSV output are retained under ignored `runs/published-v2/` and `runs/published-v3/`.

The original 120 skeletons, five held-out seeds, manually reviewed action sequences, native policy corpora, agent clients and original server measurements are external inputs. The source implements their entry points; no original numerical outcome is inferred from local smoke tests. Existing MIT source licensing is preserved.
