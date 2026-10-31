# DenialSafe implementation

Implementation of **Public-view robust authorization recourse**.

The existing finite-model algorithms are retained. This revision adds typed policy evaluation, bounded repeated-action grammar, deterministic public cost order, independently replayed legality/robustness, separate process output, and exact matched-view channel statistics. These are implementation and functional-validation artifacts; they are not the raw experimental code or evidence behind the manuscript's reported numbers.

## Installation

Requires Python >=3.11. From the repository root in an activated environment:

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

Installed validation environment: Windows, Python 3.13.5, numpy 2.1.3, scipy 1.15.3, matplotlib 3.10.0, psutil 7.1.0. Existing CI installs dependencies and runs the regression checks on Python 3.11.

## Data

The bundled generator produces synthetic finite-model scenarios for functional checks. It does not download a native benchmark, reproduce manuscript result tables or fit any parameters. Retain one generated input for paired comparisons:

```bash
python -m denialsafe prepare --count 6 --seed 17 --output data/generated.jsonl
```

Each UTF-8 JSONL line has a unique `id`, optional `family`, and `cluster` identifying the actual independent policy/history family. The generator records `generation_seed` and conservatively clusters repeated examples by family. Imported independent data should supply its reviewed cluster IDs. Input fields are:

`public`: finite `policies`, declassified `history`, legal `actions` and `max_depth`; `request`: the public denied request. Each primitive declares `user_executable`, typed `preconditions`, `set` and nonnegative `cost`. `secret_index` is an offline evaluation label and never enters public-view search except the explicitly secret-aware `true_policy` control. Optional `process_actions` contains guidance primitives; `candidate_budget` or `time_budget_seconds` bounds public search.

`core.generate` is an executable complete schema example. Use the same schema for reviewed recorded cases; keep native, mutation-derived and synthetic strata separate. No private data, manuscript, pretrained weights or original server logs are distributed. The algorithms use explicit policy/configuration inputs rather than learned models, and do not tune on test labels.

## Execution

```bash
python -m denialsafe run --data data/generated.jsonl --output runs/main
```

## Evaluation

```bash
python -m denialsafe evaluate --records runs/main/denialsafe/records.jsonl --output runs/evaluated.json
```

`coverage` is legally executable actual-policy-valid repair/all input denials; `robust_coverage` additionally quantifies over all compatible policies. `failed_repair`, `illegal_repair`, `nonrobust_repair`, actual/robust validity condition on emitted ACCESS_RECOURSE. `repair_cost` conditions on valid access repair. `process_guidance` conditions on `group=process_only`. `matched_view_secret_gain` is the exact uniform-secret Bayes recovery improvement (distinct output classes minus one, divided by compatible secrets); pairwise distinguishing is exact deterministic-channel accuracy, not a learned attacker experiment. Fractions are not percentage points until multiplied by 100.

Rates are fractions in [0,1]. `null` means an inapplicable or unresolved denominator, not zero failures. `metrics.json` gives conditional per-case means, SD and quantiles; rate fields with explicit `metric_counts` also contain pooled `micro` numerator/denominator/rate. Whole-case `latency_ms` includes local construction and audits; stage metrics identify the narrower compilation/runtime path. `rss_mib` is a sampled resident value, not a measured peak. Throughput is local finite-model useful effects per whole-case wall second, not the manuscript's server throughput.

The same `evaluate` command accepts independently recorded JSONL with `id`, `method`, `cluster`, numerical-or-null `metrics`, and optional `metric_counts` mapping each rate name to `[numerator, denominator]`. Thus backend-only paper measurements can be aggregated when genuinely collected; missing lock waits, network latency, maintenance, attacker recovery or native task outcomes are not assigned invented values.

## Comparisons and ablations

```bash
python -m denialsafe suite --data data/generated.jsonl --output runs/comparison
python -m denialsafe.statistics --records runs/comparison/denialsafe/records.jsonl --reference runs/comparison/exact_robust/records.jsonl --resamples 10000 --seed 17 --primary coverage --output runs/paired.json
```

Select a subset with `--methods`. Implemented configurations: `denialsafe`, `exact_robust`, `decision_only`, `true_policy`, `public_templates`, `sampled_policies`, `no_feasibility`. Deliberately lossy, unbound, feasibility-disabled and race variants are sandbox diagnostic controls, not safe deployments. The comparison implementations use this repository's declared finite semantics; they are not unmodified upstream systems.

Statistics first aggregate within each independent family and then bootstrap whole families. Paired analysis requires identical case IDs and excludes metrics undefined on either side. One eligible family yields no bootstrap interval. The zero-event bound concerns an event in an independent eligible cluster, not an iid per-request rate. McNemar is used only for independent single-record binary pairs; other paired summaries use Wilcoxon. Holm correction applies only to explicitly selected `--primary` endpoints. Small synthetic examples are not a source of experimental confidence intervals.

## Outputs and visualizations

```bash
python -m denialsafe plot --inputs runs/comparison/denialsafe runs/comparison/exact_robust --metrics coverage latency_ms --output runs/figures
```

Each method directory contains `records.jsonl` (actual outcomes and conditional metrics), `metrics.json`, and `config.json` (command, environment and seeds). Plotting writes `summary.csv` plus selected metric PNGs; undefined metrics produce no misleading empty plot. All paths are configurable. Choose fresh output directories for reruns; generation/evaluation do not silently overwrite retained inputs or records.

## Paper-to-code map

| Paper module or metric | Code entry | Configuration / command |
|---|---|---|
| Public possibility set and typed policy semantics | `core.possibility_set / evaluate` | public.policies and public.history |
| Public-only cost-ordered finite CEGIS | `core.synthesize / actions` | denialsafe; max_depth; candidate_budget |
| Independent action and robustness checker | `oracle.replay / decision / check` | before ACCESS_RECOURSE release |
| Access/process/conflict/abstention output | `core.synthesize` | actions / process_actions |
| Authenticated repair binding and current PDP gate | `execution.certify / authorize` | application-owned signing key; example below |
| Conditional validity, cost and same-view channel tests | `core.run_case / score` | evaluate; exact_robust / true_policy controls |
| Aggregation, paired intervals and visualization | `cli.summarize; statistics.analyze; cli.plot` | evaluate / statistics / plot |

## Validation and implementation scope

Validated locally: editable installation, syntax/import and regression checks, six seed-17 cases through every suite configuration, retained-record re-evaluation, 10,000-resample paired analysis, selected metric PNG/CSV output, and wheel/source-distribution builds. No full paper campaign was run. Local functional records are retained under `runs/smoke/` (Git-ignored).

Regression checks cover hand-computable rates and eligible denominators, the algorithm's safety boundary, and applicable replay/serialization paths. The documented small-data preparation, execution, suite, evaluation, statistics and plotting commands are the validation entry points. No complete training or large experimental campaign is required for these checks.

The grammar and policy family are explicit finite JSON structures; no symbolic SMT backend, Cedar/Balana parser or channel-padding service is supplied. `synthesis_ms` times the first search; whole-case `latency_ms` also includes the exhaustive confidentiality audit and must not be presented as online explanation latency. Timing budgets preserve honest abstention, not a strict wall-clock secrecy claim. Learned attack recovery, retained-scope/workflow studies and native policy corpora need actual labeled records and are not synthesized as results.

The local executor API authenticates the public-view/epoch/grammar/request/action
binding, independently rechecks legality and robustness, and consults the current
actual PDP before returning `EXECUTE`. Keep its HMAC key in the application;
certificates are internal records, not rendered explanations. The application
must perform its effect only for `EXECUTE` and keep its PDP check and effect within
the authorization boundary appropriate to that application. It is not a remote
transaction service or a one-time capability protocol.

```python
from denialsafe import core, execution

# public, request, actual_policy and application_key come from the application.
repair = core.synthesize(public, request)
certificate = execution.certify(public, request, repair, application_key)
decision = execution.authorize(
    certificate, public, request, actual_policy, application_key
)
```

The regression suite verifies successful repair, changed current policy, epoch
invalidation, tampered binding and rejection of process guidance as access.

The source retains its existing MIT license. Data and external systems remain subject to their own licenses and access rules.
