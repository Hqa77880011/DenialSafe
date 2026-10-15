# DenialSafe

Implementation of **Public-view robust authorization recourse**.

Implements public-policy possibility sets, legal action sequences, deterministic cost ordering and counterexample-guided robust repair. Only the true-policy baseline receives the actual policy. Missing required fields retain Indeterminate semantics.

## Install

Use Python 3.11 or newer. Create and activate a virtual environment, then install the package:

```bash
git clone https://github.com/Hqa77880011/DenialSafe.git
cd DenialSafe
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux/macOS or `.venv\Scripts\Activate.ps1` in PowerShell.

```bash
python -m pip install -e .
```

## Prepare data

```bash
python -m denialsafe prepare --count 200 --seed 17 --output data/workload.jsonl
```

The generator constructs finite workloads from the formal problem. It writes one JSON object per line. Import recorded or independently constructed cases with the same schema.

`public.policies` defines the finite policy family and `public.history` contains published request/decision pairs. Each public action declares its field changes, preconditions, cost and whether a user may execute it. `request` is the denied request; `secret_index` is used only by the evaluator and true-policy baseline.

## Execute and compare

```bash
python -m denialsafe run --data data/workload.jsonl --output runs/main
python -m denialsafe suite --data data/workload.jsonl --methods denialsafe exact_robust --output runs/comparison
```

Omit `--methods` in `suite` to include every comparison method and ablation.

`denialsafe` uses counterexample refinement; `exact_robust` checks the complete possible-policy family for every candidate; `decision_only` abstains; `true_policy` optimizes for the actual policy; `public_templates` checks a fixed public action sequence; `sampled_policies` and `no_feasibility` remove the corresponding checks.

These are algorithmic workloads without learned parameters. `--count` controls scenario count and `--seed` controls generation. Repeat with independent seeds for comparisons.

## Evaluate and visualize

Each method writes `records.jsonl` with per-case outputs and measurements, plus `metrics.json` with counts, means, sample standard deviations and quantiles. Rates are fractions. Conditional metrics exclude cases outside their denominator. Timers cover method execution; independent scoring is outside this timer.

Valid repair coverage, conditional failed/illegal/nonrobust repair rates, abstention, repair cost, policy checks and measured runtime.

```bash
python -m denialsafe plot --inputs runs/comparison/denialsafe runs/comparison/exact_robust --output figures
```

Plotting creates `summary.csv` and one PNG per numeric metric. RSS includes the Python runtime and imported libraries. Output bytes measure JSON serialization size.

## Implementation conventions

The policy language supports required fields, equalities, membership, minimum values and deny conjunctions. Search uses complete finite enumeration instead of SMT. Identity, tenant and provenance cannot be changed by action primitives. Process guidance is separate from access repair; this implementation emits access repair or abstention.


## Uncertainty and paired comparisons

```bash
python -m denialsafe.statistics --records runs/main/denialsafe/records.jsonl --output results/intervals.json
```

Supply --reference with a matched record file for paired differences. Resampling uses independent case IDs, or explicit cluster IDs when provided. Repeated observations from one source unit must share cluster. Zero-event bounds refer to an event in an independent cluster.
