# DenialSafe

Implementation of **Public-view robust authorization recourse**.

## Installation

Requires Python `>=3.11`. Run from the repository root in an activated environment.

```bash
python -m pip install -e .
```

Inspection environment: Python 3.13.5; numpy 2.1.3, matplotlib 3.10.0. Checks: Python syntax, configuration parsing and CLI/source argument matching. Training and full evaluation were not run.

## Data

The generator constructs finite workloads from the formal problem. It writes one JSON object per line. Import recorded or independently constructed cases with the same schema.

The bundled generator writes synthetic finite-model scenarios as JSONL. Fix the seed and keep the generated input for paired comparisons.

```bash
python -m denialsafe prepare --count 200 --seed 17 --output data/generated.jsonl
```

## Execution and evaluation

```bash
python -m denialsafe run --data data/generated.jsonl --output runs/main
```

## Comparisons and ablations

```bash
python -m denialsafe suite --data data/generated.jsonl --output runs/comparison
```

Use `--methods` to select: `denialsafe`, `exact_robust`, `decision_only`, `true_policy`, `public_templates`, `sampled_policies`, `no_feasibility`.

## Outputs

`runs/main/denialsafe/records.jsonl` stores per-case results; `metrics.json` stores aggregate measurements. Comparison outputs use one directory per method.

```bash
python -m denialsafe plot --inputs runs/comparison/denialsafe --output figures
```

Plotting writes `figures/summary.csv` and metric PNGs. Statistical intervals can be computed from a retained record file:

```bash
python -m denialsafe.statistics --records runs/main/denialsafe/records.jsonl --output results/intervals.json
```
