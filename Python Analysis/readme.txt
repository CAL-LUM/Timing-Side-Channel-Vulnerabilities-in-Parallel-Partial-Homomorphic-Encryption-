# analysis.py — TVLA Analysis Pipeline

Python analysis script for the Parallel Paillier E-Voting Security Analysis project. Ingests timing CSVs produced by `main.go` and applies Test Vector Leakage Assessment (TVLA) 
to evaluate whether any of the three e-voting system configurations leak candidate-distinguishable timing information during the decryption phase.

---

## Requirements

```
Python 3.12+
pandas
scipy
matplotlib
seaborn
numpy
```

Install dependencies:

```bash
pip install pandas scipy matplotlib seaborn numpy
```

---

## Usage

Run `main.go` first to generate the CSV files, then:

```bash
python analysis.py
```

The script must be run from the directory containing the `results/` folder. All outputs are written into `results/`.

---

## What It Does

**1. Descriptive statistics**
Computes mean, standard deviation, coefficient of variation (CV), median, P95, and P99 for every system/candidate/metric combination. 

**2. Overhead analysis**
Calculates percentage overhead of the parallel and secure systems relative to the sequential baseline, averaged across all candidates. 

**3. TVLA (Test Vector Leakage Assessment)**
Applies Welch's t-test (unequal variance) across four comparison groups:

| Group | Purpose |
| Cross-system, pooled | Framework validation — detects known architectural differences |
| Cross-system, per candidate | Confirms no single candidate drives the cross-system signal |
| Within-parallel | Primary security test — can an adversary distinguish candidates? |
| Within-secure | Countermeasure effectiveness — do CM1/CM2/CM3 eliminate leakage? |

A violation is defined as `|t| > 4.5`, corresponding to a false-positive rate of approximately 1 in 100,000 under the null hypothesis. This threshold follows Goodwill et al. (2011) and the TVLA Derived Test Requirements.


## Metric Availability

| Metric | Sequential | Parallel | Secure |
| `duration_ns` | ✓ | ✓ | ✓ |
| `cpu_cycles` | ✓ | ✓ | ✓ |
| `heap_allocs` | ✓ | — | — |
| `heap_bytes` | ✓ | — | — |

---

## Outputs

### CSVs

| File | Contents |
| `descriptive_stats.csv` | Per-system, per-candidate, per-metric summary statistics |
| `tvla_results.csv` | All TVLA comparisons with t-statistic, p-value, and leakage flag |
| `overhead_analysis.csv` | Per-candidate overhead breakdown across both metrics |


### Report

`analysis_report.txt` contains the full structured analysis: descriptive statistics tables, overhead breakdown, and all TVLA results with a final verdict on countermeasure effectiveness.

---

## Configuration

Two constants at the top of the script must match the values in `main.go`:

| Constant | Default | Description |
|---|---|---|
| `TVLA_THRESHOLD` | `4.5` | Detection threshold for leakage |
| `PADDING_DEADLINE_MS` | `20` | CM3 busy-wait deadline in milliseconds |

---

## N-Progressive Monotonicity

The results at three different run counts (N = 1,000, 5,000, 10,000) are stored in separate subfolders under `results/`. 
Running the script independently against each subfolder allows the N-progressive monotonicity check described in the dissertation: 
a genuine leakage signal should produce t-statistics that grow monotonically with N, whereas a fluctuation will peak at an intermediate N and then decrease.