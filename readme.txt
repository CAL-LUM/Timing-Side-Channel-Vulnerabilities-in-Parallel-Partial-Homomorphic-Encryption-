# Timing Side-Channel Vulnerabilities in Parallel Partial Homomorphic Encryption

**BSc Cyber Security Dissertation — University of Gloucestershire, 2026 by Callum Liddell**
*Supervised by Joe Cox*

---

## Overview

This repository contains the full implementation, experimental results, and dissertation for an investigation into timing side-channel vulnerabilities introduced through parallelism in Partial Homomorphic Encryption (PHE) algorithms.

While parallel processing has become the dominant optimisation strategy for PHE deployments, its security implications — particularly with respect to timing side-channel leakage in the decryption phase — remain unevaluated in existing literature. This research identifies and characterises three structural timing leakage vectors introduced by parallel Paillier decryption, develops a novel evaluation framework (CP-TVLA), and proactively implements and evaluates three countermeasures against it.

---

## Repository Structure

```
/
├── Go Implementation/
│   ├── main.go           - Three e-voting systems and timing measurement
│   ├── go.mod
│   └── go.sum
│
├── Python Analysis/
│   └── analysis.py       - TVLA analysis, statistics, and plot generation
│
├── Results/              - Results at N = 1,000, 5,000 and 10,000
│   ├── N = 1000/
│   │   ├── analysis_report.txt
│   │   ├── descriptive_stats.csv
│   │   ├── parallel_timings.csv
│   │   ├── secure_timings.csv
│   │   ├── sequential_timings.csv
│   │   └── tvla_results.csv
│   │
│   ├── N = 5000/
│   │   ├── analysis_report.txt
│   │   ├── descriptive_stats.csv
│   │   ├── parallel_timings.csv
│   │   ├── secure_timings.csv
│   │   ├── sequential_timings.csv
│   │   └── tvla_results.csv
│   │
│   └── N = 10000/
│       ├── analysis_report.txt
│       ├── descriptive_stats.csv
│       ├── overhead_analysis.csv
│       ├── parallel_timings.csv
│       ├── secure_timings.csv
│       ├── sequential_timings.csv
│       └── tvla_results.csv
│
└── Dissertation/
    └── dissertation.pdf
```

---

## Quick Start

### 1. Run the Go implementation

```bash
cd "Go Implementation"
go run main.go
```

This generates three CSV files in `results/`:
- `sequential_timings.csv`
- `parallel_timings.csv`
- `secure_timings.csv`

By default, each system runs 10,000 measurement repetitions. This takes approximately 30–60 minutes depending on hardware. See `README_main.md` for configuration options.

### 2. Run the Python analysis

```bash
cd "Python Analysis"
pip install pandas scipy matplotlib seaborn numpy
python analysis.py
```

This reads the CSVs from `results/` and produces the full TVLA report, descriptive statistics and overhead analysis See `README_analysis.md` for full output details.

---

## The Three Systems

| System | Description | Countermeasures |
| Sequential | Single-goroutine baseline | None |
| Parallel | Concurrent decryption, one goroutine per candidate | None |
| Secure | Concurrent decryption with proactive hardening | CM1 + CM2 + CM3 |

### Countermeasures

| ID | Name | Leakage vector addressed |
| CM1 | Ciphertext blinding | Input-dependent timing from ciphertext bit-pattern variation |
| CM2 | Synchronisation barrier | Scheduling state divergence from staggered goroutine launch |
| CM3 | Constant-time padding | Completion-time ordering observable to a network adversary |

---

## The CP-TVLA Framework

The **Candidate-Partitioned Test Vector Leakage Assessment** (CP-TVLA) framework is a novel adaptation of the TVLA methodology (Goodwill et al., 2011) to a software timing context. Standard TVLA partitions traces into fixed vs random input sets; CP-TVLA partitions by candidate identity instead, which maps directly to the e-voting threat model where an adversary seeks to infer relative vote totals from decryption timing.

Four adaptations distinguish CP-TVLA from standard TVLA:

1. **Candidate-identity partitioning** — traces grouped by candidate rather than fixed/random
2. **Dual independent metrics** — `duration_ns` (wall-clock) and `cpu_cycles` (computational work) captured simultaneously for cross-validation
3. **N-Progressive monotonicity testing** — t-statistics evaluated at three run counts to distinguish genuine signals from statistical fluctuations
4. **Cross-system validation** — framework sensitivity confirmed against known architectural differences before security-critical within-system comparisons

A violation is defined as `|t| > 4.5`, corresponding to a false-positive rate of approximately 1 in 100,000 under the null hypothesis.

---

## Key Results

Applied to 150,000 decryption timing records (N = 10,000 runs per candidate across three systems):

- **0/20 within-system violations** sustained across both metrics in both the unprotected parallel and hardened secure systems
- **Non-monotonic t-statistic progression** at all three run counts confirms intermediate peaks are sampling fluctuations rather than emerging signals
- **9.3% mean computational overhead** for the secure system above the unprotected parallel baseline, attributable primarily to CM1 ciphertext blinding
- CM3 constant-time padding contributes wall-clock latency but does not appear in `cpu_cycles`, confirming it operates outside the measurement window as intended

---

## Results Structure

Results are stored at three measurement counts to support N-progressive monotonicity analysis:

| Folder | Runs per candidate | Total records |
| `N = 1000` | 1,000 | 15,000 |
| `N = 5000` | 5,000 | 75,000 |
| `N = 10000` | 10,000 | 150,000 |

The `overhead_analysis.csv` file is only present in the `N = 10000` folder as it is calculated from the full dataset.

---

## Platform

The Go implementation is **Windows-specific** due to its dependency on `QueryPerformanceCounter` for nanosecond-resolution timing and `timeBeginPeriod` for improved system timer resolution. Running on Linux or macOS requires replacing the QPC timer with an equivalent high-resolution monotonic clock.

The Python analysis script is platform-independent.

---

## Dependencies

**Go**
- Go 1.21+
- `github.com/roasbeef/go-go-gadget-paillier`

**Python**
- Python 3.12+
- pandas, scipy, matplotlib, seaborn, numpy

---

## Further Documentation

- [`README_main.md`](Go%20Implementation/README_main.md) — Detailed documentation for `main.go`
- [`README_analysis.md`](Python%20Analysis/README_analysis.md) — Detailed documentation for `analysis.py`
- [`dissertation.pdf`](Dissertation/dissertation.pdf) — Full dissertation

---

## Research Questions

- **RQ1** — What timing side-channel vulnerabilities are introduced through parallel processing in the decryption phase of a Paillier-based e-voting system?
- **RQ2** — How can a candidate-partitioned TVLA framework be developed and applied to systematically evaluate side-channel leakage in parallel Paillier decryption?
- **RQ3** — How effective are proactively applied countermeasures at eliminating timing side-channel vulnerabilities, and what is their computational overhead?

---

*University of Gloucestershire — BSc Cyber Security, 2026*