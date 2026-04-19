# main.go — Paillier E-Voting Security Analysis

Go implementation of three Paillier-based e-voting systems used to evaluate timing side-channel vulnerabilities introduced through parallelism in the decryption phase. Each system performs a fully independent cold start and exports a timing CSV for analysis by `analysis.py`.

---

## Requirements

```
Go 1.21+
Windows (required for QueryPerformanceCounter and RDTSC dependencies)
```

Install the Paillier library dependency:

```bash
go get github.com/roasbeef/go-go-gadget-paillier
```

---

## Usage

```bash
go run main.go
```

Run from the project root. Results are written to `results/` which is created automatically if it does not exist.

---

## Systems

The three systems run consecutively within a single executable. Each performs a completely independent cold start — fresh key pair, fresh election setup — so no key material, heap state, or cache content is shared between measurement phases.

### System 1 — Sequential

All five candidate ciphertexts are decrypted serially in a single goroutine. This serves as the baseline: it isolates the cost of a single Paillier decryption operation without any concurrent interference. Heap allocation metrics (`heap_allocs`, `heap_bytes`) are captured here using `runtime.ReadMemStats`, which is feasible only in the sequential system because it is a stop-the-world operation that would produce cross-goroutine interference in a concurrent context.

The P99 decryption duration measured in this system is used to calibrate the CM3 padding deadline in System 3, set to five times the P99 to comfortably exceed worst-case concurrent execution time.

### System 2 — Parallel (unprotected)

All five ciphertexts are decrypted concurrently, one goroutine per candidate. Each goroutine is pinned to a dedicated OS thread via `runtime.LockOSThread()` so that on a machine with sufficient cores, all five run simultaneously on separate physical cores. A `sync.WaitGroup` barrier ensures all goroutines begin decryption from the same scheduling position.

No countermeasures are applied. This system represents a naïve performance-oriented implementation and exposes the structural timing leakage vectors introduced by parallelism.

### System 3 — Secure parallel

Extends the parallel architecture with three proactive countermeasures targeting distinct leakage vectors:

| Countermeasure | Leakage vector addressed |
| CM1 — Ciphertext blinding | Input-dependent timing from ciphertext bit-pattern variation |
| CM2 — Synchronisation barrier | Scheduling state divergence from staggered goroutine launch |
| CM3 — Constant-time padding | Completion-time ordering observable to a network adversary |


## Timing Instrumentation

Two independent timing metrics are captured for each decryption call:

| Metric | Source | What it measures |
| `duration_ns` | Windows `QueryPerformanceCounter` | Wall-clock elapsed time |
| `cpu_cycles` | QPC tick counter (RDTSC proxy) | Computational work |

## Election Configuration

Constants at the top of `main.go` control the election parameters:

| Constant | Default | Description |
| `KeyBits` | `2048` | Paillier key size |
| `NumPrecincts` | `5` | Number of independently tallied precincts |
| `NumVotersPerPrecinct` | `1000` | Voters per precinct |
| `NumRuns` | `10000` | Measurement repetitions per system |
| `PaddingDeadlineMs` | `20` | CM3 busy-wait deadline in milliseconds |

## Outputs

| File | System | Contents |
| `results/sequential_timings.csv` | Sequential | `duration_ns`, `cpu_cycles`, `heap_allocs`, `heap_bytes` |
| `results/parallel_timings.csv` | Parallel | `duration_ns`, `cpu_cycles` |
| `results/secure_timings.csv` | Secure | `duration_ns`, `cpu_cycles` |

Each CSV contains one row per decryption measurement with columns: `run`, `candidate_idx`, `candidate_name`, `duration_ns`, `cpu_cycles`, and optionally the heap metrics, plus a `system` column identifying the source system.


## Platform Note

This implementation is Windows-specific. It depends on:
- `kernel32.dll` — `QueryPerformanceCounter`, `QueryPerformanceFrequency`
- `winmm.dll` — `timeBeginPeriod` (improves system timer resolution to 1ms)

Running on Linux or macOS will require replacing the QPC timer with an equivalent high-resolution monotonic clock.