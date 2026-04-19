# TVLA Analysis — Parallel Paillier E-Voting Security Analysis
#
# Applies Test Vector Leakage Assessment (Welch t-test) to decryption-phase
# timing measurements collected from three Paillier e-voting implementations:
#   sequential — single-goroutine baseline
#   parallel   — concurrent decryption, no countermeasures
#   secure     — concurrent decryption with blinding, barrier, and padding
#
# Usage:
#   pip install pandas scipy numpy
#   python analysis.py   (run from the folder containing results/)
#
# Outputs (all written to results/):
#   analysis_report.txt
#   tvla_results.csv
#   descriptive_stats.csv
#   overhead_analysis.csv

import os
import sys
import warnings
import numpy as np
import pandas as pd
from scipy.stats import ttest_ind
from itertools import combinations

warnings.filterwarnings("ignore")

RESULTS_DIR = "results"
REPORT_PATH = os.path.join(RESULTS_DIR, "analysis_report.txt")

TVLA_THRESHOLD = 4.5

# Must match PaddingDeadlineMs in main.go.
PADDING_DEADLINE_MS = 20

SYSTEMS = ["sequential", "parallel", "secure"]

# Metrics available per system.
# heap_allocs and heap_bytes are sequential-only: runtime.ReadMemStats is a
# stop-the-world operation that pauses all goroutines, so calling it from
# concurrent goroutines would capture allocations from neighbouring operations,
# producing meaningless cross-goroutine interference values.
# cpu_cycles is available for all three systems via the QPC tick counter.
SYSTEM_METRICS = {
    "sequential": ["duration_ns", "cpu_cycles", "heap_allocs", "heap_bytes"],
    "parallel":   ["duration_ns", "cpu_cycles"],
    "secure":     ["duration_ns", "cpu_cycles"],
}

ALL_METRICS = ["duration_ns", "cpu_cycles", "heap_allocs", "heap_bytes"]

METRIC_LABELS = {
    "duration_ns":  "Duration (ns)",
    "cpu_cycles":   "CPU Cycles (count)",
    "heap_allocs":  "Heap Allocations (count)",
    "heap_bytes":   "Heap Bytes Allocated",
}

os.makedirs(RESULTS_DIR, exist_ok=True)


# ── Data loading ───────────────────────────────────────────────────────────────

def load_data():
    # Load timing CSVs for all three systems and combine into a single
    # data frame. Missing metric columns are filled with NaN so that
    # downstream code can reference every column without branching.
    dfs = []
    for fname, system in [
        ("sequential_timings.csv", "sequential"),
        ("parallel_timings.csv",   "parallel"),
        ("secure_timings.csv",     "secure"),
    ]:
        path = os.path.join(RESULTS_DIR, fname)
        if not os.path.exists(path):
            print(f"  WARNING: {path} not found — skipping {system}")
            continue
        df = pd.read_csv(path)

        for col in ["cpu_cycles", "heap_allocs", "heap_bytes"]:
            if col not in df.columns:
                df[col] = np.nan

        dfs.append(df)
        print(f"  Loaded {len(df):,} records from {fname}")

    if not dfs:
        sys.exit("No CSV files found in results/. Run main.go first.")

    df = pd.concat(dfs, ignore_index=True)

    # Extract ordered candidate names from the data itself so the script
    # does not need to duplicate the candidate list from main.go.
    candidates = (df[["candidate_idx", "candidate_name"]]
                  .drop_duplicates()
                  .sort_values("candidate_idx")["candidate_name"]
                  .tolist())
    return df, candidates


# ── Descriptive statistics ─────────────────────────────────────────────────────

def descriptive_stats(df, candidates):
    # Compute per-system, per-candidate summary statistics for every metric
    # that is available in that system. CV (coefficient of variation) is
    # particularly useful here because it normalises spread by the mean,
    # allowing noise levels to be compared across systems that have different
    # absolute decryption times.
    rows = []
    for system in SYSTEMS:
        available = SYSTEM_METRICS[system]
        for cand in candidates:
            sub = df[(df["system"] == system) & (df["candidate_name"] == cand)]
            if sub.empty:
                continue
            for metric in available:
                s = sub[metric].dropna()
                if s.empty:
                    continue
                rows.append({
                    "system":    system,
                    "candidate": cand,
                    "metric":    metric,
                    "n":         len(s),
                    "mean":      s.mean(),
                    "std":       s.std(),
                    "cv_pct":    s.std() / s.mean() * 100 if s.mean() != 0 else 0,
                    "median":    s.median(),
                    "p95":       s.quantile(0.95),
                    "p99":       s.quantile(0.99),
                    "max":       s.max(),
                })
    return pd.DataFrame(rows)


# ── Overhead analysis ──────────────────────────────────────────────────────────

def compute_overhead(stats_df):
    # Calculate mean computational overhead of each system relative to the
    # sequential baseline, averaged across all candidates.
    #
    # The divergence between duration_ns and cpu_cycles overhead for the secure
    # system is analytically significant: cpu_cycles captures only genuine
    # computational work (dominated by CM1 ciphertext blinding), whilst
    # duration_ns also absorbs the CM3 busy-wait padding that executes outside
    # the cpu_cycles measurement window. The difference between the two metrics
    # therefore isolates CM3's wall-clock contribution from the true cost of CM1.
    rows = []
    overhead_summary = {}

    for metric in ["duration_ns", "cpu_cycles"]:
        seq_means = {}
        par_means = {}
        sec_means = {}

        for system, store in [("sequential", seq_means),
                               ("parallel",   par_means),
                               ("secure",     sec_means)]:
            sub = stats_df[(stats_df["system"] == system) &
                           (stats_df["metric"] == metric)]
            for _, row in sub.iterrows():
                store[row["candidate"]] = row["mean"]

        candidates = list(seq_means.keys())

        par_vs_seq_list = []
        sec_vs_seq_list = []
        sec_vs_par_list = []

        for cand in candidates:
            if cand not in seq_means:
                continue
            seq = seq_means[cand]
            par = par_means.get(cand)
            sec = sec_means.get(cand)

            par_vs_seq = ((par - seq) / seq * 100) if par is not None else None
            sec_vs_seq = ((sec - seq) / seq * 100) if sec is not None else None
            sec_vs_par = ((sec - par) / par * 100) if (par is not None and sec is not None) else None

            if par_vs_seq is not None:
                par_vs_seq_list.append(par_vs_seq)
            if sec_vs_seq is not None:
                sec_vs_seq_list.append(sec_vs_seq)
            if sec_vs_par is not None:
                sec_vs_par_list.append(sec_vs_par)

            rows.append({
                "metric":        metric,
                "candidate":     cand,
                "seq_mean":      seq,
                "par_mean":      par,
                "sec_mean":      sec,
                "par_vs_seq_%":  par_vs_seq,
                "sec_vs_seq_%":  sec_vs_seq,
                "sec_vs_par_%":  sec_vs_par,
            })

        overhead_summary[metric] = {
            "par_vs_seq_mean_%":          np.mean(par_vs_seq_list) if par_vs_seq_list else None,
            "sec_vs_seq_mean_%":          np.mean(sec_vs_seq_list) if sec_vs_seq_list else None,
            "sec_vs_par_mean_%":          np.mean(sec_vs_par_list) if sec_vs_par_list else None,
            "par_vs_seq_per_candidate":   dict(zip(candidates, par_vs_seq_list)),
            "sec_vs_seq_per_candidate":   dict(zip(candidates, sec_vs_seq_list)),
            "sec_vs_par_per_candidate":   dict(zip(candidates, sec_vs_par_list)),
        }

    return pd.DataFrame(rows), overhead_summary


# ── TVLA ───────────────────────────────────────────────────────────────────────

def tvla_test(a, b):
    # Welch's t-test with unequal variance assumption.
    # Returns (t_stat, p_value, leakage_flag) where leakage_flag is True
    # when |t| exceeds the 4.5 detection threshold.
    if len(a) < 2 or len(b) < 2:
        return np.nan, np.nan, False
    t, p = ttest_ind(a, b, equal_var=False)
    return t, p, abs(t) > TVLA_THRESHOLD


def _metric_valid_for_pair(metric, sysA, sysB):
    # Return True only if both systems recorded real data for this metric.
    # Prevents heap metrics from appearing in parallel/secure comparisons.
    return (metric in SYSTEM_METRICS[sysA] and
            metric in SYSTEM_METRICS[sysB])


def run_tvla(df, candidates):
    # Execute all four groups of TVLA comparisons and collect results.
    #
    # Group 1 — Cross-system, all candidates pooled.
    #   Validates that the framework detects known architectural differences.
    #   Large t-statistics here are expected and carry no security implication.
    #
    # Group 2 — Cross-system, per candidate.
    #   Confirms no single candidate is driving the cross-system signal.
    #
    # Group 3 — Within-parallel, between candidates.
    #   Primary security test: does parallel decryption leak which candidate
    #   holds the largest ciphertext?
    #
    # Group 4 — Within-secure, between candidates.
    #   Countermeasure effectiveness test: do CM1/CM2/CM3 eliminate any
    #   candidate-distinguishable timing pattern?
    rows = []

    # Group 1: cross-system, all candidates pooled.
    for sysA, sysB in combinations(SYSTEMS, 2):
        for metric in ALL_METRICS:
            if not _metric_valid_for_pair(metric, sysA, sysB):
                continue
            a = df[df["system"] == sysA][metric].dropna()
            b = df[df["system"] == sysB][metric].dropna()
            t, p, leak = tvla_test(a, b)
            rows.append({
                "metric":     metric,
                "comparison": f"{sysA} vs {sysB}",
                "scope":      "all candidates pooled",
                "n_a": len(a), "n_b": len(b),
                "mean_a": a.mean(), "mean_b": b.mean(),
                "t_stat": t, "p_value": p, "leakage": leak,
            })

    # Group 2: cross-system, per candidate.
    for cand in candidates:
        for sysA, sysB in combinations(SYSTEMS, 2):
            for metric in ALL_METRICS:
                if not _metric_valid_for_pair(metric, sysA, sysB):
                    continue
                a = df[(df["system"] == sysA) &
                       (df["candidate_name"] == cand)][metric].dropna()
                b = df[(df["system"] == sysB) &
                       (df["candidate_name"] == cand)][metric].dropna()
                t, p, leak = tvla_test(a, b)
                rows.append({
                    "metric":     metric,
                    "comparison": f"{sysA} vs {sysB}",
                    "scope":      f"candidate: {cand}",
                    "n_a": len(a), "n_b": len(b),
                    "mean_a": a.mean(), "mean_b": b.mean(),
                    "t_stat": t, "p_value": p, "leakage": leak,
                })

    # Group 3: within-parallel candidate pairs.
    par = df[df["system"] == "parallel"]
    for cA, cB in combinations(candidates, 2):
        for metric in ["duration_ns", "cpu_cycles"]:
            a = par[par["candidate_name"] == cA][metric].dropna()
            b = par[par["candidate_name"] == cB][metric].dropna()
            t, p, leak = tvla_test(a, b)
            rows.append({
                "metric":     metric,
                "comparison": f"{cA} vs {cB}",
                "scope":      "within-parallel",
                "n_a": len(a), "n_b": len(b),
                "mean_a": a.mean(), "mean_b": b.mean(),
                "t_stat": t, "p_value": p, "leakage": leak,
            })

    # Group 4: within-secure candidate pairs.
    sec = df[df["system"] == "secure"]
    for cA, cB in combinations(candidates, 2):
        for metric in ["duration_ns", "cpu_cycles"]:
            a = sec[sec["candidate_name"] == cA][metric].dropna()
            b = sec[sec["candidate_name"] == cB][metric].dropna()
            t, p, leak = tvla_test(a, b)
            rows.append({
                "metric":     metric,
                "comparison": f"{cA} vs {cB}",
                "scope":      "within-secure",
                "n_a": len(a), "n_b": len(b),
                "mean_a": a.mean(), "mean_b": b.mean(),
                "t_stat": t, "p_value": p, "leakage": leak,
            })

    return pd.DataFrame(rows)


# ── Text report ────────────────────────────────────────────────────────────────

def write_report(df, stats_df, tvla_df, candidates, overhead_summary):
    # Build and write the full structured analysis report to results/analysis_report.txt.
    sep  = "=" * 78
    sep2 = "-" * 78
    lines = [
        sep,
        "  TVLA SECURITY ANALYSIS REPORT",
        "  Parallel Paillier E-Voting — Decryption Phase",
        "  Sequential | Parallel (Unprotected) | Secure (Countermeasures Applied)",
        sep, "",
        f"  Records    : {len(df):,}",
        f"  Systems    : " + "  ".join(
            f"{s} ({len(df[df['system']==s]):,})" for s in SYSTEMS
            if s in df['system'].values
        ),
        f"  Candidates : {', '.join(candidates)}",
        f"  Threshold  : |t| > {TVLA_THRESHOLD}",
        "",
        "  Metric availability per system:",
        "    sequential  — duration_ns, cpu_cycles, heap_allocs, heap_bytes",
        "    parallel    — duration_ns, cpu_cycles",
        "    secure      — duration_ns, cpu_cycles",
        "    (heap metrics omitted from parallel/secure: ReadMemStats is",
        "     stop-the-world and unsafe in concurrent goroutine context)",
        "",
        "  cpu_cycles vs duration_ns:",
        "    duration_ns measures wall-clock elapsed time via QPC (~100ns resolution).",
        "    cpu_cycles measures processor computational work via QPC tick counter.",
        "    OS scheduling pauses inflate duration_ns but not cpu_cycles.",
        "    Cache stalls inflate cpu_cycles but may be hidden in duration_ns.",
        "    CM3 (busy-wait padding) inflates duration_ns but NOT cpu_cycles,",
        "    since the busy-wait occurs outside the cpu_cycles measurement window.",
        "    The divergence between duration_ns and cpu_cycles overhead for the",
        "    secure system therefore isolates CM3's wall-clock contribution from",
        "    the true computational cost of CM1 ciphertext blinding.",
        f"  Secure system padding deadline: {PADDING_DEADLINE_MS} ms (CM3)",
        "",
    ]

    # Descriptive statistics section.
    for metric in ALL_METRICS:
        relevant_systems = [s for s in SYSTEMS if metric in SYSTEM_METRICS[s]]
        if not relevant_systems:
            continue

        lines += [sep2, f"  DESCRIPTIVE STATISTICS — {METRIC_LABELS[metric]}", sep2]
        if metric in ("heap_allocs", "heap_bytes"):
            lines.append("  (sequential only — parallel and secure omit this metric)")
        lines.append("")

        header = (f"  {'System':<12} {'Candidate':<10} {'N':>5} "
                  f"{'Mean':>14} {'Std':>14} {'CV%':>7} "
                  f"{'Median':>14} {'P99':>14}")
        lines.append(header)
        lines.append("  " + "-" * (len(header) - 2))

        for system in relevant_systems:
            for cand in candidates:
                row = stats_df[(stats_df["system"] == system) &
                               (stats_df["candidate"] == cand) &
                               (stats_df["metric"] == metric)]
                if row.empty:
                    continue
                r = row.iloc[0]
                lines.append(
                    f"  {system:<12} {cand:<10} {int(r['n']):>5} "
                    f"{r['mean']:>14.2f} {r['std']:>14.2f} {r['cv_pct']:>7.2f} "
                    f"{r['median']:>14.2f} {r['p99']:>14.2f}"
                )
            lines.append("")

    # Overhead section.
    lines += [sep2, "  COMPUTATIONAL OVERHEAD ANALYSIS", sep2, ""]
    lines.append("  Overhead is calculated per candidate relative to the sequential")
    lines.append("  baseline and then averaged across all five candidates.")
    lines.append("  The divergence between duration_ns and cpu_cycles for the secure")
    lines.append("  system isolates CM3 padding cost (wall-clock only) from the true")
    lines.append("  computational overhead of CM1 ciphertext blinding (both metrics).")
    lines.append("")

    for metric in ["duration_ns", "cpu_cycles"]:
        oh = overhead_summary[metric]
        lines.append(f"  [{METRIC_LABELS[metric]}]")
        lines.append(
            f"    Parallel vs Sequential  : "
            f"{oh['par_vs_seq_mean_%']:+.2f}% mean overhead"
        )
        lines.append(
            f"    Secure   vs Sequential  : "
            f"{oh['sec_vs_seq_mean_%']:+.2f}% mean overhead"
        )
        lines.append(
            f"    Secure   vs Parallel    : "
            f"{oh['sec_vs_par_mean_%']:+.2f}% mean overhead  "
            f"(countermeasure cost above unprotected parallel baseline)"
        )
        lines.append("")
        lines.append(f"    Per-candidate breakdown (secure vs parallel):")
        header = (f"    {'Candidate':<12} {'Seq mean':>14} {'Par mean':>14} "
                  f"{'Sec mean':>14} {'Par vs Seq':>12} {'Sec vs Par':>12}")
        lines.append(header)
        lines.append("    " + "-" * (len(header) - 4))
        cands = list(oh["sec_vs_par_per_candidate"].keys())
        for cand in cands:
            par_oh = oh["par_vs_seq_per_candidate"].get(cand)
            sec_oh = oh["sec_vs_par_per_candidate"].get(cand)

            def get_mean(system, candidate, m):
                sub = stats_df[(stats_df["system"] == system) &
                               (stats_df["candidate"] == candidate) &
                               (stats_df["metric"] == m)]
                return sub.iloc[0]["mean"] if not sub.empty else float("nan")

            seq_m = get_mean("sequential", cand, metric)
            par_m = get_mean("parallel",   cand, metric)
            sec_m = get_mean("secure",     cand, metric)
            lines.append(
                f"    {cand:<12} {seq_m:>14.0f} {par_m:>14.0f} {sec_m:>14.0f} "
                f"{par_oh:>+11.2f}% {sec_oh:>+11.2f}%"
            )
        lines.append("")

    # TVLA results section.
    lines += [sep2,
              f"  TVLA RESULTS — Welch t-test  (|t| > {TVLA_THRESHOLD} = leakage detected)",
              sep2, ""]

    scope_order = [
        ("all candidates pooled", "Cross-system, all candidates pooled"),
        ("candidate:",            "Cross-system, per candidate"),
        ("within-parallel",       "Within-parallel (candidate distinguishability)"),
        ("within-secure",         "Within-secure (countermeasure effectiveness)"),
    ]

    for metric in ALL_METRICS:
        sub_metric = tvla_df[tvla_df["metric"] == metric]
        if sub_metric.empty:
            continue
        lines.append(f"  [{METRIC_LABELS[metric]}]")

        for scope_prefix, scope_label in scope_order:
            if scope_prefix.endswith(":"):
                sub = sub_metric[sub_metric["scope"].str.startswith(scope_prefix)]
            else:
                sub = sub_metric[sub_metric["scope"] == scope_prefix]
            if sub.empty:
                continue

            lines.append(f"    {scope_label}:")
            lines.append(
                f"    {'Comparison':<28} {'Scope':<30} "
                f"{'t-stat':>8} {'p-value':>10} {'Result':>14}"
            )
            lines.append("    " + "-" * 94)
            sub = sub.sort_values("t_stat", key=abs, ascending=False)
            for _, row in sub.iterrows():
                result = "*** LEAK ***" if row["leakage"] else "no leakage"
                scope_display = (row["scope"] if len(row["scope"]) <= 30
                                 else row["scope"][:27] + "...")
                lines.append(
                    f"    {row['comparison']:<28} {scope_display:<30} "
                    f"{row['t_stat']:>8.3f} {row['p_value']:>10.4f} {result:>14}"
                )
            lines.append("")

    # Summary section.
    lines += [sep2, "  SUMMARY", sep2, ""]
    total_leaks = tvla_df["leakage"].sum()
    par_within  = tvla_df[tvla_df["scope"] == "within-parallel"]
    sec_within  = tvla_df[tvla_df["scope"] == "within-secure"]
    par_leaks   = par_within["leakage"].sum()
    sec_leaks   = sec_within["leakage"].sum()
    cross_leaks = tvla_df[
        ~tvla_df["scope"].isin(["within-parallel", "within-secure"]) &
        tvla_df["leakage"]
    ].shape[0]

    lines.append(f"  Total TVLA violations         : {total_leaks} / {len(tvla_df)}")
    lines.append(f"  Cross-system leaks            : {cross_leaks}")
    lines.append(f"  Within-parallel leaks         : {par_leaks} / {len(par_within)}"
                 f"  ({'candidate distinguishable' if par_leaks > 0 else 'candidates indistinguishable'})")
    lines.append(f"  Within-secure leaks           : {sec_leaks} / {len(sec_within)}")

    oh_dur = overhead_summary.get("duration_ns", {})
    oh_cyc = overhead_summary.get("cpu_cycles", {})
    lines.append("")
    lines.append(f"  Overhead (secure vs parallel baseline):")
    if oh_dur.get("sec_vs_par_mean_%") is not None:
        lines.append(f"    duration_ns : {oh_dur['sec_vs_par_mean_%']:+.2f}%  "
                     f"(wall-clock, includes CM3 padding)")
    if oh_cyc.get("sec_vs_par_mean_%") is not None:
        lines.append(f"    cpu_cycles  : {oh_cyc['sec_vs_par_mean_%']:+.2f}%  "
                     f"(computational work only, excludes CM3)")

    if sec_leaks == 0:
        verdict = (f"  Verdict: countermeasures effective at PaddingDeadlineMs={PADDING_DEADLINE_MS}ms")
    else:
        verdict = (f"  Verdict: WARNING — increase PaddingDeadlineMs above {PADDING_DEADLINE_MS}ms")
    lines += ["", verdict, "", sep]

    report = "\n".join(lines)
    with open(REPORT_PATH, "w") as f:
        f.write(report)
    print(f"\n  Report written to {REPORT_PATH}")
    return report


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    print("\n=== TVLA Analysis — Parallel Paillier E-Voting ===\n")

    print("Loading data...")
    df, candidates = load_data()
    print(f"  {len(df):,} total records")
    print(f"  Candidates: {candidates}\n")

    print("Computing descriptive statistics...")
    stats_df = descriptive_stats(df, candidates)

    print("Computing overhead...")
    overhead_df, overhead_summary = compute_overhead(stats_df)

    print("Running TVLA...")
    tvla_df = run_tvla(df, candidates)
    leaks = tvla_df["leakage"].sum()
    print(f"  {leaks} violation(s) detected across all metrics\n")

    print("Writing report...")
    report = write_report(df, stats_df, tvla_df, candidates, overhead_summary)

    stats_df.to_csv(os.path.join(RESULTS_DIR, "descriptive_stats.csv"), index=False)
    tvla_df.to_csv(os.path.join(RESULTS_DIR, "tvla_results.csv"), index=False)
    overhead_df.to_csv(os.path.join(RESULTS_DIR, "overhead_analysis.csv"), index=False)
    print(f"  Exported descriptive_stats.csv, tvla_results.csv, overhead_analysis.csv")
    print("\n" + report)


if __name__ == "__main__":
    main()