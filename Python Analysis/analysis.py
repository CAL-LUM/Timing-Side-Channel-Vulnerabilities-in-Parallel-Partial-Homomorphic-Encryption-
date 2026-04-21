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

# Output directory and report path.
resultsDir = "results"
reportPath = os.path.join(resultsDir, "analysis_report.txt")

# Detection threshold |t| > 4.5 corresponds to a false-positive rate of
# approximately 1 in 100,000 under the null hypothesis.
tvlaThreshold = 4.5

# Must match PaddingDeadlineMs in main.go.
paddingDeadlineMs = 20

systems = ["sequential", "parallel", "secure"]

# Metrics available per system.
# heap_allocs and heap_bytes are sequential-only: runtime.ReadMemStats is a
# stop-the-world operation that pauses all goroutines, so calling it from
# concurrent goroutines would capture allocations from neighbouring operations,
# producing meaningless cross-goroutine interference values.
# cpu_cycles is available for all three systems via the QPC tick counter.
systemMetrics = {
    "sequential": ["duration_ns", "cpu_cycles", "heap_allocs", "heap_bytes"],
    "parallel":   ["duration_ns", "cpu_cycles"],
    "secure":     ["duration_ns", "cpu_cycles"],
}

allMetrics = ["duration_ns", "cpu_cycles", "heap_allocs", "heap_bytes"]

# Human-readable labels used in the report and CSV headers.
metricLabels = {
    "duration_ns":  "Duration (ns)",
    "cpu_cycles":   "CPU Cycles (count)",
    "heap_allocs":  "Heap Allocations (count)",
    "heap_bytes":   "Heap Bytes Allocated",
}

os.makedirs(resultsDir, exist_ok=True)


# Data loading

def loadData():
    # Load timing CSVs for all three systems and combine into a single
    # data frame. Missing metric columns are filled with NaN so that
    # downstream code can reference every column without branching.
    dfs = []
    for fname, system in [
        ("sequential_timings.csv", "sequential"),
        ("parallel_timings.csv",   "parallel"),
        ("secure_timings.csv",     "secure"),
    ]:
        path = os.path.join(resultsDir, fname)
        if not os.path.exists(path):
            print(f"  WARNING: {path} not found — skipping {system}")
            continue
        df = pd.read_csv(path)

        # Add missing columns as NaN rather than raising a KeyError later.
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


# Descriptive statistics

def descriptiveStats(df, candidates):
    # Compute per-system, per-candidate summary statistics for every metric
    # that is available in that system. CV (coefficient of variation) is
    # particularly useful here because it normalises spread by the mean,
    # allowing noise levels to be compared across systems that have different
    # absolute decryption times.
    rows = []
    for system in systems:
        available = systemMetrics[system]
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
                    "cvPct":     s.std() / s.mean() * 100 if s.mean() != 0 else 0,
                    "median":    s.median(),
                    "p95":       s.quantile(0.95),
                    "p99":       s.quantile(0.99),
                    "max":       s.max(),
                })
    return pd.DataFrame(rows)


# Overhead analysis

def computeOverhead(statsDF):
    # Calculate mean computational overhead of each system relative to the
    # sequential baseline, averaged across all candidates.
    rows = []
    overheadSummary = {}

    for metric in ["duration_ns", "cpu_cycles"]:

        # Collect per-candidate means for each system into separate dicts
        # so overhead percentages can be calculated candidate-by-candidate.
        seqMeans = {}
        parMeans = {}
        secMeans = {}

        for system, store in [("sequential", seqMeans),
                               ("parallel",   parMeans),
                               ("secure",     secMeans)]:
            sub = statsDF[(statsDF["system"] == system) &
                          (statsDF["metric"] == metric)]
            for _, row in sub.iterrows():
                store[row["candidate"]] = row["mean"]

        candidates = list(seqMeans.keys())

        parVsSeqList = []
        secVsSeqList = []
        secVsParList = []

        for cand in candidates:
            if cand not in seqMeans:
                continue
            seq = seqMeans[cand]
            par = parMeans.get(cand)
            sec = secMeans.get(cand)

            # Percentage overhead relative to the appropriate baseline.
            parVsSeq = ((par - seq) / seq * 100) if par is not None else None
            secVsSeq = ((sec - seq) / seq * 100) if sec is not None else None
            secVsPar = ((sec - par) / par * 100) if (par is not None and sec is not None) else None

            if parVsSeq is not None:
                parVsSeqList.append(parVsSeq)
            if secVsSeq is not None:
                secVsSeqList.append(secVsSeq)
            if secVsPar is not None:
                secVsParList.append(secVsPar)

            rows.append({
                "metric":       metric,
                "candidate":    cand,
                "seqMean":      seq,
                "parMean":      par,
                "secMean":      sec,
                "parVsSeqPct":  parVsSeq,
                "secVsSeqPct":  secVsSeq,
                "secVsParPct":  secVsPar,
            })

        # Store mean overhead across all candidates alongside the per-candidate
        # breakdown so the report can print both summary and detailed tables.
        overheadSummary[metric] = {
            "parVsSeqMeanPct":       np.mean(parVsSeqList) if parVsSeqList else None,
            "secVsSeqMeanPct":       np.mean(secVsSeqList) if secVsSeqList else None,
            "secVsParMeanPct":       np.mean(secVsParList) if secVsParList else None,
            "parVsSeqPerCandidate":  dict(zip(candidates, parVsSeqList)),
            "secVsSeqPerCandidate":  dict(zip(candidates, secVsSeqList)),
            "secVsParPerCandidate":  dict(zip(candidates, secVsParList)),
        }

    return pd.DataFrame(rows), overheadSummary


# TVLA

def tvlaTest(a, b):
    # Welch's t-test with unequal variance assumption.
    # Returns (tStat, pValue, leakageFlag) where leakageFlag is True
    # when |t| exceeds the 4.5 detection threshold.
    if len(a) < 2 or len(b) < 2:
        return np.nan, np.nan, False
    t, p = ttest_ind(a, b, equal_var=False)
    return t, p, abs(t) > tvlaThreshold


def metricValidForPair(metric, sysA, sysB):
    # Return True only if both systems recorded real data for this metric.
    # Prevents heap metrics from appearing in parallel/secure comparisons.
    return (metric in systemMetrics[sysA] and
            metric in systemMetrics[sysB])


def runTVLA(df, candidates):
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
    for sysA, sysB in combinations(systems, 2):
        for metric in allMetrics:
            if not metricValidForPair(metric, sysA, sysB):
                continue
            a = df[df["system"] == sysA][metric].dropna()
            b = df[df["system"] == sysB][metric].dropna()
            t, p, leak = tvlaTest(a, b)
            rows.append({
                "metric":     metric,
                "comparison": f"{sysA} vs {sysB}",
                "scope":      "all candidates pooled",
                "nA": len(a), "nB": len(b),
                "meanA": a.mean(), "meanB": b.mean(),
                "tStat": t, "pValue": p, "leakage": leak,
            })

    # Group 2: cross-system, per candidate.
    for cand in candidates:
        for sysA, sysB in combinations(systems, 2):
            for metric in allMetrics:
                if not metricValidForPair(metric, sysA, sysB):
                    continue
                a = df[(df["system"] == sysA) &
                       (df["candidate_name"] == cand)][metric].dropna()
                b = df[(df["system"] == sysB) &
                       (df["candidate_name"] == cand)][metric].dropna()
                t, p, leak = tvlaTest(a, b)
                rows.append({
                    "metric":     metric,
                    "comparison": f"{sysA} vs {sysB}",
                    "scope":      f"candidate: {cand}",
                    "nA": len(a), "nB": len(b),
                    "meanA": a.mean(), "meanB": b.mean(),
                    "tStat": t, "pValue": p, "leakage": leak,
                })

    # Group 3: within-parallel candidate pairs.
    par = df[df["system"] == "parallel"]
    for cA, cB in combinations(candidates, 2):
        for metric in ["duration_ns", "cpu_cycles"]:
            a = par[par["candidate_name"] == cA][metric].dropna()
            b = par[par["candidate_name"] == cB][metric].dropna()
            t, p, leak = tvlaTest(a, b)
            rows.append({
                "metric":     metric,
                "comparison": f"{cA} vs {cB}",
                "scope":      "within-parallel",
                "nA": len(a), "nB": len(b),
                "meanA": a.mean(), "meanB": b.mean(),
                "tStat": t, "pValue": p, "leakage": leak,
            })

    # Group 4: within-secure candidate pairs.
    sec = df[df["system"] == "secure"]
    for cA, cB in combinations(candidates, 2):
        for metric in ["duration_ns", "cpu_cycles"]:
            a = sec[sec["candidate_name"] == cA][metric].dropna()
            b = sec[sec["candidate_name"] == cB][metric].dropna()
            t, p, leak = tvlaTest(a, b)
            rows.append({
                "metric":     metric,
                "comparison": f"{cA} vs {cB}",
                "scope":      "within-secure",
                "nA": len(a), "nB": len(b),
                "meanA": a.mean(), "meanB": b.mean(),
                "tStat": t, "pValue": p, "leakage": leak,
            })

    return pd.DataFrame(rows)


# Text report

def writeReport(df, statsDF, tvlaDF, candidates, overheadSummary):
    # Build and write the full structured analysis report to results/analysis_report.txt.
    # The report is assembled as a list of strings and joined at the end to
    # avoid repeated file writes and to keep formatting logic in one place.
    sep  = "=" * 78
    sep2 = "-" * 78

    # Header block summarises the run configuration so the report is self-contained.
    lines = [
        sep,
        "  TVLA SECURITY ANALYSIS REPORT",
        "  Parallel Paillier E-Voting — Decryption Phase",
        "  Sequential | Parallel (Unprotected) | Secure (Countermeasures Applied)",
        sep, "",
        f"  Records    : {len(df):,}",
        f"  Systems    : " + "  ".join(
            f"{s} ({len(df[df['system']==s]):,})" for s in systems
            if s in df['system'].values
        ),
        f"  Candidates : {', '.join(candidates)}",
        f"  Threshold  : |t| > {tvlaThreshold}",
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
        "",
    ]

    # Descriptive statistics section — one table per metric, systems stacked.
    for metric in allMetrics:
        relevantSystems = [s for s in systems if metric in systemMetrics[s]]
        if not relevantSystems:
            continue

        lines += [sep2, f"  DESCRIPTIVE STATISTICS — {metricLabels[metric]}", sep2]
        if metric in ("heap_allocs", "heap_bytes"):
            lines.append("  (sequential only — parallel and secure omit this metric)")
        lines.append("")

        header = (f"  {'System':<12} {'Candidate':<10} {'N':>5} "
                  f"{'Mean':>14} {'Std':>14} {'CV%':>7} "
                  f"{'Median':>14} {'P99':>14}")
        lines.append(header)
        lines.append("  " + "-" * (len(header) - 2))

        for system in relevantSystems:
            for cand in candidates:
                row = statsDF[(statsDF["system"] == system) &
                              (statsDF["candidate"] == cand) &
                              (statsDF["metric"] == metric)]
                if row.empty:
                    continue
                r = row.iloc[0]
                lines.append(
                    f"  {system:<12} {cand:<10} {int(r['n']):>5} "
                    f"{r['mean']:>14.2f} {r['std']:>14.2f} {r['cvPct']:>7.2f} "
                    f"{r['median']:>14.2f} {r['p99']:>14.2f}"
                )
            lines.append("")

    # Overhead section — summary percentages followed by per-candidate breakdown.
    lines += [sep2, "  COMPUTATIONAL OVERHEAD ANALYSIS", sep2, ""]
    lines.append("  Overhead is calculated per candidate relative to the sequential")
    lines.append("  baseline and then averaged across all five candidates.")
    lines.append("  The divergence between duration_ns and cpu_cycles for the secure")
    lines.append("  system isolates CM3 padding cost (wall-clock only) from the true")
    lines.append("  computational overhead of CM1 ciphertext blinding (both metrics).")
    lines.append("")

    for metric in ["duration_ns", "cpu_cycles"]:
        oh = overheadSummary[metric]
        lines.append(f"  [{metricLabels[metric]}]")
        lines.append(
            f"    Parallel vs Sequential  : "
            f"{oh['parVsSeqMeanPct']:+.2f}% mean overhead"
        )
        lines.append(
            f"    Secure   vs Sequential  : "
            f"{oh['secVsSeqMeanPct']:+.2f}% mean overhead"
        )
        lines.append(
            f"    Secure   vs Parallel    : "
            f"{oh['secVsParMeanPct']:+.2f}% mean overhead  "
            f"(countermeasure cost above unprotected parallel baseline)"
        )
        lines.append("")
        lines.append(f"    Per-candidate breakdown (secure vs parallel):")
        header = (f"    {'Candidate':<12} {'Seq mean':>14} {'Par mean':>14} "
                  f"{'Sec mean':>14} {'Par vs Seq':>12} {'Sec vs Par':>12}")
        lines.append(header)
        lines.append("    " + "-" * (len(header) - 4))
        cands = list(oh["secVsParPerCandidate"].keys())
        for cand in cands:
            parOh = oh["parVsSeqPerCandidate"].get(cand)
            secOh = oh["secVsParPerCandidate"].get(cand)

            # Inner helper to pull the mean for a specific system/candidate/metric
            # combination from the stats data frame without repeating the filter.
            def getMean(system, candidate, m):
                sub = statsDF[(statsDF["system"] == system) &
                              (statsDF["candidate"] == candidate) &
                              (statsDF["metric"] == m)]
                return sub.iloc[0]["mean"] if not sub.empty else float("nan")

            seqM = getMean("sequential", cand, metric)
            parM = getMean("parallel",   cand, metric)
            secM = getMean("secure",     cand, metric)
            lines.append(
                f"    {cand:<12} {seqM:>14.0f} {parM:>14.0f} {secM:>14.0f} "
                f"{parOh:>+11.2f}% {secOh:>+11.2f}%"
            )
        lines.append("")

    # TVLA results section — results grouped by scope, sorted by |t| descending
    # so the largest potential signals appear first.
    lines += [sep2,
              f"  TVLA RESULTS — Welch t-test  (|t| > {tvlaThreshold} = leakage detected)",
              sep2, ""]

    # Scope order controls the visual grouping in the report: cross-system
    # comparisons first (framework validation), within-system comparisons last
    # (the security-critical results).
    scopeOrder = [
        ("all candidates pooled", "Cross-system, all candidates pooled"),
        ("candidate:",            "Cross-system, per candidate"),
        ("within-parallel",       "Within-parallel (candidate distinguishability)"),
        ("within-secure",         "Within-secure (countermeasure effectiveness)"),
    ]

    for metric in allMetrics:
        subMetric = tvlaDF[tvlaDF["metric"] == metric]
        if subMetric.empty:
            continue
        lines.append(f"  [{metricLabels[metric]}]")

        for scopePrefix, scopeLabel in scopeOrder:
            if scopePrefix.endswith(":"):
                sub = subMetric[subMetric["scope"].str.startswith(scopePrefix)]
            else:
                sub = subMetric[subMetric["scope"] == scopePrefix]
            if sub.empty:
                continue

            lines.append(f"    {scopeLabel}:")
            lines.append(
                f"    {'Comparison':<28} {'Scope':<30} "
                f"{'t-stat':>8} {'p-value':>10} {'Result':>14}"
            )
            lines.append("    " + "-" * 94)

            # Sort by absolute t-statistic so the largest signals appear first.
            sub = sub.sort_values("tStat", key=abs, ascending=False)
            for _, row in sub.iterrows():
                result = "*** LEAK ***" if row["leakage"] else "no leakage"
                scopeDisplay = (row["scope"] if len(row["scope"]) <= 30
                                else row["scope"][:27] + "...")
                lines.append(
                    f"    {row['comparison']:<28} {scopeDisplay:<30} "
                    f"{row['tStat']:>8.3f} {row['pValue']:>10.4f} {result:>14}"
                )
            lines.append("")

    # Summary section — violation counts and a final verdict on countermeasure
    # effectiveness at the configured padding deadline.
    lines += [sep2, "  SUMMARY", sep2, ""]
    totalLeaks = tvlaDF["leakage"].sum()
    parWithin  = tvlaDF[tvlaDF["scope"] == "within-parallel"]
    secWithin  = tvlaDF[tvlaDF["scope"] == "within-secure"]
    parLeaks   = parWithin["leakage"].sum()
    secLeaks   = secWithin["leakage"].sum()

    # Cross-system leaks are expected by design and excluded from the verdict.
    crossLeaks = tvlaDF[
        ~tvlaDF["scope"].isin(["within-parallel", "within-secure"]) &
        tvlaDF["leakage"]
    ].shape[0]

    lines.append(f"  Total TVLA violations         : {totalLeaks} / {len(tvlaDF)}")
    lines.append(f"  Cross-system leaks            : {crossLeaks}")
    lines.append(f"  Within-parallel leaks         : {parLeaks} / {len(parWithin)}"
                 f"  ({'candidate distinguishable' if parLeaks > 0 else 'candidates indistinguishable'})")
    lines.append(f"  Within-secure leaks           : {secLeaks} / {len(secWithin)}")

    ohDur = overheadSummary.get("duration_ns", {})
    ohCyc = overheadSummary.get("cpu_cycles", {})
    lines.append("")
    lines.append(f"  Overhead (secure vs parallel baseline):")
    if ohDur.get("secVsParMeanPct") is not None:
        lines.append(f"    duration_ns : {ohDur['secVsParMeanPct']:+.2f}%  "
                     f"(wall-clock, includes CM3 padding)")
    if ohCyc.get("secVsParMeanPct") is not None:
        lines.append(f"    cpu_cycles  : {ohCyc['secVsParMeanPct']:+.2f}%  "
                     f"(computational work only, excludes CM3)")

    # Verdict: if no within-secure leaks are detected, countermeasures are
    # effective at the current padding deadline. If leaks are detected, the
    # deadline needs to be increased in both main.go and paddingDeadlineMs above.
    if secLeaks == 0:
        verdict = (f"  Verdict: countermeasures effective at PaddingDeadlineMs={paddingDeadlineMs}ms")
    else:
        verdict = (f"  Verdict: WARNING — increase PaddingDeadlineMs above {paddingDeadlineMs}ms")
    lines += ["", verdict, "", sep]

    report = "\n".join(lines)
    with open(reportPath, "w") as f:
        f.write(report)
    print(f"\n  Report written to {reportPath}")
    return report


# Entry point

def main():
    print("\n=== TVLA Analysis — Parallel Paillier E-Voting ===\n")

    # Load and validate all three timing CSVs.
    print("Loading data...")
    df, candidates = loadData()
    print(f"  {len(df):,} total records")
    print(f"  Candidates: {candidates}\n")

    # Compute summary statistics across all systems, candidates, and metrics.
    print("Computing descriptive statistics...")
    statsDF = descriptiveStats(df, candidates)

    # Calculate overhead of parallel and secure systems relative to sequential baseline.
    print("Computing overhead...")
    overheadDF, overheadSummary = computeOverhead(statsDF)

    # Run all four TVLA comparison groups and count violations.
    print("Running TVLA...")
    tvlaDF = runTVLA(df, candidates)
    leaks = tvlaDF["leakage"].sum()
    print(f"  {leaks} violation(s) detected across all metrics\n")

    # Write the structured text report and export all data frames to CSV.
    print("Writing report...")
    report = writeReport(df, statsDF, tvlaDF, candidates, overheadSummary)

    statsDF.to_csv(os.path.join(resultsDir, "descriptive_stats.csv"), index=False)
    tvlaDF.to_csv(os.path.join(resultsDir, "tvla_results.csv"), index=False)
    overheadDF.to_csv(os.path.join(resultsDir, "overhead_analysis.csv"), index=False)
    print(f"  Exported descriptive_stats.csv, tvla_results.csv, overhead_analysis.csv")
    print("\n" + report)


if __name__ == "__main__":
    main()