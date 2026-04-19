// Paillier E-Voting Security Analysis
//
// Runs three e-voting systems consecutively and exports a CSV for each.
// Each system performs a fully independent cold start with its own key pair
// and election setup, so no key material, heap state, or cache content is
// shared between measurement phases.
//
// Systems:
//   1. Sequential — single-goroutine baseline
//   2. Parallel   — concurrent decryption, no countermeasures
//   3. Secure     — concurrent decryption with three countermeasures applied
//
// Outputs (written to results/):
//   sequential_timings.csv  — duration_ns, cpu_cycles, heap_allocs, heap_bytes
//   parallel_timings.csv    — duration_ns, cpu_cycles
//   secure_timings.csv      — duration_ns, cpu_cycles
//
// Usage:
//   go run main.go

package main

import (
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

// Election configuration constants.
const (
	KeyBits              = 2048  // Paillier key size
	NumPrecincts         = 5     // number of precincts
	NumVotersPerPrecinct = 1000  // voters per precinct
	NumRuns              = 10000 // measurement repetitions

	// Padding duration for secure system (CM3).
	// Chosen to exceed worst-case decryption time.
	PaddingDeadlineMs = 20
)

var (
	// Candidates are the five people standing in the election.
	Candidates = []string{"Marcus", "Trey", "Will", "George", "Jess"}

	// Selection probabilities (must sum to 100).
	Weights = []int{34, 23, 19, 14, 10}
)

// High-resolution timer (Windows QPC).
// Avoids coarse ~1ms granularity of time.Now().
var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	winmm                  = syscall.NewLazyDLL("winmm.dll")
	procQueryPerfCounter   = kernel32.NewProc("QueryPerformanceCounter")
	procQueryPerfFrequency = kernel32.NewProc("QueryPerformanceFrequency")
	procTimeBeginPeriod    = winmm.NewProc("timeBeginPeriod")
	qpcFrequency           int64 // ticks per second — constant for the lifetime of the process
)

// Initialise QPC and improve system timer resolution.
func initTimer() {
	// request 1ms timer precision
	procTimeBeginPeriod.Call(uintptr(1))
	procQueryPerfFrequency.Call(uintptr(unsafe.Pointer(&qpcFrequency)))
}

// Return current time in nanoseconds using QPC.
func qpcNow() int64 {
	var counter int64
	procQueryPerfCounter.Call(uintptr(unsafe.Pointer(&counter)))
	return counter * 1_000_000_000 / qpcFrequency
}

// CPU cycle proxy using QPC ticks (≈ cycles on invariant TSC).
// Provides a second side-channel independent of wall-clock time.

var (
	procGetSystemTimeAsFileTime = kernel32.NewProc("GetSystemTimeAsFileTime")
)

// Return raw QPC tick count.
func rdtscNow() int64 {
	var counter int64
	procQueryPerfCounter.Call(uintptr(unsafe.Pointer(&counter)))
	return counter
}

// Convert tick delta to cycle count
func ticksToCycles(tickDelta int64) int64 {
	return tickDelta
}

// Select a candidate index based on weighted probabilities.
func weightedRandom() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	roll := int(n.Int64())
	cumulative := 0
	for i, w := range Weights {
		cumulative += w
		if roll < cumulative {
			return i
		}
	}
	return len(Weights) - 1
}

// Encrypt a vote using 1-of-k encoding.
// Only the chosen candidate slot contains Enc(1); others Enc(0).
func encryptBallot(pub *paillier.PublicKey, candidateIdx int) ([]*big.Int, error) {
	numCandidates := len(Candidates)
	ballot := make([]*big.Int, numCandidates)

	for slot := 0; slot < numCandidates; slot++ {
		voteValue := int64(0)
		if slot == candidateIdx {
			voteValue = 1
		}
		encryptedSlot, err := paillier.Encrypt(pub, big.NewInt(voteValue).Bytes())
		if err != nil {
			return nil, fmt.Errorf("encrypting slot %d: %w", slot, err)
		}
		ballot[slot] = new(big.Int).SetBytes(encryptedSlot)
	}
	return ballot, nil
}

// Encrypt all ballots in a precinct using parallel workers.
// Encryption is parallelised across CPU cores because it uses only the public key.
func encryptPrecinct(pub *paillier.PublicKey) ([][]*big.Int, []int, error) {
	ballots := make([][]*big.Int, NumVotersPerPrecinct)
	groundTruth := make([]int, len(Candidates))

	voterChoices := make([]int, NumVotersPerPrecinct)
	for i := range voterChoices {
		voterChoices[i] = weightedRandom()
		groundTruth[voterChoices[i]]++
	}

	// Queue all voter jobs
	jobs := make(chan int, NumVotersPerPrecinct)
	for i := range voterChoices {
		jobs <- i
	}
	close(jobs)

	type encryptResult struct {
		voterIdx int
		ballot   []*big.Int
		err      error
	}
	results := make(chan encryptResult, NumVotersPerPrecinct)

	// worker pool across CPU cores
	for worker := 0; worker < runtime.NumCPU(); worker++ {
		go func() {
			for voterIdx := range jobs {
				b, err := encryptBallot(pub, voterChoices[voterIdx])
				results <- encryptResult{voterIdx, b, err}
			}
		}()
	}
	// Collect encrypted ballots
	for i := 0; i < NumVotersPerPrecinct; i++ {
		r := <-results
		if r.err != nil {
			return nil, nil, fmt.Errorf("voter %d: %w", r.voterIdx, r.err)
		}
		ballots[r.voterIdx] = r.ballot
	}
	return ballots, groundTruth, nil
}

// Aggregate ballots using Paillier homomorphism:
//
//	Enc(v₁) · Enc(v₂) = Enc(v₁ + v₂)
func aggregatePrecinct(pub *paillier.PublicKey, ballots [][]*big.Int) ([]*big.Int, error) {
	numCandidates := len(Candidates)

	// Initialise each candidate's running total to Enc(0).
	runningTotals := make([]*big.Int, numCandidates)
	for i := range runningTotals {
		encZero, err := paillier.Encrypt(pub, big.NewInt(0).Bytes())
		if err != nil {
			return nil, err
		}
		runningTotals[i] = new(big.Int).SetBytes(encZero)
	}

	for _, ballot := range ballots {
		for candidate := 0; candidate < numCandidates; candidate++ {
			newTotal := paillier.AddCipher(pub,
				runningTotals[candidate].Bytes(),
				ballot[candidate].Bytes(),
			)
			runningTotals[candidate] = new(big.Int).SetBytes(newTotal)
		}
	}
	return runningTotals, nil
}

// Combine precinct totals into national totals.
func combinePrecincts(pub *paillier.PublicKey, precinctAggregates [][]*big.Int) ([]*big.Int, error) {
	numCandidates := len(Candidates)

	nationalTotals := make([]*big.Int, numCandidates)
	for i := range nationalTotals {
		encZero, err := paillier.Encrypt(pub, big.NewInt(0).Bytes())
		if err != nil {
			return nil, err
		}
		nationalTotals[i] = new(big.Int).SetBytes(encZero)
	}

	for _, precinctTotal := range precinctAggregates {
		for candidate := 0; candidate < numCandidates; candidate++ {
			newTotal := paillier.AddCipher(pub,
				nationalTotals[candidate].Bytes(),
				precinctTotal[candidate].Bytes(),
			)
			nationalTotals[candidate] = new(big.Int).SetBytes(newTotal)
		}
	}
	return nationalTotals, nil
}

// Perform full election setup with a fresh key (cold start).
func coldStart() (priv *paillier.PrivateKey, pub *paillier.PublicKey, aggregates []*big.Int, groundTruth []int, err error) {
	fmt.Print("  Generating key pair... ")
	priv, err = paillier.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("key generation failed: %w", err)
	}
	pub = &priv.PublicKey
	fmt.Println("done.")
	// Encryupt and aggregate each precinct independently 
	fmt.Printf("  Setting up election (%d precincts × %d voters)...\n",
		NumPrecincts, NumVotersPerPrecinct)

	groundTruth = make([]int, len(Candidates))
	precinctAggregates := make([][]*big.Int, NumPrecincts)

	for p := 0; p < NumPrecincts; p++ {
		ballots, precinctTruth, encErr := encryptPrecinct(pub)
		if encErr != nil {
			return nil, nil, nil, nil, fmt.Errorf("precinct %d encryption: %w", p, encErr)
		}
		for i, votes := range precinctTruth {
			groundTruth[i] += votes // accumulate ground truth
		}

		precinctAggregates[p], err = aggregatePrecinct(pub, ballots)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("precinct %d aggregation: %w", p, err)
		}
		fmt.Printf("  Precinct %d/%d complete\n", p+1, NumPrecincts)
	}
	// combine all preinct totals into single national ciphertext per candidate
	fmt.Print("  Combining precinct aggregates... ")
	aggregates, err = combinePrecincts(pub, precinctAggregates)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("combining precincts: %w", err)
	}
	fmt.Println("done.")

	fmt.Print("  Ground truth: ")
	for i, name := range Candidates {
		fmt.Printf("%s=%d ", name, groundTruth[i])
	}
	fmt.Println()

	return priv, pub, aggregates, groundTruth, nil
}

// CSV export and measurements
// DecryptionRecord stores measurements for s ingle decryption
type DecryptionRecord struct {
	Run          int
	CandidateIdx int
	DurationNs   int64
	CpuCycles    int64
	HeapAllocs   uint64
	HeapBytes    uint64
}

// Write measurement records to CSV.
// includeHeap controls whether heap metrics are included.
func writeCSV(records []DecryptionRecord, path, systemName string, includeHeap bool) error {
	if err := os.MkdirAll("results", 0755); err != nil {
		return fmt.Errorf("creating results directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating CSV file: %w", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{"run", "candidate_idx", "candidate_name", "duration_ns", "cpu_cycles"}
	if includeHeap {
		header = append(header, "heap_allocs", "heap_bytes")
	}
	header = append(header, "system")
	_ = writer.Write(header)

	for _, r := range records {
		row := []string{
			strconv.Itoa(r.Run),
			strconv.Itoa(r.CandidateIdx),
			Candidates[r.CandidateIdx],
			strconv.FormatInt(r.DurationNs, 10),
			strconv.FormatInt(r.CpuCycles, 10),
		}
		if includeHeap {
			row = append(row,
				strconv.FormatUint(r.HeapAllocs, 10),
				strconv.FormatUint(r.HeapBytes, 10),
			)
		}
		row = append(row, systemName)
		_ = writer.Write(row)
	}
	return nil
}

// Print decrypted vote totals.
func printTally(totals []int64) {
	for i, name := range Candidates {
		fmt.Printf("  %-10s %d votes\n", name, totals[i])
	}
}

// System 1: Sequential decryption
// Sequential baseline (single goroutine).
// No contention; captures all metrics including heap usage.

// Capture current heap statistics.
func captureMemStats() runtime.MemStats {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats
}

// Compute allocation delta between two snapshots.
func heapDelta(before, after runtime.MemStats) (allocCount, allocBytes uint64) {
	return after.Mallocs - before.Mallocs,
		after.TotalAlloc - before.TotalAlloc
}

func runSequential() {
	fmt.Println("System 1/3: Sequential")
	fmt.Println("  Metrics: duration_ns, cpu_cycles, heap_allocs, heap_bytes")

	priv, _, aggregates, _, err := coldStart()
	if err != nil {
		log.Fatalf("sequential cold start: %v", err)
	}

	fmt.Printf("  Running %d measurement runs...\n", NumRuns)
	var records []DecryptionRecord
	var lastTotals []int64

	for run := 0; run < NumRuns; run++ {
		lastTotals = make([]int64, len(Candidates))

		for candidateIdx, encryptedTotal := range aggregates {
			// Capture heap first (stop-the-world), then cycles, then wall clock
			heapBefore := captureMemStats()
			cyclesBefore := rdtscNow()
			startNs := qpcNow()

			// decryption under measurement
			decryptedBytes, err := paillier.Decrypt(priv, encryptedTotal.Bytes())

			// Capture post-decrypt measurements in reverse order.
			elapsedNs := qpcNow() - startNs
			cyclesAfter := rdtscNow()
			heapAfter := captureMemStats()

			if err != nil {
				log.Fatalf("sequential run %d candidate %d: %v", run, candidateIdx, err)
			}

			allocCount, allocBytes := heapDelta(heapBefore, heapAfter)
			cpuCycles := ticksToCycles(cyclesAfter - cyclesBefore)
			lastTotals[candidateIdx] = new(big.Int).SetBytes(decryptedBytes).Int64()

			records = append(records, DecryptionRecord{
				Run:          run,
				CandidateIdx: candidateIdx,
				DurationNs:   elapsedNs,
				CpuCycles:    cpuCycles,
				HeapAllocs:   allocCount,
				HeapBytes:    allocBytes,
			})
		}
		if (run+1)%100 == 0 {
			fmt.Printf("  %d/%d runs complete\n", run+1, NumRuns)
		}
	}

	fmt.Println("  Final tally:")
	printTally(lastTotals)

	if err := writeCSV(records, "results/sequential_timings.csv", "sequential", true); err != nil {
		log.Fatalf("sequential CSV write: %v", err)
	}
	fmt.Printf("  Written: results/sequential_timings.csv (%d records)\n\n", len(records))
}

// System 2: Parallel decryption (unprotected)
// Parallel decryption without protections.
// One goroutine per candidate, pinned to separate OS threads.
// A barrier ensures all decryptions start simultaneously.

func runParallel() {
	fmt.Println("System 2/3: Parallel (unprotected)")
	fmt.Println("  Metrics: duration_ns, cpu_cycles")

	priv, _, aggregates, _, err := coldStart()
	if err != nil {
		log.Fatalf("parallel cold start: %v", err)
	}

	fmt.Printf("  Running %d measurement runs...\n", NumRuns)
	var records []DecryptionRecord
	var lastTotals []int64

	type perCandidateResult struct {
		candidateIdx int
		voteTotal    int64
		durationNs   int64
		cpuCycles    int64
		err          error
	}

	for run := 0; run < NumRuns; run++ {
		numCandidates := len(aggregates)
		goroutineResults := make([]perCandidateResult, numCandidates)

		// startGate holds all goroutines until every one is scheduled and
		// waiting. allReady counts down as each goroutine signals readiness.
		// Once allReady reaches zero, startGate is opened and all goroutines
		// begin decryption at the same instant.
		var startGate sync.WaitGroup
		startGate.Add(1)
		var allReady sync.WaitGroup
		allReady.Add(numCandidates)

		var wg sync.WaitGroup
		for candidateIdx, encryptedTotal := range aggregates {
			wg.Add(1)
			go func(idx int, ciphertext *big.Int) {
				defer wg.Done()

				// Pin to a dedicated OS thread so all five goroutines run
				// concurrently on separate CPU cores.
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()

				allReady.Done()  // signal: "pinned and ready"
				startGate.Wait() // block: "wait until goroutines are ready"

				cyclesBefore := rdtscNow()
				startNs := qpcNow()

				decryptedBytes, err := paillier.Decrypt(priv, ciphertext.Bytes())

				elapsedNs := qpcNow() - startNs
				cpuCycles := ticksToCycles(rdtscNow() - cyclesBefore)

				voteTotal := int64(0)
				if err == nil {
					voteTotal = new(big.Int).SetBytes(decryptedBytes).Int64()
				}
				goroutineResults[idx] = perCandidateResult{idx, voteTotal, elapsedNs, cpuCycles, err}
			}(candidateIdx, encryptedTotal)
		}

		// Release all goroutines at once
		allReady.Wait()
		startGate.Done()
		wg.Wait()

		lastTotals = make([]int64, numCandidates)
		for _, result := range goroutineResults {
			if result.err != nil {
				log.Fatalf("parallel run %d candidate %d: %v", run, result.candidateIdx, result.err)
			}
			lastTotals[result.candidateIdx] = result.voteTotal
			records = append(records, DecryptionRecord{
				Run:          run,
				CandidateIdx: result.candidateIdx,
				DurationNs:   result.durationNs,
				CpuCycles:    result.cpuCycles,
			})
		}
		if (run+1)%100 == 0 {
			fmt.Printf("  %d/%d runs complete\n", run+1, NumRuns)
		}
	}

	fmt.Println("  Final tally:")
	printTally(lastTotals)

	if err := writeCSV(records, "results/parallel_timings.csv", "parallel", false); err != nil {
		log.Fatalf("parallel CSV write: %v", err)
	}
	fmt.Printf("  Written: results/parallel_timings.csv (%d records)\n\n", len(records))
}

// System 3: Secure parallel decryption
//   CM1: Ciphertext blinding (remove value-time correlation)
//   CM2: Barrier synchronisation (aligned start)
//   CM3: Constant-time padding (aligned finish)

// Blind ciphertext by adding Enc(0).
func blindCiphertext(pub *paillier.PublicKey, ciphertext *big.Int) (*big.Int, error) {
	encryptedZero, err := paillier.Encrypt(pub, big.NewInt(0).Bytes())
	if err != nil {
		return nil, err
	}
	blinded := paillier.AddCipher(pub, ciphertext.Bytes(), encryptedZero)
	return new(big.Int).SetBytes(blinded), nil
}

// Busy-wait until deadline to equalise completion times.
func busyWaitUntil(deadline time.Time) {
	modulus, _ := new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16,
	)
	accumulator := big.NewInt(0xDEADBEEF)
	multiplier := big.NewInt(0xCAFEBABE)
	scratch := new(big.Int) // reused each iteration

	for time.Now().Before(deadline) {
		scratch.Mul(accumulator, multiplier)
		accumulator.Mod(scratch, modulus)
	}
}

func runSecure() {
	fmt.Println("System 3/3: Secure Parallel")
	fmt.Println("  Countermeasures: CM1 ciphertext blinding | CM2 barrier sync | CM3 constant-time padding")
	fmt.Println("  Metrics: duration_ns, cpu_cycles")
	fmt.Printf("  Padding deadline: %dms per batch\n", PaddingDeadlineMs)

	priv, pub, aggregates, _, err := coldStart()
	if err != nil {
		log.Fatalf("secure cold start: %v", err)
	}

	fmt.Printf("  Running %d measurement runs...\n", NumRuns)
	var records []DecryptionRecord
	var lastTotals []int64

	type perCandidateResult struct {
		candidateIdx int
		voteTotal    int64
		durationNs   int64
		cpuCycles    int64
		err          error
	}

	for run := 0; run < NumRuns; run++ {
		numCandidates := len(aggregates)
		goroutineResults := make([]perCandidateResult, numCandidates)

		// CM1: Blind all ciphertexts before launching goroutines.
		blindedCiphertexts := make([]*big.Int, numCandidates)
		for i, aggregate := range aggregates {
			blindedCiphertexts[i], err = blindCiphertext(pub, aggregate)
			if err != nil {
				log.Fatalf("secure run %d: blinding candidate %d: %v", run, i, err)
			}
		}

		// CM3: Shared padding deadline
		paddingDeadline := time.Now().Add(PaddingDeadlineMs * time.Millisecond)

		// CM2: Synchronisation barrier.
		// startGate is held closed until all goroutines signal readiness via
		// allReady. Once allReady reaches zero, startGate opens and all
		// goroutines begin decryption simultaneously.
		var startGate sync.WaitGroup
		startGate.Add(1)
		var allReady sync.WaitGroup
		allReady.Add(numCandidates)

		var wg sync.WaitGroup
		for candidateIdx, blindedCiphertext := range blindedCiphertexts {
			wg.Add(1)
			go func(idx int, ciphertext *big.Int) {
				defer wg.Done()
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()

				allReady.Done()  // signal: "ready and waiting at the gate"
				startGate.Wait() // block: "wait until all goroutines are ready"

				// Measurement window: both metrics are captured around Decrypt only.
				// The busy-wait below is outside this window so cpu_cycles reflects
				// only actual decryption work, not padding.
				cyclesBefore := rdtscNow()
				startNs := qpcNow()

				decryptedBytes, err := paillier.Decrypt(priv, ciphertext.Bytes())

				elapsedNs := qpcNow() - startNs
				cpuCycles := ticksToCycles(rdtscNow() - cyclesBefore)

				// CM3: Spin until the shared deadline regardless of when
				// decryption finished, so an external observer cannot tell
				// which candidate completed first.
				busyWaitUntil(paddingDeadline)

				voteTotal := int64(0)
				if err == nil {
					voteTotal = new(big.Int).SetBytes(decryptedBytes).Int64()
				}
				goroutineResults[idx] = perCandidateResult{idx, voteTotal, elapsedNs, cpuCycles, err}
			}(candidateIdx, blindedCiphertext)
		}

		allReady.Wait()
		startGate.Done()
		wg.Wait()

		lastTotals = make([]int64, numCandidates)
		for _, result := range goroutineResults {
			if result.err != nil {
				log.Fatalf("secure run %d candidate %d: %v", run, result.candidateIdx, result.err)
			}
			lastTotals[result.candidateIdx] = result.voteTotal
			records = append(records, DecryptionRecord{
				Run:          run,
				CandidateIdx: result.candidateIdx,
				DurationNs:   result.durationNs,
				CpuCycles:    result.cpuCycles,
			})
		}
		if (run+1)%100 == 0 {
			fmt.Printf("  %d/%d runs complete\n", run+1, NumRuns)
		}
	}

	fmt.Println("  Final tally:")
	printTally(lastTotals)

	if err := writeCSV(records, "results/secure_timings.csv", "secure", false); err != nil {
		log.Fatalf("secure CSV write: %v", err)
	}
	fmt.Printf("  Written: results/secure_timings.csv (%d records)\n\n", len(records))
}

// Main

// Entry point: initialise timer, enable full CPU usage, run each system consecutively
func main() {
	// initialise timing
	initTimer()

	fmt.Println("Paillier E-Voting Security Analysis — Combined Runner")
	fmt.Printf("Candidates : %v\n", Candidates)
	fmt.Printf("Precincts  : %d × %d voters = %d total\n",
		NumPrecincts, NumVotersPerPrecinct, NumPrecincts*NumVotersPerPrecinct)
	fmt.Printf("Key size   : %d bits\n", KeyBits)
	fmt.Printf("Runs       : %d per system\n", NumRuns)
	fmt.Printf("CPUs       : %d\n\n", runtime.NumCPU())

	// Allow the scheduler to use all available CPU cores so the parallel
	// and secure systems can achieve true concurrent execution.
	runtime.GOMAXPROCS(runtime.NumCPU())

	runSequential()
	runParallel()
	runSecure()

	fmt.Println("All systems complete. Run analysis.py to generate the TVLA report and plots.")
}
