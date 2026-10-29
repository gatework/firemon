# Benchmark matrix

The 2026-10-29 measurements use synthetic complete native captures and the public Go APIs. They cover 75 cases, each measured six times serially on Go 1.27.1, darwin/arm64, Apple M5, 16 GiB RAM, with `GOMAXPROCS=1`. The module's minimum Go version remains 1.26. Setup is outside `b.Loop`; each timed operation checks its result. No device, database, transport or concurrent throughput is measured.

Run from the repository root:

```sh
GOWORK=off GOPROXY=off go test ./benchmarks
GOWORK=off GOPROXY=off go test ./benchmarks -run '^$' -bench . \
  -benchtime=100ms -count=6 -cpu=1 > bench.txt
benchstat bench.txt
```

The report uses `golang.org/x/perf/cmd/benchstat` at `v0.0.0-20261009192801-be2c69fb417e`, installed outside the root module. Use the same Go toolchain and hardware when comparing changes; these short local samples are a baseline, not a production latency guarantee or a CI performance gate.

| Operation | Workload |
| --- | --- |
| Parse | All seven vendors; 10, 100 and 1000 address objects and ordered policies, one shared TCP service, interfaces and zones |
| Query | The same seven captures; a single request reaches the last explicit permit; ASA ACL and Fortinet VDOM context supplied explicitly |
| NAT and packet path | Huawei, 10/100/1000 source-NAT policies and security policies; match the last rule, retain possible PAT allocation, include routing and policy evaluation for packet queries |
| Snapshot encode/decode | Huawei 10/100/1000-rule graph, retained source and evidence; encode to `io.Discard`, decode from memory and compare semantic digest; excludes file I/O and fsync |
| Planning | Reuse at 10/100/1000 rules; create at 10/100 rules with a gap that cannot safely expand existing declarations; includes candidate construction, full proof and native rendering |
| Traffic algebra | Union/intersection/difference of 16 and 128 paired regions, IPv4 and IPv6 |
| Request optimization | 10 and 100 requests; adjacent ranges coalesce, paired source/destination requests remain separate |

Final medians for the 1000-rule native captures, measured again after the PAN interface-selection and route-identity corrections (snapshot semantic format 8):

| Vendor | Parse | Parse allocation | Last-rule query |
| --- | ---: | ---: | ---: |
| ASA | 33.245 ms | 166.766 MiB/op | 1.071 ms |
| Fortinet | 14.154 ms | 48.492 MiB/op | 1.674 ms |
| Hillstone | 14.284 ms | 39.171 MiB/op | 1.378 ms |
| Huawei | 12.753 ms | 41.405 MiB/op | 1.423 ms |
| Netscreen | 13.695 ms | 28.755 MiB/op | 1.235 ms |
| Palo Alto | 17.514 ms | 39.899 MiB/op | 1.319 ms |
| SRX | 12.820 ms | 28.439 MiB/op | 1.376 ms |

Allocation is cumulative heap allocation per operation, not peak memory. Captures have comparable object counts but different native grammar, byte sizes and default policy behavior; these numbers do not rank device products. The 1000-rule snapshot median is 2.401 ms to encode and 5.900 ms to decode, excluding disk durability work. All 75 cases and 450 samples passed in this final run; its [raw results](benchmarks/2026-10-29-final.txt) are retained separately from the planner comparison below.

## Planning correction found by measurement

The original planner built and fully proved every append candidate, including obvious changes outside the request. A CPU/heap profile of the 100-rule create case attributed over 99% of allocated bytes to full proofs, mainly repeated traffic difference/union during policy evaluation. It also exhausted a one-combination budget on an impossible append before reaching the valid new-rule alternative.

The planner now queries the immutable baseline once. For ordinary ordered chains, it rejects an append only if the expanded match takes traffic outside the request from a later rule or unmatched traffic. Earlier effective ownership is subtracted first, so shadowed cross pairs remain eligible. FortiOS VIP lookup retains its full native proof path. Every surviving candidate still receives the complete target/outside-preservation proof and native renderer checks.

| Create workload | Before | After | Time change | Allocated bytes before / after |
| --- | ---: | ---: | ---: | ---: |
| 10 rules | 19.709 ms | 2.708 ms | -86.26% | 56.969 / 7.768 MiB |
| 100 rules | 15.156 s | 228.995 ms | -98.49% | 43047.2 / 625.4 MiB |

Both time differences have `p=0.002`, `n=6`. The large remaining allocation for creation is visible; no 1000-rule creation, adversarial region explosion, peak-RSS or production SLA claim is made. Existing limits still bound candidate visits, plan combinations and traffic regions.

The before runtime is commit `ccc3430`; benchmark sources are captured by `2a43b85` (the only subsequent fixture edit was a comment). The after runtime is `fdcec7b`, which adds the planner correction. Raw [before](benchmarks/2026-10-29-before.txt), [after](benchmarks/2026-10-29-after.txt) and [benchstat comparison](benchmarks/2026-10-29-plan-comparison.txt) are retained. The subsequent final run measured 2.658 ms / 7.769 MiB for 10-rule creation and 227.605 ms / 625.359 MiB for 100-rule creation; it is not substituted into the earlier statistical comparison. Reproduce that comparison with:

```sh
benchstat -filter '.name:Plan .fullname:/create/' \
  docs/benchmarks/2026-10-29-before.txt docs/benchmarks/2026-10-29-after.txt
```


## Domain refactor measurements (2026-10-29)

The e9e9b96 baseline binary and b47e97e result used Go 1.27.1, darwin/arm64,
Apple M5, `-test.cpu=1 -test.benchtime=100ms -test.count=6`, run serially without
concurrent tests. The complete matrix retains 75 comparable workloads and adds
8 lifecycle workloads (convergence, risk and shared-group member usage).

| Workload | Before | After | Allocation change |
| --- | --- | --- | --- |
| ASA parse, 1,000 rules | 37.25 ms; 190.89 MiB | 11.28 ms; 24.68 MiB | -87.07% bytes/op |
| Huawei query, 1,000 rules | 1.495 ms; 2.036 MiB | 1.325 ms; 1.658 MiB | -18.57% bytes/op |
| Create plan, 100 rules | 232.16 ms; 627.2 MiB | 85.19 ms; 119.3 MiB | -80.99% bytes/op |
| Huawei packet, 1,000 rules | 4.373 ms; 6.202 MiB | 3.897 ms; 5.444 MiB | -12.22% bytes/op |

Allocation profiling attributed the ASA hotspot to literal address-directory
clones and planning primarily to repeated traffic subtraction allocations. The
changes index literal identities, transfer owned parse drafts, reuse bounded
query expansions, avoid record cloning during sorting, and reuse exact difference
buffers. They do not remove proof, resource charging or unknown evidence.

Raw evidence: [before](benchmarks/2026-10-29-refactor-before.txt),
[after](benchmarks/2026-10-29-refactor-after.txt),
[benchstat comparison](benchmarks/2026-10-29-refactor-comparison.txt).
An earlier run overlapping compilation/tests was discarded.

The full serial run showed timing increases in otherwise unchanged snapshot
encoding and several small native workloads. A counterbalanced follow-up alternated
before/after execution order for each of six samples, using the same frozen
binaries. It found no significant snapshot, NAT, SRX or large PAN timing regression:
[control before](benchmarks/2026-10-29-refactor-controls-before.txt),
[control after](benchmarks/2026-10-29-refactor-controls-after.txt),
[control comparison](benchmarks/2026-10-29-refactor-controls-comparison.txt).
Snapshot decoding does allocate about two additional zone-reference slices per
rule (about 3.7% more allocations at 1,000 rules) to expose the unified immutable
match view. Encoding allocations and persisted bytes remain unchanged. This is
an explicit representation cost, not a claim that every metric improves.

These are synthetic local measurements, not firmware interoperability, worst-case
latency or a service-level guarantee. Benchmarks assert their semantic results;
short timing windows remain sensitive to host load and thermal conditions.

## Contract and ownership refactor measurements (2026-10-29)

The baseline runtime is `dd15031`; the new capture-validation and route-resolution
harnesses were added to that frozen baseline without changing runtime code. Both
binaries use Go 1.27.1, darwin/arm64, Apple M5. Six serial samples alternate the
before/after execution order, with `GOMAXPROCS=1`, `-test.cpu=1` and
`-test.benchtime=100ms`. All 87 cases passed all six samples for both binaries.
No tests or builds ran during measurement. Each benchmark validates its result.

The full matrix contains the existing 83 workloads plus capture validation at
10/1,000 rules and route resolution at 10/1,000 routes. Capture validation starts
with an already parsed retained graph; it excludes parsing, device I/O and
publication. Route resolution partitions a synthetic /16 across the configured
/32 routes and the unmatched remainder, with native interface/zone evidence.

| Workload | Before | After | Allocation change |
| --- | --- | --- | --- |
| Validate retained capture, 1,000 rules | 346.412 µs; 1.383 MiB; 7,015 allocations | 17.94 ns; 0 bytes; 0 allocations | Removes a defensive full-graph clone used only to compare raw text |
| Declared risk, 100 rules | 129.6 µs; 201.4 KiB; 2,913 allocations | 115.3 µs; 174.8 KiB; 2,413 allocations | -13.19% bytes; -17.16% allocations |
| Effective risk, 100 rules | 152.3 µs; 241.8 KiB; 3,134 allocations | 131.3 µs; 215.3 KiB; 2,634 allocations | -10.98% bytes; -15.95% allocations |

Those timing differences have `p=0.002`, `n=6`. Capture validation still checks
metadata and exact retained text; an invalid or substituted result remains
incomplete/error. The nanosecond result measures that narrow retained-graph
validation path and is not configuration parsing throughput.

The full matrix initially exposed a route-buffer allocation cost: at 1,000 routes,
time fell 18.86% and allocation count fell 33.12%, but bytes increased 5.61%.
Inspection found a remaining interface-record clone used only for flags. Replacing
it with `Disabled`/`HasUnsupported` completed the scalar-read migration. The final
runtime is `02977bc` (later import grouping does not change runtime behavior).
Only the affected route and packet cases were remeasured, again with six
counterbalanced serial samples:

| Final route workload | Before | After | Change |
| --- | --- | --- | --- |
| 10 routes | 4.436 µs; 7,168 bytes; 126 allocations | 3.303 µs; 7,232 bytes; 90 allocations | -25.54% time; +64 bytes; -28.57% allocations |
| 1,000 routes | 643.2 µs; 1,027.5 KiB; 16,398 allocations | 480.9 µs; 991.3 KiB; 8,965 allocations | -25.23% time; -3.52% bytes; -45.33% allocations |

The 1,000-route timing change has `p=0.002`; the smaller case has `p=0.041` and a
±37% after-sample uncertainty, so its timing is less stable. Cached route keys and a
bounded stable merge buffer retain declaration order and responsive cancellation.
The 64-byte small-case increase is an explicit representation cost. Final packet
timings, full-matrix parser/query/planning/convergence timings, and snapshot
controls showed no statistically significant timing regression in these samples.
No general production, peak-memory or firmware-capacity claim follows.

Raw full-matrix [before](benchmarks/2026-10-29-contracts-before.txt),
[after](benchmarks/2026-10-29-contracts-after.txt) and
[comparison](benchmarks/2026-10-29-contracts-comparison.txt) retain the initial
route result. The final [route/packet before](benchmarks/2026-10-29-contracts-route-before.txt),
[after](benchmarks/2026-10-29-contracts-route-after.txt) and
[comparison](benchmarks/2026-10-29-contracts-route-comparison.txt) supersede only
those affected rows. These are separate measurements, not merged samples.

## Prepared risk expressions (2026-10-29)

Baseline `8340b50` includes the corrected layered budgets and aggregate standard
region limit. Six counterbalanced serial samples per binary use Go 1.27.1,
Darwin/arm64 Apple M5, `-benchtime=100ms`, with 10/100/1,000 rules and 1/4/16
expression leaves in declared/effective modes. Allocation profiling of the
1,000-rule, 16-leaf declared case attributed 92.74% of allocated bytes to recursive
expression assessment (including repeated match/projection); CPU sampling was too
noisy for a precise CPU attribution. Standards are now prepared once per call and
dimension projections once per rule, with no global cache.

At 1,000 rules and 16 leaves, declared assessment fell from 26.090 ms to 7.217 ms
(-72.34%), 43.14 MiB to 10.16 MiB (-76.45%), and 480,100 to 114,100 allocations.
Effective assessment fell from 33.47 ms to 29.86 ms (-10.79%), with bytes down
13.96%. Both timing differences have p=0.002, n=6. Ordinary paired-risk and
convergence controls show no significant timing regression, and ordinary risk
allocations are unchanged. Initial testing exposed a counter pointer escaping
onto the heap; value-owned evaluation state removed that extra allocation before
this final measurement.

Raw [before](benchmarks/2026-10-29-risk-before.txt),
[after](benchmarks/2026-10-29-risk-after.txt) and
[comparison](benchmarks/2026-10-29-risk-comparison.txt) are retained. The separate
[original baseline](benchmarks/2026-10-29-computation-original.txt) predates the
budget corrections: ordinary risk allocations remain equal and convergence bytes
fell about 0.4%. Its timing uncertainty reached 82%, so it does not establish the
CPU overhead of correctness checks and is not mixed into the performance result.
These synthetic measurements establish neither real-device capacity nor peak RSS.

## Cancellable scanning (2026-10-29)

Six counterbalanced serial samples compare `67fcb6f` with the cancellable scanner,
using the same host, Go version and 100 ms sample duration as the risk experiment.
Short CLI scanning increased from 24.98 to 26.56 µs (+6.34%); the 576 KiB quoted
UTF-8 line increased from 1.483 to 1.634 ms (+10.17%), both p=0.002. These are the
measured costs of bounded validation and scan checkpoints, retained to support
prompt cancellation. Multiline scanning was not significantly changed.

Full Huawei parsing at 100 rules increased 0.84% (p=0.041); 10/1,000-rule Huawei
and 10/1,000-address PAN XML cases had no significant timing change. These scanner
measurements are correctness overhead, not a performance improvement claim.
Raw [before](benchmarks/2026-10-29-scanning-before.txt),
[after](benchmarks/2026-10-29-scanning-after.txt) and
[comparison](benchmarks/2026-10-29-scanning-comparison.txt) include allocations.

After the independent review's pre-copy budget correction, six new counterbalanced
samples rechecked the ordinary risk controls and the 1,000-rule/16-leaf expression
cases against the same corrected-contract baseline. Declared expression time was
25.660 → 7.052 ms (-72.52%); effective time was 33.01 → 29.57 ms (-10.42%). Ordinary
risk again had no significant regression or allocation change. These [before](benchmarks/2026-10-29-risk-reviewed-before.txt),
[after](benchmarks/2026-10-29-risk-reviewed-after.txt) and
[comparison](benchmarks/2026-10-29-risk-reviewed-comparison.txt) supersede those
risk rows only; they are not merged into the earlier samples.

Candidate construction now charges catalog traversals cumulatively. The
100-rule create benchmark consequently exceeds the default 100,000 visits;
`BenchmarkPlan` explicitly uses 2,000,000 visits to retain its stress workload.
A one-iteration smoke run validates that benchmark's success, not performance.
Earlier planner timing records predate this stricter accounting.
