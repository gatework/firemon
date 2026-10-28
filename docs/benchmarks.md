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

Current medians for the 1000-rule native captures:

| Vendor | Parse | Parse allocation | Last-rule query |
| --- | ---: | ---: | ---: |
| ASA | 34.602 ms | 166.848 MiB/op | 1.073 ms |
| Fortinet | 14.893 ms | 48.914 MiB/op | 1.691 ms |
| Hillstone | 14.806 ms | 39.101 MiB/op | 1.403 ms |
| Huawei | 13.192 ms | 40.913 MiB/op | 1.429 ms |
| Netscreen | 14.338 ms | 29.301 MiB/op | 1.252 ms |
| Palo Alto | 18.290 ms | 40.227 MiB/op | 1.329 ms |
| SRX | 13.348 ms | 28.931 MiB/op | 1.384 ms |

Allocation is cumulative heap allocation per operation, not peak memory. Captures have comparable object counts but different native grammar, byte sizes and default policy behavior; these numbers do not rank device products. The 1000-rule snapshot median is 2.423 ms to encode and 5.920 ms to decode, excluding disk durability work.

## Planning correction found by measurement

The original planner built and fully proved every append candidate, including obvious changes outside the request. A CPU/heap profile of the 100-rule create case attributed over 99% of allocated bytes to full proofs, mainly repeated traffic difference/union during policy evaluation. It also exhausted a one-combination budget on an impossible append before reaching the valid new-rule alternative.

The planner now queries the immutable baseline once. For ordinary ordered chains, it rejects an append only if the expanded match takes traffic outside the request from a later rule or unmatched traffic. Earlier effective ownership is subtracted first, so shadowed cross pairs remain eligible. FortiOS VIP lookup retains its full native proof path. Every surviving candidate still receives the complete target/outside-preservation proof and native renderer checks.

| Create workload | Before | After | Time change | Allocated bytes before / after |
| --- | ---: | ---: | ---: | ---: |
| 10 rules | 19.709 ms | 2.708 ms | -86.26% | 56.969 / 7.768 MiB |
| 100 rules | 15.156 s | 228.995 ms | -98.49% | 43047.2 / 625.4 MiB |

Both time differences have `p=0.002`, `n=6`. The large remaining allocation for creation is visible; no 1000-rule creation, adversarial region explosion, peak-RSS or production SLA claim is made. Existing limits still bound candidate visits, plan combinations and traffic regions.

The before runtime is commit `ccc3430`; benchmark sources are captured by `2a43b85` (the only subsequent fixture edit was a comment). The after runtime is that tree plus the planner correction accompanying this report. Raw [before](benchmarks/2026-10-29-before.txt), [after](benchmarks/2026-10-29-after.txt) and [benchstat comparison](benchmarks/2026-10-29-plan-comparison.txt) are retained. Reproduce the comparison with:

```sh
benchstat -filter '.name:Plan .fullname:/create/' \
  docs/benchmarks/2026-10-29-before.txt docs/benchmarks/2026-10-29-after.txt
```
