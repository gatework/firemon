# Parser refinement verification — 2026-10-30

Local base: `19d1fb999feb63a2f5cf7c2450dec1e7e63da01a`, existing linked
`feat/go-firewall` worktree. The implementation is uncommitted. The Perl and Ruby
reference worktrees were not changed. This work did not push, publish a release,
run remote CI or access a real device.

## Correctness evidence

- A fresh `GOWORK=off GOPROXY=off go test -count=1 ./...` passed before editing.
- The initial mechanical split preserved all 26 original non-import
  declarations byte for byte; targeted Hillstone/policy/plan tests and vet passed.
- New regressions failed on the frozen baseline for duplicate object identity,
  lost mixed literal/group members, empty reopening type overwrite and silently
  accepted header suffixes. The baseline mixed-member case reported a complete
  graph while resolving only `192.0.2.20`, omitting `192.0.2.10`.
- The actual Perl 5.44.0 Content and Hillstone Parser ran with read-only source
  mounts, no network and synthetic input. Output matches the checked-in oracle
  JSON. The Go regression checks the same domain results before and after
  snapshot archive/load; the local reference source hashes remained unchanged.
- Independent review identified service/group lookup precedence as another
  reference check. Both declaration orders ran against the actual Perl parser;
  the consuming group consistently selected the declared service. A separate
  Go regression failed before the fix and passed after it. The follow-up
  independent review found no blocking issues.
- `GOWORK=off GOPROXY=off go test -race -count=1 ./...` passed all 25 packages
  containing tests. `go vet ./...`, `go build ./...` and `go mod verify` passed
  under the same standalone module environment, with Go 1.27.1 on darwin/arm64.
- Existing synthetic samples for all seven vendors retained byte-identical JSON
  exports and semantic digests after normalizing only ParserVersion to the same
  value. Raw text, source evidence, declarations and diagnostic state otherwise
  participate in that comparison. The Hillstone sample intentionally retains
  its pre-existing unknown allocation mode; this comparison is not a claim that
  every sample is complete.

The new tests also cover first-seen object order, accepted source spans, forward
references, unknown members, scope conflicts, truncated reopenings and malformed
nested wrapper isolation. Existing root tests exercise transaction/stage
rollback, parser limits, immutable references, query/planning and snapshots.

The independent review traced source claims, draft ownership, cancellation,
reference binding and snapshot/plan compatibility. Schedule reopening, predefined
services, FQDN resolution and broader NAT/PBR syntax remain existing capability
limits. The existing policy rule-ID/context design was not extended by the
named-object aggregation; it warrants separate native identity fixtures before
changing that contract.

## Performance check

Both executables use identical existing `BenchmarkParse` workloads, the same Go
toolchain, Apple M5 and GOMAXPROCS=4. Ten serial samples alternate before/after
order, with 200 ms per case. The baseline is an archive of the recorded commit;
its production code is unchanged. Huawei is an unchanged control.

| Hillstone synthetic workload | Allocation bytes/op before → after | Allocation count change |
| --- | --- | --- |
| 10 rules | 361.9 KiB → 343.7 KiB (−5.02%) | −3.68% |
| 100 rules | 3.382 MiB → 3.279 MiB (−3.05%) | −3.82% |
| 1,000 rules | 40.86 MiB → 39.99 MiB (−2.13%) | −3.90% |

These reductions include removing the unused full draft copy, offset by named
definition bookkeeping. The final 10/1,000-rule timings decreased 1.37%; the
100-rule timing and unchanged Huawei control differences were not statistically
significant. An earlier development run was noisy; the recorded final samples
were rerun after the service-precedence correction. These are small local
synthetic differences, not a production throughput or capacity claim.

Raw samples, benchstat output, baseline failure log, full race log, source
identities, fixture comparison tool/results and checksums are retained under
[`benchmarks/2026-10-30-parser`](benchmarks/2026-10-30-parser/metadata.json).
`measure.py` uses the two separately compiled test executables in its directory;
compile the baseline and candidate with `go test -c -o <path> ./benchmarks`
before rerunning it. `fixture_probe.go` uses the seven existing test fixtures and
the retained synthetic Huawei fixture; adjust its local fixture path when
running outside the original evidence directory.

## Compatibility and limits

`hillstone-go-3` deliberately changes parser identity and thus semantic digests.
Snapshot semantic format 9 and the public Go API remain unchanged. Existing
snapshots remain readable without reparse. Use a fresh import and newly created
plan for corrected parsing; complete pending recovery with the prior parser
before switching versions.

Only Hillstone production parsing changed. Other native parsers were inspected
for responsibility and scope differences and checked by existing regression
tests; this is not a complete syntax audit of every firmware. The optional
nested netconnector adapter still pins its published core version and was not
changed or represented as validation of this uncommitted core. The Perl oracle
proves the documented synthetic case, not general vendor equivalence.
