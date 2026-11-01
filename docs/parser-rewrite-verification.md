# Parser rewrite verification — 2026-10-30

The Content/Builder rewrite and all seven native migrations are implemented
locally. This record supersedes the earlier bounded [Hillstone refinement
record](parser-verification.md) for the current code. The design and intentional
low-level API migration are described in [parser design](parser-design.md).

## Behavioral evidence

- Frozen baseline: the entire pre-rewrite worktree, including the preceding
  uncommitted Hillstone changes. Git HEAD remained
  `19d1fb999feb63a2f5cf7c2450dec1e7e63da01a`.
- Seven-vendor canonical graph comparison: synthetic ten-rule captures compare
  every exported record, source span/state, diagnostic and ordering field. Only
  ParserVersion is normalized. All seven match before and after snapshot
  encode/decode. Original and restored semantic digests match.
- Six actual-Perl oracles: Hillstone, Huawei, Fortinet, SRX, Netscreen and ASA all
  match resolved named addresses/groups, TCP destination ports, interface/zone
  binding and explicit policy selectors. ASA includes ACL binding. The Perl
  runner independently checks defer/rewind. The Go test repeats the projections
  after snapshot restoration. Fixtures, runner and expected results are in
  `vendors/testdata/perl`; no private implementation source is copied.
- The reference used Perl 5.44.0 in the locally available container image
  `sha256:01405e21111b41c379e6f75d1aaf82cb56ee0b0908faae82c6aabb247b18e609`,
  with networking disabled and source/input mounts read-only. The final adopted
  verification script was rerun against the rewritten checkout successfully.
- New Builder tests cover duplicate-ID rejection before source consumption,
  explicit replacement preserving order, nested rollback, identity-index cleanup,
  transaction phase lifetime, copy isolation and evidence-only cache invalidation.
  The duplicate-ID defect was observed failing against the old implementation.
- Existing native tests retain scoped unknowns, forward references, route binding,
  service pairing, rule/NAT order, policy-owned NAT, query/packet behavior,
  planning, rendering and independent readback. No graph or snapshot schema changed.

The Perl oracle is bounded: it does not prove NAT parity, source-port pairing,
schedules, all VDOM/VRF contexts, arbitrary firmware or real-device behavior.
Palo Alto has no supplied Perl parser; its native XML/set and exact-byte evidence
continue to be validated by Go tests. Go retains structural isolation where the
Perl line dispatcher can mistake an unindented Hillstone rule member for a
standalone service declaration.

## Local checks

| Check | Result |
| --- | --- |
| Root `GOWORK=off GOPROXY=off go test -race ./...` | PASS, 25 test-bearing packages |
| Root `go vet ./...`, `go build ./...`, `go mod verify` | PASS |
| Go 1.26.0 `go test ./config ./vendors/...` | PASS |
| Adapter with pinned published core, `GOWORK=off` race tests | PASS |
| Adapter against current core via temporary go.work: race, vet, build | PASS |
| Content/statement/XML ownership fuzz, 30 seconds | PASS, 44,158 executions |
| Fortinet scoped capture fuzz, 10 seconds | PASS, 32,082 executions |
| Huawei scoped capture fuzz, 10 seconds | PASS, 30,610 executions |
| Netscreen scoped capture fuzz, 10 seconds | PASS, 46,235 executions |
| Independent code review and focused correction review | PASS, no unresolved concrete findings |

The adapter remains pinned to its existing published dependencies. Only its
synthetic XML fixture helper changed to use standard-library tokenization, so
it no longer requires the old or new parser construction API. Current-core
integration was explicitly tested with a temporary workspace; this is separate
from published-version compatibility and is not release evidence.

## Performance

Apple M5, darwin/arm64, Go 1.27.1, GOMAXPROCS=4. Ten paired 200ms samples used
alternating serial before/after binaries, covering seven vendors at 10/100/1000
rules, XML, scanning and a 500-interface/1000-policy Fortinet case. The last pair
was rerun after concurrent adapter verification ended; the decision and method
are recorded with the raw evidence.

Representative 1000-rule median changes:

| Vendor | Time | Allocated bytes | Allocation count |
| --- | ---: | ---: | ---: |
| Hillstone | -30.1% | -25.5% | -31.9% |
| Huawei | -8.3% | -5.1% | -17.5% |
| Palo Alto | -8.4% | -7.9% | -12.3% |
| SRX | -7.5% | -10.7% | -14.6% |
| Fortinet | -3.9% | -3.5% | -15.0% |
| ASA | -3.1% | -5.0% | -14.4% |
| Netscreen | -0.5% | +3.5% | -4.9% |

Netscreen's 1000-rule timing difference was not statistically established; its
smallest capture has a modest measured slowdown, below the 5% gate. Added typed
indexes and safe catalog views have a small allocation-byte cost for this vendor.
No workload had a statistically significant time regression above 5%.

Review caught an important regression hidden by the two-interface rule matrix:
copying the interface table inside each Fortinet policy made the large-topology
case 4.49 times slower and allocated 6.74 times as many bytes. The fix captures
one read-only view per phase and uses indexed lookups for individual references.
The final ten-pair topology benchmark has effectively unchanged timing
(-1.6%, not statistically established), -3.1% allocated bytes and -12.5%
allocation count. It is retained in `benchmarks/topology_bench_test.go`.

Full measurements, method, binary/source hashes, review and test logs are in
[the evidence directory](benchmarks/2026-10-30-parser-rewrite/README.md).
Statistics are exploratory paired comparisons; synthetic timings are not device
throughput or production capacity measurements.

## Delivery and compatibility

Business Parse/Source/Limits entry points, concrete graph and snapshot format 9
remain. Cursor/Session/Stage and their low-level transaction construction APIs
were deliberately replaced, without aliases. All seven ParserVersion strings
advance. Existing snapshots load without reinterpreting raw text; reimport and
regenerate plans to use new parsing. Complete pending deployment recovery under
its original parser version before upgrading.

Work is uncommitted in the existing feature worktree. No commit, push, CI run,
release or device operation was performed for this rewrite.
