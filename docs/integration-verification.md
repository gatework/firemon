# Candidate search and connector integration

## Baseline and reconciliation

The starting Go branch is `e1bafcd5e444e3b52ab89c16af8ce12ad40f9a42`.
Go repository `main` was `19d1fb999feb63a2f5cf7c2450dec1e7e63da01a`, one
ancestor commit behind. The original Go and Ruby worktrees were clean.

The `trunk/firemon` directory is a historical filesystem copy whose `.git`
pointer refers to the active Go worktree. Of its 147 source/configuration files,
141 exactly match historical commit `2bac8e2`. Six adapter files contain an
unfinished connector migration; they fail to compile with their unchanged
dependency pins. Missing files in that old copy are not proposed deletions.
The integration ports those migration intentions onto the current implementation
and also updates configuration-lock and Fortinet prompt handling. It does not
overwrite current files with the historical copies.

Both baseline modules passed uncached tests and vet on Go 1.26.0 and 1.27.1.
Those checks cover the old connector pin, not the new adapter migration.

## Contracts and dependencies

- Candidate search is private to `plan`. Single-request and policy-batch
  accounting, rejection classification, proof and reporting remain distinct.
- Discovery still precedes attempt exhaustion; creation remains lazy and only
  full proof/render attempts consume the shared batch allowance.
- Snapshot v9, approval digests, reconstruction and selection formats remain
  unchanged. Seven approved vendors remain the complete implementation scope.
- go-net-connector v0.2.0 resolves to
  `68cf112895271ffa2f6593500634c6d597d93f81`; go-expect v0.4.0 resolves to
  `80886a1198dd37ce36c00ece48a0fcf7883a3367`. Both repositories are public.
- The adapter pins published core
  `v0.0.0-20261107151352-cab273cd76e3` in `adapter/netconnector/go.mod`.
  Commit `cab273cd76e39c4932ddefe46926358e9ef1b499` was pushed to the integration
  branch before resolving and downloading the module. Its checks use
  `GOWORK=off`, without a local replacement. Current-core workspace verification
  is separate evidence.

## Verification

Local verification ran on macOS arm64 using Go 1.26.0 and Go 1.27.3. Every cell
below passed `go mod verify`, `go vet ./...`, `go test -race -count=1 ./...` and
`go build ./...` with `GOFLAGS=-mod=readonly`:

| Module mode | Go 1.26.0 | Go 1.27.3 |
| --- | --- | --- |
| Core, `GOWORK=off` | Passed | Passed |
| Adapter with published core pin, `GOWORK=off` | Passed | Passed |
| Adapter with current core in a temporary workspace | Passed | Passed |

Both standalone modules also passed `go mod tidy -diff`. The workspace check
uses the same two module directories as CI; on macOS their physical paths avoid
the `/var` to `/private/var` alias. No workspace is committed. Formatting,
`git diff --check` and `actionlint` passed. Core and adapter `govulncheck ./...`
reported no vulnerabilities using Go 1.27.3. These scans are point-in-time
checks, not claims about every supported Go toolchain.

The new behavioral checks cover discovery evidence after batch attempt
exhaustion, preflight refusal without consuming a proof attempt, retained
configuration evidence on decoding failure, rejected decoded output, and
connector-close cancellation reaching receipt callbacks. Existing tests cover
approval identity, reconstruction, native output, unknown conditions and
independent whole-device proof. All device conversations are synthetic.

Independent reviews compared `e1bafcd...b5c7a06` against repository conventions
and the approved plan:

- Standards: zero findings. The review also ran targeted planner and adapter
  tests independently.
- Spec: zero findings. It traced the connector dependency's actual API,
  discovery accounting, refusal classification and proof ownership.

The final core pin, CI and documentation were checked separately during
integration; these review results do not imply real-device verification.

The candidate-search production code is identical to the published core pin;
subsequent integration changes concern the nested adapter, CI and documentation.
Local results do not establish remote CI or real-device interoperability. The
delivery procedure requires the final integration commit's CI to pass before
fast-forwarding `main`; the Actions run remains the authoritative remote result.

## Candidate-search benchmark

Six samples per case compared `e1bafcd` with the candidate-search refactor using
Go 1.27.1 on the same Apple M5, darwin/arm64 machine. The benchmarked refactor
was committed as `358cfa5` and cherry-picked unchanged as `cab273c`.

`benchstat` found no statistically significant time difference in any measured
case. The two 10-rule cases add nine allocations per operation (0.27%) and
0.11–0.13% bytes. Allocation and byte differences in the 100-rule and batch
cases are not significant. This is a maintainability refactor, with a small
measured allocation cost; it does not claim a performance improvement.

Raw [before](benchmarks/2026-11-07-candidate-search/candidate-before.txt),
[after](benchmarks/2026-11-07-candidate-search/candidate-after.txt) and
[benchstat](benchmarks/2026-11-07-candidate-search/candidate-benchstat.txt)
results are retained. Commands, run sequentially on each source tree:

```sh
GOWORK=off GOPROXY=off go test -run '^$' -bench 'BenchmarkPlanCandidates' -benchmem -count=6 -benchtime=200ms ./plan
GOWORK=off GOPROXY=off go test -run '^$' -bench 'BenchmarkBusinessPlanBatchAddition/rules=1000$/requests=' -benchmem -count=6 -benchtime=200ms ./benchmarks
benchstat candidate-before.txt candidate-after.txt
```

The tool was `golang.org/x/perf v0.0.0-20261009192801-be2c69fb417e`, built with
Go 1.27.1. No CPU override was supplied; benchmark names record concurrency 10.

## Continuous integration

At this integration baseline the CI workflow checked core, adapter-pinned and
adapter-current on Go 1.26.0 and 1.27.x with module verification, vet, uncached
race tests and builds. Fixed module
jobs also check tidy output; only the adapter-current jobs create a temporary
workspace. Formatting uses Go 1.27.x. Dependabot monitors the nested adapter
module as well as the root module and GitHub Actions.

The subsequent [Go 1.27 update](2026-11-07-go127-verification.md) raises the
minimum to 1.27.0 and records its own six-cell verification matrix.

No release, real-device operation or hardware interoperability certification is
part of this integration. Existing historical delivery records remain intact.
