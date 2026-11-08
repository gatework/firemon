# Go 1.27 business module verification

Baseline: `bc11aca3052355bca442033dc26bcca3e0ab0216`. The supported vendors remain
Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA. See
[the migration notes](refactoring.md#go-127-business-module-update) for interface
and CLI changes.

## Observable behavior

| Area | Evidence |
| --- | --- |
| Deployment completion | Confirmed publication/abortion survives a subsequent close error; unconfirmed results stay uncertain. Repeated Aborted Apply is terminal and never reconnects. |
| Recovery evidence | Cancellation while checking saved state retains the observed running graph using a bounded local context. The reservation survives failure; recovery never replays Execute or Save. |
| Reservation races | A failed durability step may have installed a reservation, so Apply cannot assume Aborted. Independent recovery terminates a pre-device conflict after a concurrent publication without changing its head. A missing reservation cannot erase an unconfirmed configuration token. |
| Parser capacity | Accepted service terms, pending terms, replacement, phase rollback, builtins, unsupported records and PAN set/XML port products have capacity regressions. Fatal capacity/cancellation errors are not converted into unrestricted traffic. |
| Snapshot persistence | Oversized stored manifests fail with ErrFormat and ErrLimit; failed oversized writes preserve generation, head, reservation and outbox. Existing blobs are compared through real EOF with bounded reads. |
| NAT context identity | Non-JSON times fail before identity construction. Legal offsets, raw rule-set identity and finite-window context counts retain compatibility. |
| Target provenance | Input/target order, partial discovery, topology versus business sources, duplicate sources, original request time, fatal plan clearing and reconstruction digests are characterized through operations. |
| Native declarations | Twenty frozen native command and approval fixtures retain exact output. Ownership, malformed deltas, shared Huawei inline terms, native readback, schedule prefixes and ordering are exercised through vendor/planning interfaces. |
| CLI | All 17 command help paths, root help, usage/runtime classification, short writes, output failures and actual binary exit codes are checked. Signal tests keep stdin open and synchronize child readiness before SIGINT/SIGTERM. |

The command and approval fixture was captured against the unchanged baseline
before the native builder refactor. The target report/reconstruction
characterizations were likewise checked against the old implementation. Tests
use synthetic inputs and local fake/transcript sessions.

## Local verification matrix

All six final checks passed on macOS arm64:

| Configuration | Go 1.27.0 | Go 1.27.3 |
| --- | --- | --- |
| Core (`GOWORK=off`) | PASS | PASS |
| Adapter with published dependency pin (`GOWORK=off`) | PASS | PASS |
| Adapter with current core (external workspace) | PASS | PASS |

Formatting and `git diff --check` passed. `govulncheck ./...` found no
vulnerabilities in the core, pinned adapter or paired adapter with Go 1.27.3.
Semantic checks through `gopls` passed for the changed module and CLI seams.
The CLI also cross-compiled for linux/amd64; this is compilation evidence,
not a Linux runtime signal test.

The matrix uses `GOFLAGS=-mod=readonly`, `GOPROXY=off` and an external workspace
only for the paired adapter. Every cell runs `go mod verify`, `go vet ./...`,
`go test -race -count=1 ./...` and `go build ./...`. Standalone core and adapter
cells also run `go mod tidy -diff`. The adapter dependency pin is unchanged;
paired checks exercise this checkout, while pinned checks exercise its published
core dependency. No dependency source or temporary workspace is added to the
repository.

## Measurements

Measurements use Go 1.27.3 on darwin/arm64, Apple M5. The same benchmark sources
ran serially against the baseline and changed checkout, with fixture preparation
outside the measured loop. The broad run uses six samples and 100 ms minimum per
sample; the focused ordinary-policy Plan rerun uses ten samples and 500 ms.
These are local synthetic measurements, not capacity guarantees.

| Workload | Before → after | Interpretation |
| --- | --- | --- |
| Finite NAT Plan | 613.7 → 511.2 µs; 639.7 → 545.8 KiB; 4,001 → 3,449 allocs/op | About 17% less time and 15% fewer bytes in this fixture. |
| Finite NAT Restore | 727.6 → 626.2 µs; 748.9 → 654.7 KiB | About 14% less time and 13% fewer bytes. |
| Huawei packet, 1,000 rules | 3.532 → 3.315 ms; 5.444 → 5.429 MiB | About 6% less time; allocation change is small. |
| Business batch, 1,000/10,000 rules | Most comparisons show no significant time difference | The target module primarily improves ownership and projection locality. |
| Ordinary policy Plan, focused rerun | 128.8 → 136.3 µs; 189.6 → 189.7 KiB; 1,206 → 1,212 allocs/op | About 6% slower in this run, with small extra allocations from owning nested change slices. No general speedup is claimed. |

The first short ordinary-policy Plan comparison showed a larger timing change
with wide variation; the longer focused rerun above is the more useful evidence.
Command ownership intentionally retains deep copies. Remaining candidate-plan
allocations were not redesigned in this change.

Local raw logs, benchstat output, matrix JSON and failure reproductions are in
`/tmp/firemon-go127-20261107.tR2hyw`. This is a temporary local artifact location,
not part of the package or a durable CI record. CI now declares the same three
configurations for Go 1.27.0 and 1.27.x; a remote run of these new changes is not
claimed. No real device, release or deployment is part of this verification.
