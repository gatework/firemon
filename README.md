# firemon

Go firewall configuration and policy automation. Implementation is in progress against [the specification](docs/spec.md) and [execution plan](docs/plans/go-firewall.md).

The firewall graph includes interfaces, routes, zones, addresses and groups, services and groups, schedules, security rules, **StaticNAT**, **DynamicNAT**, and NAT pools. Vendor execution order is retained separately from object identity.

This branch converts the original Ruby gem skeleton to Go while retaining Git history. The Ruby and Perl Algosec implementations are reference implementations, not runtime dependencies.

Run `go test ./...` and `go vet ./...` from this directory. No database or device connection is required for offline tests.

The approved vendor scope is Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA. The [status matrix](docs/status.md) distinguishes implemented slices from remaining work. Parsers are `hillstone`, `paloalto` (set/XML), `asa`, `srx` (Junos display-set), `netscreen` (ScreenOS) and `fortinet` (FortiOS config/edit); native syntax coverage is reported per fixture. Huawei remains to be implemented.

Offline example (synthetic or sanitized configuration):

```sh
go run ./cmd/firemon import --store ./snapshots --device lab --vendor hillstone \
  --file ./lab.cfg --complete --publication import-1
go run ./cmd/firemon inspect --store ./snapshots --device lab
go run ./cmd/firemon query --store ./snapshots --device lab \
  --source 192.0.2.10/32 --destination 198.51.100.20/32 --service tcp/443 \
  --from-zone inside --to-zone outside
```

`--complete` asserts the capture was fully received; unsupported syntax can still make the parsed graph incomplete. Incomplete offline imports are archived without replacing current. Use `inspect --revision <revision>` to inspect an archived graph. Updates require `--expected <current-revision>` and a new publication ID. A known capture time can be supplied as `--captured-at <RFC3339>`.

`query` evaluates the supplied policy address/zone context. `policy.Engine.QueryPacket` also models PAN original-address/post-DNAT-zone, ASA real-address ACL paths, SRX post-DNAT policy followed by permitted source translation, ScreenOS original-address/service policy with MIP/VIP destination-zone resolution, and FortiOS VIP routing followed by policy-owned source translation. `nat` preserves separate static/dynamic objects, native order and inverse/pipeline steps; uncertain versions or mapping semantics return explicit unknown/error. For SRX, ScreenOS and FortiOS, its `--to-zone` is the destination security zone after resolving DNAT. `plan` renders supported changes for all six implemented vendors for review.

Fortinet imports accept `--vdom <name>` (default `root`). One firewall graph represents that selected VDOM; `Metadata.Context` survives snapshot loading, and the CLI uses it as the default query scope. The Go API takes `Request.Scope` explicitly. Commands are relative to the reported VDOM; callers must establish that device context. The online connector adapter does not enable Fortinet deployment. VIP identity, `match-vip` policy selection, forward port mappings and policy NAT ownership are retained. Source allocation is possible session behavior, not an exact binding. Translated service checks without sufficient native evidence and local VIP/IP-pool packet destinations stay unknown. See [native semantics](docs/native-semantics.md) for evidence and limits.

ScreenOS policy NAT has an explicit `DynamicNAT.Rule()` reference to its owning security policy. Query and lifecycle proofs retain first-match ownership, including earlier ordinary permits and denies. Modifying a policy that owns NAT requires joint translation proof; the current renderer rejects those edits. MIP is a bidirectional `StaticNAT`, while VIP and DIP allocation remain `DynamicNAT` behavior. Mixed interface/policy translations in opposite directions remain unknown.

The `analysis` package provides exact request optimization, convergence, explicit-zone translation, declared/effective risk and evidence-bound reclamation. Lifecycle plans share independent readback verification with request plans. `deploy` injects transport, authorization and a durable journal, reserves the current snapshot, records receipts, confirms persistence and parses a new-session capture before publication. Recovery reads independently and never replays uncertain writes. These paths have local synthetic tests; no real-device interoperability is claimed.

The optional [connector adapter](adapter/netconnector/README.md) is a separate module with pinned private dependencies. It supplies fresh device sessions, command receipts, native save confirmation and distinct running/persistent capture for Hillstone, PAN and ASA. Root offline builds do not import it.

Snapshot directories contain complete source configurations. Keep them local and trusted; gob is not an untrusted interchange format. Runtime files use private permissions. The optional database projection reads published snapshot files and requires a host-supplied idempotent transactional sink.

Snapshot semantic format 6 preserves zone address-book attachments, policy-owned NAT references, the selected native context and VIP policy matching. Older semantic formats are rejected explicitly; import the original capture into a new store rather than treating old cached graphs as current evidence.
