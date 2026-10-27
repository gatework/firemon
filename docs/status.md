# Implementation status

This worktree is an implementation in progress, **not the completion of the approved plan or a release**. No real device, SQL database, remote CI or release validation has been performed.

| Area | Current evidence | Remaining work |
| --- | --- | --- |
| Concrete graph | StaticNAT and DynamicNAT catalogs; shared references, sealed copies, scoped routes; local tests | Broader native fields and lifecycle dependencies |
| Exact traffic | IPv4/IPv6 interval and multidimensional algebra; short fuzz run and race tests | Large benchmark matrix, further adversarial limits |
| Cursor | Pending skip, rewind, transactional drafts/evidence and stage rollback; bounded XML fragments with original byte spans | Additional native grammar recovery |
| Persistence | gob envelope; shared graph restored without raw parse; CAS, reservation, outbox, projection retry; separate-process reservation test | Fault-injected durability matrix, store growth/compaction policy |
| Hillstone | Scoped parser, exact policy query, independent plan/readback proof and rendering; 4 verified Perl oracle cases; BNAT inverse and per-direction priority; version-gated original-packet DNAT/SNAT composition | Extended syntax and broader native fixtures; mixed-chain behavior needs real-device verification |
| Palo Alto | Native set/XML graph parity and byte evidence; implicit same-zone/cross-zone rules; distinct log-start/log-end; original-address/post-DNAT-zone packet tests; native rendering and independent readback | Multi-vsys/central management rules, application conditions, reverse static NAT and wider version coverage |
| ASA | Interface/ACL binding, full service protocol/port pairing, native NAT section priority and exact auto-NAT cardinality/name sort; static and twice-NAT forward/reverse address/port evaluation; real-address packet path; new ACL rendering/readback | Additional ACL/time syntax, global/same-security rules, legacy NAT and wider version matrix |
| CLI | Offline import/inspect/query/nat/plan; reload after original file removal | Broader commands, help ergonomics and export contracts |
| Online | Injected deploy engine, exact-plan authorization, durable operation journal/receipts, reservation, save confirmation, new-session readback, incomplete-live publication and no-write recovery; fault/concurrency tests | Optional private adapter; wider process-crash durability matrix; real-device validation |
| Lifecycle | Exact fixed-point request optimizer; all-zone/future-boundary equivalence; convergence and batch reclamation plans; revision/graph-bound contiguous usage evidence; declared/effective risk; explicit-zone effective-partition translation preserving action/logging | Broader native rendering and schedule migration; richer risk definitions, CLI and benchmark coverage |
| Other vendors | Not implemented | SRX, Netscreen, Fortinet, H3C, Huawei, Topsec, Neteye |

Unrecognized source and unsupported semantics remain incomplete; do not describe that as vendor parity. A successful offline proof is not real-device interoperability or permission to deploy.

## Commit checkpoint

The root module passed `GOWORK=off GOPROXY=off go test -count=1 -race ./...` across 14 packages, `GOWORK=off GOPROXY=off go vet ./...`, CLI build and formatting checks locally on macOS. It has no external module dependency. These checks do not establish remote CI or real-device behavior.

The optional connector adapter is still a local draft and is excluded from this checkpoint. Its placeholder dependencies do not resolve as published versions; the root module and its CI do not depend on that adapter. The remaining vendor, lifecycle and verification work above remains open.

Development ledger: `.superpowers/sdd/go-firewall/progress.md` (local, ignored).
