# Implementation status

This worktree is an implementation in progress, **not the completion of the approved plan or a release**. No real device, SQL database or release validation has been performed.

| Area | Current evidence | Remaining work |
| --- | --- | --- |
| Concrete graph | StaticNAT and DynamicNAT catalogs; shared references, sealed copies, scoped routes; local tests | Broader native fields and lifecycle dependencies |
| Exact traffic | IPv4/IPv6 interval and multidimensional algebra; short fuzz run and race tests | Large benchmark matrix, further adversarial limits |
| Cursor | Pending skip, rewind, transactional drafts/evidence and stage rollback; bounded XML fragments with original byte spans | Additional native grammar recovery |
| Persistence | gob envelope; shared graph restored without raw parse; CAS, reservation, outbox, projection retry; separate-process reservation test | Fault-injected durability matrix, store growth/compaction policy |
| Hillstone | Scoped parser, exact policy query, independent plan/readback proof and rendering; 4 verified Perl oracle cases; BNAT inverse and per-direction priority; version-gated original-packet DNAT/SNAT composition | Extended syntax and broader native fixtures; mixed-chain behavior needs real-device verification |
| Palo Alto | Native set/XML graph parity and byte evidence; implicit same-zone/cross-zone rules; distinct log-start/log-end; original-address/post-DNAT-zone packet tests; native rendering and independent readback | Multi-vsys/central management rules, application conditions, reverse static NAT and wider version coverage |
| ASA | Interface/ACL binding, full service protocol/port pairing, native NAT section priority and exact auto-NAT cardinality/name sort; static and twice-NAT forward/reverse address/port evaluation; real-address packet path; new ACL rendering/readback | Additional ACL/time syntax, global/same-security rules, legacy NAT and wider version matrix |
| SRX | Staged display-set parser; logical interfaces and VRF routes; attached/local/global address-book identity and lookup; application term pairing; zone-pair policy identity/order; static address/port inverse, destination pool translation, source pool/PAT and off; post-DNAT routing/policy then permitted SNAT; create/append/delete rendering and independent readback; CLI import/NAT/plan | Hierarchical input, groups/inheritance, predefined applications, schedules/global policies, interface/instance NAT rule-set precedence, interface allocation, non-singleton destination pools, additional native/version coverage |
| Netscreen | Scoped ScreenOS passes; VRF/interface route binding; zone/global addresses and paired service groups; policy continuations, top placement, disable and intrazone block/bypass; separate MIP/VIP/DIP/policy NAT with owning-rule identity; original-address/port packet policy; independent create/append/delete readback and CLI snapshots | Virtual systems, Global policies, schedules/predefined services, PBR/route leaks, DIP address shifting, loopback groups/multi-interface NAT, mixed opposite-direction interface/policy translation and edits to NAT-owning policies; broader native/version fixtures |
| Fortinet | Selected-VDOM scoped config/edit parser; interface/zone/route dependencies; address/group and paired service terms with global source-port defaults; separate fixed VIP, port forwarding, pools and policy-owned source NAT; VIP policy lookup, reverse VIP source priority, original-wire query traces and post-DNAT packet routing; native create/append/delete rendering with independent readback; VDOM-aware CLI snapshots | Central NAT, policy-based NGFW, IPv6 native syntax, schedules, PBR/SD-WAN, additional VRFs/secondary interfaces, non-overload pools, port-forward source forcing, partial-zone interface selectors, unresolved one-sided translated service checks, declared VIP risk, local VIP/pool behavior, native NAT edits and online connector profile; broader fixtures/version evidence |
| CLI | Offline import/inspect/query/nat/plan; selected Fortinet VDOM survives reload after original file removal | Broader commands, help ergonomics and export contracts |
| Online | Injected deploy engine, exact-plan authorization, durable operation journal/receipts, reservation, save confirmation, new-session readback, incomplete-live publication and no-write recovery; process-exit tests at five write/save/publication boundaries; separate connector adapter with pinned remote versions and native ASA deployment/recovery transcript tests | Real-device interoperability and additional native save/commit response formats |
| Lifecycle | Exact fixed-point request optimizer; all-zone/future-boundary equivalence; convergence and batch reclamation plans; revision/graph-bound contiguous usage evidence; declared/effective risk; explicit-zone effective-partition translation preserving action/logging | Broader native rendering and schedule migration; richer risk definitions, CLI and benchmark coverage |
| Remaining vendors in scope | Not implemented | Huawei |

Unrecognized source and unsupported semantics remain incomplete; do not describe that as vendor parity. A successful offline proof is not real-device interoperability or permission to deploy.

The user-confirmed scope is Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA. H3C, Topsec, Neteye and other vendors are deferred.

## Commit checkpoint

The Fortinet implementation passed `GOWORK=off GOPROXY=off go test -count=1 -race ./...` across 17 root packages and `GOWORK=off GOPROXY=off go vet ./...` locally on macOS. A 20-second Fortinet parser fuzz run completed 725,187 executions without failure. The nested connector adapter also passed its race tests in the isolated workspace against the current core. Root has no external module dependency. These checks do not establish remote CI or real-device behavior.

The checkpoint `2bac8e215b52076177c890d292ccfd06cfc763b2` was pushed to the public [gatework/firemon](https://github.com/gatework/firemon) repository on `main`. Its [Go workflow](https://github.com/gatework/firemon/actions/runs/40603212952) passed on Ubuntu. It includes ScreenOS, the optional adapter and process-exit tests. This evidence applies to that commit; later changes require their own CI results.

The adapter pins the SRX core commit `19d5508` and connector commit `c68c42b4bbcf`; local transcript/integration tests pass with `GOWORK=off`, as do `go vet` and `go mod verify`. Root public CI does not test the nested adapter. Its private dependency requires authenticated Git access. The remaining vendor, lifecycle and verification work above remains open.

Development ledger: `.superpowers/sdd/go-firewall/progress.md` (local, ignored).
