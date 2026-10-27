# Go firewall implementation plan

Spec: ../spec.md

## Global constraints

Implement inline in the Go worktree, branch feat/go-firewall. Preserve reference worktrees. Commits, pushes, releases and device writes require explicit user authorization; implementation approval alone does not grant it. Each behavior uses RED then GREEN tests; task completion requires fresh verification. Concrete StaticNAT and DynamicNAT replace the initially proposed unified NATRule. No compatibility alias.

### Task 1: Baseline and exact traffic algebra

Record reference hashes, convert Ruby skeleton, establish Go module and CI. Implement normalized IPv4/IPv6 intervals and exact traffic rectangles with bounded difference/union preserving pairs.
Interfaces: flow address ranges and traffic sets consumed by graph, query, NAT and planning.
Tests: hand-derived boundaries, IPv6 maximum, mixed-family rejection, cross-pair non-expansion, independent tiny-universe oracle, budget exhaustion.
Verification: go test ./flow; go vet ./flow. Expected: success.

### Task 2: Concrete immutable firewall graph

Implement typed objects, draft tables, validated sealed reference graph, separate static/dynamic NAT catalogs, group cycle/dangling-ref evidence, scoped route/interface binding and deterministic semantic digest.
Interfaces: root graph consumed by config, snapshot, policy; DTO export used by snapshot without exposing graph mutability.
Tests: shared references, input/output mutation isolation, route longest-prefix/VRF/ambiguity, distinct NAT catalogs and interleaved order, invalid mappings and unknown modes.
Verification: go test . ./flow. Expected: success.

### Task 3: Cursor and stage engine

Implement bounded source, line evidence, scoped blocks, transactional draft+span commit and rollback, pending skip and rewind, explicit dependency stages.
Interfaces: config Source/Cursor/ParseResult; vendor parsers consume transactions and return graph drafts.
Tests: skip/rewind, overlapping claims, failed commit rollback, nested and quoted unknown blocks, cancellation and limits.
Verification: go test ./config/... . ./flow. Expected: success.

### Task 4: gob store, inventory, projection

Implement versioned envelope, graph two-pass restoration, atomic blobs and manifests, CAS/idempotency/durable reservations, incomplete-live invalidation, projection outbox, revision-bound inventory location.
Tests: roundtrip pointer identity and NAT types, corrupt/version rejection, no reparse, concurrent CAS and cross-process lock, incomplete state, out-of-order sink failures and retry.
Verification: go test -race ./snapshot/... ./inventory/... ./projection/.... Expected: success.

### Task 5: Hillstone offline vertical slice

Parse native target blocks through ordered stages; objects/topology/rules/static NAT/dynamic NAT, unknown semantics diagnostics. Implement exact ordered query, native NAT mapping, minimal-change candidates/proofs/rendering and CLI import/inspect/query/plan.
Tests: synthetic native fixtures, Perl oracle parity with bounded cases, partial subnet and deny precedence, unknown consumes, NAT offset and pools, deterministic candidate fallback, CLI snapshot reload.
Verification: go test -race ./.... Expected: success; no DB/device dependency.

### Task 6: Palo Alto then ASA

Native XML/set PAN and ASA block parsing; preserve native scopes, rule order, service conditions, NAT stages, renderer proof boundaries.
Tests: per-vendor golden graph/query/NAT/plan, PAN original addresses/post-DNAT zone and ASA real-address/staged auto/manual behavior.
Verification: go test -race ./.... Expected: success.

### Task 7: Online orchestration and adapter

Generic context-aware deploy engine with durable receipts/reservations, exact-plan authorization, save/commit confirmation, independent readback and recovery. Optional private connector module without root dependency; explicitly handle ASA profile and PAN commit completion.
Tests: injected transport failures before/after write, no uncertain replay, crash recovery, readback mismatch and publication retry.
Verification: go test -race ./deploy/...; optional adapter checks with local workspace. Expected: success with external dependency limits explicitly recorded.

### Task 8: Lifecycle algorithms

Request optimizer, proof-based convergence, translation, risk and reclamation with revision-bound observations.
Tests: exact union preservation, deny shadowing, whole-plan equivalence, unsupported translation, reset/missing counters never imply unused.
Verification: go test -race ./analysis/.... Expected: success.

### Task 9: Remaining vendors and delivery verification

Add staged capability implementations for SRX/Netscreen/Fortinet/H3C/Huawei/Topsec/Neteye, fixture parity, benchmark matrix, documentation and fresh independent whole-branch review. Implement supported capabilities, explicitly retain unknown for unsupported syntax.
Verification: go test -race ./...; go vet ./...; selected fuzz/benchmark runs. Expected: success. Record local vs CI vs real-device evidence separately.

## Review Focus

Check graph aliasing and pointer identity, static/dynamic NAT semantics, unknown evidence becoming any, native stage/order preservation, cursor transaction boundaries, range overflow and traffic cross-products, publication crash windows and cross-process reservations, and deployment uncertainty without replay. Check that claimed capabilities have real native fixture coverage.
