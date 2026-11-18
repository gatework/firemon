# 0001 — Rewrite firemon as v2

Status: accepted (2026-11-17)

## Context

firemon v0.2 grew to about 110k lines. The root package mixed DTOs, entities, parse drafts and rollback, digests and HA; every concept existed twice (`XRecord` and `X`); `tables.go` iterated record kinds through generic constraint tricks; `policy`, `plan` and `request` each held 50 to 70 files; pure computation threaded `context.Context`.

## Decision

Rebuild the module from an empty tree instead of refactoring in place. Scope phase 1 to one firewall end to end (parse, query, design, render, deploy) for Hillstone StoneOS and PAN-OS set-format configurations. Multi-firewall path finding (ADR 0006), snapshot persistence and policy audit followed in phase 2; other vendors are out of scope for now.

Layout: `traffic` (set algebra) ← `firemon` (domain model and compiler) ← `query`, `design`, `deploy`; `vendors/<vendor>` parse and render; `adapter/netconnector` talks to devices; `internal/{workflow,bootstrap,cli}` and `cmd/firemon` drive it.

## Consequences

v0.2 callers break. Behaviour is pinned against the Perl reference by tests where it is intended to match, and ADR 0003 lists where it is not.
