# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.4.2] - 2026-11-21

- Use documentation IP ranges, example domains, and explicit dummy credential and certificate data in tests.

## [0.4.1] - 2026-11-21

- Update device sessions to net-connector v0.10.3 and the shared operations packages to netops v0.4.0.

## [0.4.0] - 2026-11-20

### Changed

- Use net-connector v0.10.1 and netops v0.2.0 for device sessions, deployment, parsing and port sets. The standalone set, parser and go-netops modules are no longer required.
- Device collection and deployment use in-process SSH with strict host-key checks. Use a management IP address and a trusted known-hosts file.
- PAN-OS deployments commit the candidate as one batch and require positive commit evidence. Set-format reads require an empty configuration diff before and after the read.

## [0.3.0] - 2026-11-20

### Changed

- **Breaking:** v2 rewrite. The module is rebuilt around `traffic` (exact set algebra), the `firemon` domain model and compiler, vendor packages for Hillstone and PAN-OS, and the `query`, `design` and `deploy` workflows. The v0.2 API is removed.

### Added

- `traffic`: exact IPv4/IPv6 address, port and service sets; spaces and disjoint regions.
- `firemon`: declarative configuration model, compiler, fingerprints, JSON round trip.
- `vendors/hillstone` and `vendors/paloalto`: parsers (including legacy StoneOS policy blocks) and renderers with rollback.
- `query`: ordered first-match evaluation with routing, NAT and undecidable-rule handling; address usage lookup.
- `design`: verified change plans that reuse objects, extend rules within the intent or add rules before the deciding deny.
- `deploy` and `adapter/netconnector`: fingerprint-checked, journaled deployment on go-netops `apply`.
- `audit`: redundant, shadowed, disabled, expired, undecidable and permit-any rules; unused objects.
- `adapter/filestore`: device snapshots used offline by every read command.
- `inventory`: locating the firewalls a flow crosses (ADR 0006) and planning on each.
- Predefined service books: embedded per-vendor defaults, device books with `--service-book`, `firemon services` (ADR 0007).
- Review round 2: route installation and ECMP, address-family split, single-list (PAN-OS) and separate (StoneOS) NAT first-match with zone checks per routed part, schedule modes, strict catch-all denies, unique rule names, readback equality on deploy, parsers that never widen unreadable rules.
- `intake` tolerant input, domain and application targets (ADR 0009), protected networks and HA clusters (ADR 0008), the `report` package with candidates and group aggregation (ADR 0010), `firemon check`.
- StoneOS service book: HTTP-EXT is tcp/80 and tcp/443 (confirmed on devices).
- Inventory: `role: active|backup` selects the member evaluated and planned on; `protected_zone` names the zone behind the protected networks, which act as routes to it, while the far end of a flow is reached through the peer zone (transparent firewalls); traffic with both ends behind one interface is reported as not crossing.
- Design treats rules ahead that only narrow by application, URL category or user as a warning, not a blocker; conflicts and warnings print even without changes.
- Policy convergence (ADR 0014): `firemon converge` reports unused objects (through a reference graph that includes QoS, DoS and PBF), rules that never take effect, broad permits and mergeable rules with their evidence and tier, and `--plan` designs the safe ones as changes verified to keep every decision, with rollback.
- Hit counters: `firemon hits` collects rule hit counters read-only (PAN-OS; StoneOS experimental) or imports them as JSON/CSV; converge uses them for zero-hit evidence.
- Migration (ADR 0015): `firemon migrate --to VENDOR` translates a configuration into the other vendor's commands with a fidelity report; untranslatable rules are carried over disabled.
- NAT design (ADR 0012): `--nat snat|dnat|static` with `--nat-ip`, `--nat-port`, `--egress` on `design` and `check --design`; reuses translations that already match first, reports conflicts and missing public addresses, places new NAT rules before the rule that would match first, and designs the matching security rule.
- First-match accuracy (ADR 0013): incomplete StoneOS rules never match, undecidable rules keep their certain part, PAN-OS interface addresses translate to the host.
- Policy-based routing (StoneOS pbr-policy and bindings) applied before the routing table, with conditional branches for user-group entries; NAT hits report their order position, translated traffic and skipped disabled rules (ADR 0011).
- `firemon` CLI: parse, query, usage, audit, design, deploy, collect, locate.
