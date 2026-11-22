# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.5.0] - 2026-11-22

- Package `platform` exports the vendor bundle the CLI uses (`For`, `Vendors`, `Platform.MigrationTarget`), so backends parse, render, read hit counters and plan migrations without rebuilding it.
- `Platform.HARole` reads a member's runtime HA role: from the StoneOS prompt (`(M)`/`(B)`), and from the PAN-OS prompt or `show high-availability state` (`HAStateCommand`; not yet checked on a device).
- Design plans over the period the access must hold: a timed rule in force only part of it counts against the access (`query.ScheduleWorstCase`). A scheduled deny is a conflict for permanent access, and rules are extended only when they are in force exactly when the intent asks.
- Design: an undecidable deny that may match first (an application deny on a port no application claims) leaves the access indeterminate and names the rule, as ADR 0017 states; a plan that opens nothing is not verified.
- `migrate` translates policy-based routing between StoneOS and PAN-OS, keeping each entry's place in the order of every ingress it applies to; both renderers write policy routes and bindings.
- Fix: `nat` reports a rule in effect when any decided path uses it, and judges shadowing only on the paths its zones apply to.
- Fix: a deployment whose session close fails persists the settled (uncertain) record again.
- Fix: migration keeps a default static route distance the target's default.

- Fleet health and cleanup output (ADR 0019):
  - `firemon health --inventory DIR|FILE` scores every cluster with stated deductions and lists the first things to fix, each with the command that acts on it.
  - `converge` and `audit` print a summary by default (`-v` lists findings). `converge --inventory` accepts a backup directory; `--cluster` narrows the fleet; `--plan --out DIR` writes the cleanup and rollback files.
  - Coverage analysis includes rules restricted to applications, and finishes on every corpus firewall: a projection test, then an order-free fallback past the budget.
  - `parse`/`audit` count conditional rules apart from undecidable ones.
  - Performance: the wide query went from 1.7 s to 0.76 s (report spaces gathered once instead of merged piece by piece). Fleet review runs in parallel.

- `search` answers with scripts, firewall by firewall:
  - the existing rules that permit the traffic, in the device's own text (`Config.Source`, recorded by both parsers; `Config.RuleSource` puts the addresses, services and schedules a rule names before it);
  - the add or modify script, with its rollback, for what is still needed.

  `-v` keeps the reasoning and `-vv` the full detail. The model is version 6: snapshots are parsed again to record the source text.



- Hop chaining, change risk and operations output (ADR 0018):
  - **Bounded output.** Wide requests print a zone-pair summary and bounded lists (the /16-to-any probe went from 1.7 MB to 20 KB); `-v`/`--json` keep everything.
  - **One reading of each firewall.** Firewalls are described by flows; the conclusion says whether the plans add or modify rules, and rules not chosen for modification are named with the reasons. Applications are spelled as configured.
  - **NAT chaining.** A firewall whose NAT rewrites traffic hands the translated packet on: the next firewall is evaluated and planned for the server address and port it really sees.
  - **Change risk.** Planned changes are graded for risk, including bypassing a network-isolation deny.
  - **Operations.**
    - `--until` grants temporary access, through a validity window (StoneOS) or a one-time schedule (PAN-OS).
    - `--file` answers a CSV batch of tickets, each designed on the ones before it.
    - `--format markdown` prints a report ready for a ticket.

- Determinate verdicts with stated premises (ADR 0017):
  - A five-tuple query identifies the traffic as the standard application of its ports (tcp/22 is SSH). Rules for other applications no longer leave it "需确认".
  - Rules by user, URL category or domain name, and scheduled rules inactive at the query time, are taken not to match. The report lists each such premise with what it would change.
  - `--user` and `--url-category` settle those criteria exactly; `--strict` keeps the conservative reading.
  - The model is version 5 (predefined application groups). The PAN-OS application book gains the applications seen on production rulebases.
- `search` reports by flow:
  - Every source × destination item is followed through the firewalls it crosses, in order, with the deciding rule on each.
  - Firewalls are named `NAME(management address)`, taken from the backup file name or the inventory `host`, with their HA peers.
  - Planned rules print in full: action, zones, source, destination, service, application, time, logging and objects created. Modified rules show their state before the change.
- Fix: a plan with several parts on one cluster was never re-verified after merging, so it printed "方案验证未通过（未验证）" without commands. It is now replayed and verified from the current configuration.
- Input: full-width digits and punctuation are read as ASCII. A host written as a network or broadcast address (`10.1.1.0`) is flagged in case a mask is missing.

- `--inventory` accepts a configuration backup directory: its Hillstone and PAN-OS configurations become the fleet, read directly; the configured inventory file still supplies clusters, roles and zone bindings for the firewalls it names, the others pair into HA clusters by name and own what their routes reach.
- Paths follow the shared gatework layout: the settings file is `$FIREMON_CONFIG`, `./firemon.yml`, then `~/.gatework/firemon.yml` (was `~/.config/firemon/config.yaml`, which on macOS resolved under `~/Library/Application Support`), with relative paths resolved against it; credentials may come from the `.env` beside it under the process environment; snapshots default to `~/.local/share/gatework/firemon/snapshots` and deploy journals to `~/.local/share/gatework/firemon/deploy` (was the OS cache directory).
- Dependencies moved from go-netops v0.4.2, parser v0.2.2, set v0.1.1 and net-connector v0.9.3 to netops v0.2.0 and net-connector v0.10.1. Port sets use netops `set`; vendor parsers use netops `parse`, `deploy` runs netops `apply.Run` (records `apply.Record` in netops `store/journal`), and `adapter/netconnector` uses `connector.Dialer` over in-process SSH (strict host keys).
- PAN-OS deployments send each set command and a final `commit`; the session commits them as one candidate batch and requires "Configuration committed successfully". The running configuration is read in set format only when `show config diff` is empty before and after.

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
