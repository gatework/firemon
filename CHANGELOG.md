# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
- `firemon` CLI: parse, query, usage, audit, design, deploy, collect, locate.
