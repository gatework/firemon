# 0008 — Protected networks and locating v2

Status: accepted (2026-11-18); supersedes the ownership rule of ADR 0006

## Context

Routing alone cannot tell which site firewall owns an address when several sites route the same summary (10.0.0.0/8) inward. The Perl searcher used operator-maintained protected-zone tables. In production that data lives in a database; locally it is a file.

## Decision

- `inventory.Protection{Firewall, Zone, Networks, Exclude}` declares protected networks. Members carry an HA `Cluster`; a cluster is evaluated and planned once, on its first member.
- Ownership of each address is longest prefix across the inventory, declared protections first; clusters without declarations fall back to their non-default routes (`derived`). Equal claims of different clusters are all evaluated and reported as ambiguous.
- Every (source part, destination part) pair is evaluated on its owners, with declared zones as the zone pair, and on transit clusters reached by route next hops from the source owners. Traffic whose ends no firewall owns is excluded and reported.
- `adapter/yamlfile` reads `firemon.yaml` (firewalls, clusters, snapshots, protected networks); unknown keys are errors. A database source can provide the same `Protection` values later.

## Consequences

`firemon check` and `firemon locate` answer per cluster. Without an inventory file the behaviour degrades to ADR 0006's routing-derived ownership.
