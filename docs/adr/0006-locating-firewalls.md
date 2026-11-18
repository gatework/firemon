# 0006 — Locating the firewalls a flow crosses

Status: superseded by 0008 for ownership (2026-11-18)

## Context

The Perl searcher found the firewalls of a request through database views of "protected" and "unprotected" zone address ranges maintained by operators. v2 has only the device configurations.

## Decision

`inventory.Locate` derives the path from each firewall's own routing:

1. A firewall is a candidate when part of the request enters and leaves it through different interfaces.
2. The owners of the sources (and of the destinations) are the candidates whose route to them has the longest prefix across the inventory; default routes own nothing. Several sites that route 10.0.0.0/8 inward therefore do not own a host behind the one site that routes its /16, and HA pairs with identical routes own the same ends.
3. From the source owners the trace follows route next hops: a next hop that is an interface address of another candidate puts that firewall on the path (transit firewalls such as an Internet edge).

Transparent (layer-2) firewalls have no routing context and are not located; they are queried with explicit zones.

## Consequences

The result needs no operator-maintained ownership data, but ties are reported rather than broken: when two sites route the same prefix, both appear. Snapshots (`adapter/filestore`) supply the configurations so locating does not contact devices.
