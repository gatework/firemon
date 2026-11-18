# 0009 — Domain and application targets

Status: accepted (2026-11-18)

## Context

Next-generation rules match destination domains (`dst-host`, FQDN objects, `domain-book`) and applications. Before this decision every such rule was undecidable, so most queries on real configurations ended indeterminate.

## Decision

- Rules keep their destination domain patterns as a `traffic.DomainSet` (exact, `*.x` subdomains, `*x` suffix) and their applications by lowercase name. Issues caused only by domains or only by applications are counted separately (`Rule.DecidableFor`).
- A request may name destination domains (with optional resolutions) and applications. Each becomes its own target:
  - domain targets match rules by pattern; resolved names match address rules by address; an unresolved name leaves by the default route, so address-only rules whose addresses are routed elsewhere cannot match it, the others are possible matches;
  - application targets skip rules restricted to other applications; with the service left open they use the application's default ports, which also define application-default services. Vendors embed a default application book; configurations carry it.
- Requests without a domain or application keep the conservative behaviour: domain and application rules are possible matches.
- `--resolve` (adapter/dns) resolves names with the system resolver, bounded in time and count.
