# 0015 — Cross-vendor migration and fidelity

Status: accepted (2026-11-18)

## Context

Replacing a StoneOS firewall with PAN-OS or the reverse means translating years of objects and rules whose constructs do not map one to one: exclusions, mixed objects, wildcard domains, rule groups, inline validity windows and service entries on StoneOS; negation, rule-type, application-default and a single NAT list on PAN-OS; different default actions and name rules on both. A translation that widens a rule, or narrows it without saying so, is worse than none.

## Decision

- `migrate.Translate(src, mapping, target)` builds the target `firemon.Config` and a `PlanKindMigration` plan the target renderer writes as a complete configuration (network, schedules, objects, rules in order, explicit defaults, NAT in order). The target is described by `firemon.Capabilities`, its default semantics and its predefined services; a YAML mapping names zones, interfaces, virtual routers, predefined services and applications, and `Skeleton` drafts it.
- Every item gets a fidelity:
  - exact: an equivalent form exists (exclusions as ranges, negation as a complement object, rule-type as zone pairs, multi-entry objects and multi-protocol services as groups, inline services and windows as objects, differing defaults as explicit last rules);
  - approximate, with the difference stated (ends rounded to PAN-OS minutes, application-default dropped, interface names kept unmapped, NAT list semantics);
  - untranslatable (wildcard domains, unmapped applications, users, URL categories, unsupported periods): the rule is carried over disabled with the reason in its description, so it is never lost and never widened.
- Each translated rule is compared with its source rule: same action, same zones through the mapping, same match space; a difference downgrades it to approximate.

## Consequences

Migration output is generated offline and must be loaded on a lab device and read back before production. Layer-2 setups, QoS, security profiles and log settings are reported, not translated.
