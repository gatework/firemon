# 0016 — Unified rule model: conditions, inspection and application matches

Status: accepted (2026-11-19)

## Context

firemon manages firewalls of different vendors and forms through one model. Beyond the five-tuple, what a rule matches on was spread over vendor-shaped fields: `Applications`, `ApplicationDefault`, FQDN entries and an `Unsupported []string` of vendor text whose kind was guessed from its prefix. Every new kind of criterion became a special case in the algorithms (application ports, domain views, narrowing denies). Security inspection was dropped by the parsers, so operators could not see it. Operators query by five-tuple even when application identification depends on session traffic.

## Decision

- **Vendor syntax only at the edge.** Parsers and renderers map vendor syntax to the model and back; the model and the algorithms name no vendor and no vendor keyword. Vendor differences in behaviour are declared (`Semantics`, `Capabilities`, the service and application books), never branched on.
- **One extension point for criteria.** A security rule matches on zones, addresses, services and a list of `Condition{Kind, Values, Raw}`. Kind is a closed set — application, domain, user, url-category, other — each a question an operator asks on its own; everything else is `other`. Raw keeps the vendor text for display and rendering. `DynamicNAT` and `PolicyRoute` use the same list.
- **Inspection is one opaque list.** `SecurityRule.Inspection []string` records the inspection a rule enables in the vendor's terms (`ips NAME`, `group NAME`). It never affects matching; it is counted, shown, audited and reported as not migrated.
- **Neutral names.** `ApplicationDefault` becomes `DefaultPorts` (the services are the applications' standard ports), `Logging.Setting` becomes `Logging.Forward`. `NumericRuleIDs` stays in `Semantics` only: it describes how the device identifies rules, which reading a stored configuration needs.
- **Application and service are independent criteria.** `Certain()` gives traffic the rule definitely matches. `Bound()` includes traffic it may match. With `application-default`, a complete default port book can exclude ports. With `service any`, an application may use any port. The five-tuple query, design and readback use the same first-match semantics. Conflicting possible actions produce an indeterminate result.
- **Derived, not stored.** Classification by condition kind, counts and the indexes by kind, application and domain are computed at compile time.

## Consequences

The stored configuration changes shape (`ModelVersion` 4): snapshots are parsed again from their text on first use. A new vendor implements a parser, a renderer, a platform description and its books; the model and algorithms do not change. Reports identify the application-default rules whose known service bounds excluded some of the requested ports.
