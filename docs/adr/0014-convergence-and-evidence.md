# 0014 — Policy convergence and evidence tiers

Status: accepted (2026-11-18)

## Context

Operators clean rulebases that grew for years: objects nobody uses, rules that never take effect, permits wider than needed, and many rules that differ in one address or port. Production configurations show 20–75 % of permits mergeable on large firewalls, hundreds of unused objects, and objects referenced only by QoS pipes or PBF rules, which a rule-only view reports as unused. A cleanup must not change what the firewall decides, and some questions (is a broad rule used, how should it be narrowed) cannot be answered from the configuration.

## Decision

- `firemon.References` is the reference graph of a configuration: rules, NAT, policy routes, interfaces, routes and constructs the model does not evaluate (QoS, DoS, recorded by the parsers as `ExternalUses`) are roots, groups propagate liveness to members. An object is unused when it is not live; groups are deleted before their members. Schedules are objects.
- `converge.Analyze` combines the audit facts with breadth, merge and hit-counter analysis. Every finding names its evidence (configuration, hit counters, both) and its tier:
  - Safe: unused objects whose definition is fully modelled; rules that never match, are incomplete, disabled, expired or redundant (covered by rules of the same action); mergeable rules.
  - Review: shadowed rules (covered by an opposite action: the intent never takes effect), empty objects, broad permits, zero-hit rules.
- Rules merge when they are equal in two dimensions and in everything else that decides or labels traffic (zones, rule-type, action, applications, logging, group), and only when no rule between them with another action, an undecidable match or a schedule could decide the moved traffic.
- `converge.Plan` designs the selected Safe findings (`design.ExtendRule`, `DeleteRule` with the next rule for an in-place rollback, `Delete*` objects) as a `PlanKindCleanup` plan and verifies that, for every changed rule and every zone pair it applies to, the permitted, denied, default and unknown regions are equal before and after. Objects the plan deletes are never reused for an extension. Deployment of a cleanup checks that the readback equals the verified prediction.
- Hit counters (`hits`) are evidence, collected read-only (PAN-OS `show rule-hit-count`; StoneOS experimental until confirmed on a device) or imported. A rule is unused only with zero hits over a window at least `--min-window` long; counters never justify narrowing, which needs traffic logs.

## Consequences

Deleting rules can leave more objects unused; running `converge` again after deployment finds them. On production configurations every planned cleanup verifies, reads back equal to the prediction and rolls back to the original configuration.
