# 0013 — Incomplete rules and certain matches

Status: accepted (2026-11-18)

## Context

Cross-validation against production configurations found three ways the model disagreed with first-match on the device:

- StoneOS lists rules created without an action, source, destination or service (`rule id 6` / `action permit` / `exit`). They were read as permit any to any and shadowed every rule below, including the default deny.
- One unresolved entry in an operand list (an unknown predefined service, an FQDN among addresses) made the whole rule undecidable, so a later rule was reported as deciding traffic the rule certainly matches.
- PAN-OS `interface-address ip 103.24.178.130/28` was read as the /28 pool rather than the interface host.

## Decision

- A rule missing a required part is `SecurityRule.Incomplete`; it never matches (`Rule.Ignored`), the parser emits a diagnostic and the firewall an issue. Unreadable operands count as present.
- A rule's unresolved parts are classified: those that can only add to an OR-list (unknown members, domain names, invalid include entries) leave `Rule.Certain` = Match, which first-match decides for sure; only the rest of `Bound` is a possible match. Unresolved exclusions, cycles, negation of an inexact dimension, and narrowing criteria (applications, users, schedules, unknown zones) leave nothing certain.
- An address object with only `exclude` lines means every address except them (to be confirmed on a device).
- PAN-OS interface addresses written with the interface mask translate to the host.
- Complementary policy-route branches that reach the same egress are folded into one unconditional path; a firewall with interfaces in layer-2 zones asks for zones (`--from-zone/--to-zone`), and a single firewall is then evaluated on the named zones.

## Consequences

Predefined services missing from a vendor book no longer hide certain matches; supply the device's definition with `--service-book` to decide the rest.
