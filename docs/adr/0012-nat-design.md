# 0012 — NAT design

Status: accepted (2026-11-18)

## Context

Operators ask for access together with a translation: an office subnet leaving by a given public address, a server published on a public address and port, or a one-to-one mapping. NAT rules match first in configuration order, like security rules, so a new rule only works where it matches first, and putting it in front of an existing rule takes traffic away from that rule. The Perl designer added rules at the end of the list, without checking which rule matched first, with `to Any service Any`, and failed when no public address was assigned.

Production configurations show the conventions: StoneOS `snatrule … eif <uplink> trans-to ip <secondary address> mode dynamicport` inside `ip vrouter`, rule IDs that do not follow list order, no `dnatrule` or `bnatrule` in use; PAN-OS `To_<zone>` interface PAT and `DNAT_<server>[-<port>]` port forwarding with the security rule on the pre-NAT address and the post-NAT zone.

## Decision

- `design.Intent.NAT` (`NATIntent`) asks for source NAT, destination NAT (with an optional published port) or static NAT. The intent's addresses are the real ones; the public address comes from the request, else from an existing rule for the same server or on the same egress, else (source NAT only) from the egress interface. Destination and static NAT with no address end as `needs-address`, without commands.
- The planner first evaluates the traffic as the device would: when the rule that matches first already translates as asked the NAT part is `satisfied`. When it publishes the address and port to another server the part is a `conflict`, and `--override` is needed to place a new rule in front of it.
- A new rule matches exactly the intent (sources, destinations, service). It goes in front of the first enabled rule of its list (StoneOS source or destination list, PAN-OS single list, zones considered) that may match the same traffic, or at the end. StoneOS rules get the next free ID of their list; PAN-OS rules get a unique name following the conventions above.
- Changes are `AddNAT` (with `Before` and, for PAN-OS static-ip, `Bidirectional`) and `AddStaticNAT`. `Apply` inserts in order and renumbers PAN-OS precedences. Renderers write StoneOS `snatrule/dnatrule id N before M … ` and `bnatrule` inside `ip vrouter`, PAN-OS `set rulebase nat rules …` with `move … before`, and their rollbacks. The StoneOS parser honours inline `top/before/after`, so appended commands read back in order, and treats `Any` operands as an empty list.
- Verification applies the NAT change, re-queries and requires every path to be translated as asked by the first matching rule. Access is then designed on the configuration with the NAT change, for the traffic as clients send it (the published address for destination and static NAT). Undecidable deny rules that only add application, URL category or user criteria do not block verification of a new permit; the plan warns about them.

## Consequences

The StoneOS inline placement keywords (`before`, `after`, `top`) and `mode dynamicport` must be confirmed on a device before the first deployment; deployment checks that the readback equals the baseline with the plan applied, which catches a device that placed the rule elsewhere.
