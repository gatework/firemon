# Offline inspection and analysis reports

All commands below load an explicit immutable snapshot revision. They never
reparse configuration, connect to devices, read usage counters, or consult a
DB. Reports identify the exact revision and graph digest. `complete` describes
the loaded graph; risk and exposure values retain their own unknown state.

```sh
firemon inspect-address --store ./snapshots --revision REV --file inspection.json
firemon risk-report --store ./snapshots --revision REV --file risks.json
firemon convergence-report --store ./snapshots --revision REV --at 2026-10-30T00:00:00Z
firemon compare-revisions --store ./snapshots --revision BEFORE --after AFTER --at 2026-10-30T00:00:00Z
```

The optional proof horizon `--at` applies to convergence and comparison.
Scheduled policies may require it. Input JSON is version 1, at most 4 MiB, with
unknown fields and trailing documents rejected. Reports are at most 16 MiB and
are fully encoded before any output is written. `--max-visits`, `--max-regions`
and `--max-combinations` can lower the default limits of 100000, 4096 and 4096;
they cannot raise them. Budget errors fail the command without a partial report.

## Address inspection

An inspection selects exactly one typed address/address-group identity or an
address range set. Nested paths preserve every typed group hop. Rule references
retain source/destination roles. The selector describes declaration inventory;
it does not itself imply access. Service restrictions belong in the explicit
traffic evaluation context, not in a separate service-catalog selector.

```json
{
  "version": 1,
  "object": {"Kind": 1, "ID": "host-object"}
}
```

`Kind` 1 is an address and 2 is an address group. Alternatively:

```json
{
  "version": 1,
  "addresses": [{"First": "192.0.2.1", "Last": "192.0.2.1"}]
}
```

Optional `evaluation` contains `traffic`, `scope`, `ruleset`, `from_zone`,
`to_zone`, `egress_interface`, and `at`. Traffic is an array of exact paired
regions, for example:

```json
{
  "traffic": [{
    "Source": {"First": "192.0.2.1", "Last": "192.0.2.1"},
    "Destination": {"First": "198.51.100.1", "Last": "198.51.100.1"},
    "Protocol": {"Low": 6, "High": 6},
    "SourcePort": {"Low": 0, "High": 65535},
    "DestinationPort": {"Low": 443, "High": 443},
    "ICMPType": {"Low": 0, "High": 255},
    "ICMPCode": {"Low": 0, "High": 255}
  }],
  "ruleset": "security",
  "from_zone": "inside",
  "to_zone": "outside"
}
```

Exposure describes the **entire evaluation request**, independently of the
inventory selector. Declared match and effective first-match ownership are
separate values: 0 unknown, 1 false, 2 true. Disabled and shadowed rules can have
a declaration match while having no effective ownership. Action is reported
separately; ownership by a deny rule is not permitted access. Wildcard rule
references appear only when an evaluation context is supplied. Inventory
`contains`/`overlap` relations describe declared address ranges, not behavior.

Optional `aliases` is `{ "request": CONTEXT, "vrf": "", "view": "real" }`
(or view `translated`). Its request is explicitly in business coordinates and
requires ingress evidence. It is distinct from the native policy coordinates
of `evaluation`. Each alias includes exact business and wire regions and native
NAT steps, after ordered forward verification. Ambiguous, unknown and unmatched
business regions remain separate. Unmatched means no discovered/proven static
alias; it does not exclude an unobserved session mechanism. Existing alias
limitations apply to arbitrary multistage inverse compositions and port inverses.
Dynamic pool relations are catalog relations with `possible_allocation: true`;
they do not establish sessions or effective translation. Disabled state remains
visible. Paths are bounded to 64 hops, report rows to MaxCombinations, and total
retained exposure/alias/pool regions to MaxRegions.

## Risk and convergence

Risk JSON contains `version`, `contexts` (the explicit contexts above), and
`definitions`. A paired standard has `id`, `version`, `mode`, `relation`,
`traffic`, and optional `actions`. Modes: 1 declared, 2 effective. Relations:
1 intersects, 2 contains, 3 within, 4 equal, 5 not equal. Actions default to permit.

A compound standard uses `expression` instead of paired `traffic`/`relation`:

```json
{
  "id": "restricted-source",
  "version": "1",
  "mode": 2,
  "expression": {
    "any": [{
      "predicate": {
        "dimension": 1,
        "relation": 1,
        "addresses": [{"First": "192.0.2.1", "Last": "192.0.2.1"}]
      }
    }]
  }
}
```

Each expression has exactly one predicate, nonempty `all`, or nonempty `any`.
Dimensions are source=1, destination=2, service=3. Service predicates use
`services` arrays of complete service terms (Protocol, SourcePort,
DestinationPort, ICMPType, ICMPCode intervals). Standards are prepared once per
definition across contexts. Preparation nodes/regions, evaluation visits/nodes,
and retained finding traffic are separately cumulative across the batch.
Findings carry context/definition indexes, policy version, graph digest and
three-valued truth. Empty intersections are false under both AND and OR.

Convergence groups complete exact compatibility signatures before matching
pairs, retaining native pair order and nil/empty slice distinctions. Reports
show proven plan digest, changes and whole-policy preservation evidence, or
`unproven` for a directly rejected candidate. No plans are applied or implicitly
combined. Operational errors and budget failures stop the report.

## Revision comparison

Comparison requires both graphs to name the same device, vendor and context.
It separates raw text changes, added/removed/modified typed declarations, native
rule order, and direct NAT declaration/pool/order changes. Source spans do not
create declaration changes. NAT dependencies also remain visible in their own
object catalogs. Behavior is `equivalent` only after complete policy and NAT
preservation proofs; `unproven` includes changed, incomplete and unsupported
evidence. A declaration difference alone never establishes a behavior change.

## Batch collection API

`Collector.CollectBatch(ctx, requests, CollectBatchOptions{Workers: 4})` is a Go
composition API for a host's injected capture dependencies; it has no offline
CLI transport. The default is four workers and the batch bound is 100 items.
All occurrences of duplicate device IDs are excluded before opening sessions.
Each input gets an ordered CollectOutcome with request, result, fixed status,
and an in-process error supporting `errors.Is`. Transport errors are omitted
from JSON. Local failures do not cancel siblings. Each call retains independent
CAS, publication idempotency and timeout behavior from Collector.Collect.
Cancellation stops new scheduling, waits for session closure and preserves
observed incomplete live evidence. Injected Store, Parser and Sessions must
support independent concurrent calls.
