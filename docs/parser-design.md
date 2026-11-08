# Native configuration parsing

Firemon uses the Perl `Firewall/Config/Content` and `Firewall/Config/Parser`
implementations as a business reference. The Go implementation keeps the useful
algorithm: retain source, recognize declarations in dependency order, accumulate
native objects, then bind references. It also keeps Go's stricter scope,
unknown-condition, cancellation and immutable-result contracts.

## Ownership and data flow

```mermaid
flowchart LR
    capture[Capture or offline source] --> content[Content: raw bytes and evidence]
    content --> native[Native structure and scope]
    native --> phases[Explicit parsing phases]
    phases --> builder[Builder: ordered typed records]
    builder --> graph[Seal: immutable graph and bindings]
    graph --> snapshot[Snapshot publication]
    graph --> policy[Query, NAT and planning]
```

`Content` composes `github.com/gatework/parser v0.1.0` for immutable source
bytes, physical line indexes, byte positions and a cached SHA-256. Firemon owns
the Pending/Parsed/Ignored ledger, capture completeness and schedule clock.
Reading never claims semantic success; there is no shared cursor or duplicate
parsed-flag state. The native scanner
builds structure once, keeping opaque containers and their descendants scoped.
Statements retain spans into the original immutable string; quoted multiline
text cannot be reinterpreted as independent commands. XML keeps its original
byte fragments instead of regenerating a textual configuration.

`Builder` is the only owner of accepted mutable records. Each concrete catalog
has an ordered slice and an ID index. Native order comes from slices and explicit
position fields, never map iteration. Factory/parser instances do not retain
Builder state between Parse calls. Temporary native drafts and indexes describe
one phase; they do not hold a second accepted `fm.Data` graph.

A transaction introduces records with `Emit` or explicitly replaces existing
records with `Replace`. Replacement retains position. Both copy only the supplied
records. Commit validates all typed identities and source claims before applying
any change. A duplicate ID cannot consume configuration evidence. Vendor code
chooses whether repeated syntax appends, replaces or is invalid; the table does
not infer that policy. Typed lookups and category views return isolated copies;
Has methods inspect identity without copying records.

Each native Parse entry lists `Builder.Phase` calls in dependency order. Phase
failure or cancellation restores records, indexes, evidence and the cached graph. Internally, append boundaries and replacement undo entries
avoid cloning the entire catalog. Nested phases retain undo until their enclosing
phase succeeds. Transactions cannot escape the phase that created them.
Builders are synchronous, invocation-local construction objects, not concurrent
containers. Only sealed graphs are shared.

`Builder.Seal` delegates the ownership copy to `firemon.Seal`, which validates and
binds typed references, groups, interfaces, routes, rules and NAT. It caches that
immutable result until the next record/evidence commit. Parsers needing resolved
addresses/services at an intermediate dependency boundary reuse this mechanism.
They do not call `Data` before Seal and pay for a second full graph copy.

## Perl algorithm mapping

| Perl responsibility | Go contract |
| --- | --- |
| Content::Static source and parsed flags | Immutable parser.Content index plus Firemon Pending/Parsed/Ignored ledger |
| `ignore`, `goToHead`, `backtrack` | Defer by leaving Pending; each phase reads scoped declarations without changing evidence |
| Parser::Role native passes | Explicit vendor phase functions with cancellation and transactional rollback |
| Parser::Elements typed dictionaries | Builder concrete typed tables, native identity indexes and stable ordering |
| Reopened object mutation | Phase-local native accumulation; explicit accepted-record replacement when needed |
| `addRouteToInterface`, `addZoneRange` | Interfaces before routes, scoped longest-prefix binding, immutable topology |
| Parser::Report expanded sets | Policy engine derives views from the immutable graph |

Perl `ignore` clears the consumed flag and advances: it means defer. Go
`Transaction.Ignore` is reserved for syntax known to be irrelevant and requires a
reason. Unknown source remains Pending; unknown members remain attached to the
owning object. Unknown, empty and any remain different states.

Perl's read-immediately-marks-parsed behavior, dynamic Moose dispatch and mutable
report/database coupling are not imported. A confirmed limitation illustrates
why: unindented `service` inside a Hillstone rule can be mistaken for a top-level
service by the Perl first pass. Go retains its native block ownership instead.

## Native responsibilities

| Vendor | Grammar and dependency contract |
| --- | --- |
| Hillstone | Scoped blocks; reopened objects accumulate in first-seen order; literal and referenced address members coexist; declared service precedes same-name service group; network/objects precede rules and NAT |
| Huawei | Indentation and `#` boundaries; opaque unknown blocks; indexed members replace within reopened definitions; network/routes/objects precede policies and NAT |
| Fortinet | Config/edit/next/end hierarchy; selected VDOM plus explicit global settings/interfaces; network and objects precede VIP/pools and policy-owned NAT; repeated fields retain validation |
| SRX | Display-set paths, logical interfaces and address-book attachment; scoped lookup and application-term pairing; policies before dependent NAT |
| Netscreen | Policy continuations and virtual-router ownership; zone then Global lookup; interface NAT precedes policy parsing, policy NAT follows accepted rules |
| ASA | Object/interface blocks versus top-level ACL/NAT commands; ACL interface bindings before rules; inline identities; legacy and modern NAT kept distinct |
| Palo Alto | Native set paths or XML fragments; shared/vsys selection and original XML evidence; object/network dependencies before security/NAT rules |

Files within each vendor separate entry/orchestration, structure, network,
objects, policy and NAT where those responsibilities exist. Scalar native
address/port helpers remain reusable. There is no universal grammar registry or
mutable object hierarchy. A full category view needed repeatedly is captured
once per phase; individual references use indexed lookups. The large-topology
benchmark protects against accidentally cloning a whole catalog per policy.

## Hillstone components and range sets

The StoneOS parser composes three invocation-local components:

- `document` retains scoped blocks, statement order and every reopening of a
  native definition. The scanner handles syntax; it does not claim evidence.
- `catalog` owns address/service reference kinds and the supplied service book.
  Definition records remain in Builder's typed tables. Explicit configuration
  wins over the external book; absent definitions remain unknown.
- `topology` owns zone-to-VRF lookup and parses zones, interfaces and routes.
  Interface binding precedes connected/static routes. Final next-hop resolution
  and zone networks remain graph responsibilities.

The entry point calls structure, zones, interfaces, objects, routes, rules and
NAT phases explicitly. Rule selectors use the catalog and topology. NAT resolves
addresses and services against a local immutable graph at its dependency
boundary; it emits distinct StaticNAT and DynamicNAT records. No Builder or
intermediate graph is retained by the public Parser between invocations.

This follows Hillstone.pm's `parseZone`, `parseInterface`, `parseAddress`,
`parseService`, `parseServiceGroup`, `parseSchedule`, `parseRoute`, `parseRule`,
`parseNat`, `addRouteToInterface` and `addZoneRange` responsibilities. Go retains
scope-aware graph binding, typed records and exact unknown evidence rather than
Moose class dispatch or mutable report state. Perl looks up predefined services
before native declarations; Go deliberately retains explicit-definition
precedence and caller-selected service books.

`flow.AddressSet` uses a private `set.Set[uint32]` value from
`github.com/gatework/set v0.1.0` for IPv4 normalization, union, intersection and
inclusion. IPv6 remains in exact address intervals; mapped IPv6 is not unwrapped.
The published dependency has no difference operation, so exact subtraction stays
in Firemon. Reversed ranges are rejected before the integer library can reorder
them. Value copies and returned ranges remain isolated. Service terms keep their
protocol/source-port/destination-port pairing and the traffic engine retains its
bounded multidimensional algebra.

## Public API and migration

The business boundary remains:

```go
Parse(context.Context, config.Source, firemon.Metadata) (*firemon.Firewall, error)
```

Parser, ParseFunc, Source, Limits and XML node navigation retain their roles.
The subsequent calendar work uses concrete typed graph records and snapshot
semantic format 10; package-level native Parse/ParseVDOM have been removed in
favor of `Parser.Parse` and `Metadata.Context`. Low-level changes are intentional
and have no compatibility aliases:

| Previous | Current |
| --- | --- |
| NewCursor / NewFragmentCursor / NewFragmentContent | NewContent for CLI; XML constructs its own fragment ledger |
| NewSession, Session.Cursor | NewBuilder, Builder.Content |
| Cursor.Begin, Transaction.Commit(*Data) | Builder.Begin, Builder.Commit |
| Session.Run and Stage.Requires | Explicit Builder.Phase calls |
| Seal(session.Data()) | Builder.Seal() |
| XMLDocument.Cursor | XMLDocument.Content |
| config.Line | parser.Line; Text retains indentation and strips only the line ending |
| Peek / NextPending / Rewind / Checkpoint / Restore | Removed; stages read immutable structure and commit evidence explicitly |

This foundation refactor leaves parser identities and snapshot semantic format
unchanged. Existing snapshots load their stored records without reparsing.
No reimport is required solely for this change. See the
[foundation verification](2026-11-07-parser-foundation.md) for corpus equivalence
and the earlier [parser evolution](2026-11-07-parser-corpus.md) for current
Hillstone and Palo Alto syntax support.

The default source bounds remain 16 MiB, 200,000 physical lines, 200,000 XML
fragments and depth 64. XML now checks physical lines exactly, including a final
unterminated line; the former newline counter could admit one extra line.
Firemon keeps UTF-8 validation and context checks in addition to library bounds.
No new vendor syntax or firmware parity is claimed. The six actual-Perl synthetic
comparisons cover shared object and rule contracts; Palo Alto has no parser in
the supplied Perl directory. See [rewrite verification](parser-rewrite-verification.md)
and the earlier [Hillstone refinement evidence](parser-verification.md).
