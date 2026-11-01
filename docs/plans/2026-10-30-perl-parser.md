# Perl-grounded configuration parsing

The user asked to study Firemon against the local Perl Firewall implementation,
especially `Config/Parser` and `Config/Content`, and bring its clearer business
abstractions into Go. Work is local; this task does not publish code or operate
devices. The Perl source is read-only and is not a Go dependency.

## Findings and design

`Content::Static` owns source lines, the cursor and per-line parsed flags.
`nextUnParsedLine` tentatively consumes a line; `ignore` puts it back into the
pending set while advancing the cursor. `goToHead` resets position without
resetting parsed flags. Go's `config.Cursor` already preserves this distinction
more explicitly: reading never claims evidence, and `Transaction` commits
records and claims together. Keep that ownership model.

`Parser::Elements` indexes objects by type and native identity. Hillstone's
`parseAddress`, `parseService`, `parseServiceGroup`, `parseZone` and
`parseInterface` retrieve an existing object before adding content. The Go
Hillstone parser currently merges repeated rule blocks, but emits duplicate
records for these other declarations. Its address-kind inventory can also be
overwritten by a later empty reopening, losing a group reference.

Use ordered, parser-local named definitions to collect each object's blocks,
then interpret one typed draft and commit its actual source claims. Inventory
address/service kinds before resolving forward references. Keep native syntax
and merge rules in Hillstone; Fortinet's repeated `set`, Huawei's indexed
members, ScreenOS scope and Junos set paths are different contracts.

Separate Hillstone source by responsibility within the existing package:
orchestration, structure/evidence, network, objects, policy and NAT. Extract
small object parsers from the current object-family switch. Public APIs,
immutable graph ownership, snapshot format and supported vendor scope remain.

Alternatives considered: a line-handler registry obscures native scopes and
dependencies; a shared cross-vendor object builder would prematurely equate
different grammars. A focused native implementation uses the existing Go
types and transaction mechanism with fewer implicit state transitions.

## Ordered work

1. Record a fresh whole-module test baseline. Mechanically separate existing
   Hillstone functions, proving declaration text and behavior unchanged.
2. Add observable regressions for reopened address/service/group and network
   objects, later empty declarations, forward references and retained unknown
   members. Compare a bounded synthetic case with the real Perl parser.
3. Collect named definitions and parse typed drafts; preserve native order,
   ownership and source evidence. Do not infer schedule, FQDN, NAT or other
   unsupported semantics from this work. Keep the Session as the sole draft
   owner; remove the unused object-stage full graph copy and parser-held session.
4. Document the full module responsibility chain and seven-vendor findings,
   including where Go deliberately retains stronger evidence semantics.
5. Run root tests with race detection, vet and build; exercise existing parser
   benchmarks as a regression check and record the exact verification scope.

Further source tracing reproduced silently discarded Hillstone block-header
suffixes (`address a unsupported`, `policy-global unsupported`, and
`rule id 1 unsupported`). Add a separate behavior regression and preserve these
blocks as pending instead of claiming a fully understood object or policy.

Independent review identified an existing order-dependent service/group name
collision. The actual Perl lookup consistently selects the declared service in
both declaration orders. Add a separate RED/GREEN regression and retain that
explicit precedence; do not add predefined service catalogs.

## Invariants

- A skipped or unsupported member stays pending; no implicit `any`.
- One named object has one identity and all accepted declaration spans.
- Group type comes from all declarations, not the last empty block.
- Different native scopes cannot silently merge.
- Interface binding precedes route binding; reference resolution is independent
  of declaration order.
- Cancellation returns an error and no published partial graph.
- Existing snapshots restore without reparsing; corrected parsing requires
  importing the original capture again.
