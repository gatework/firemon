# Domain and migration implementation

Approved 2026-11-07. Firemon is in development; compatibility shims and historical
wire formats are not requirements. Preserve the existing uncommitted work.

## Contracts

- Seven vendors only: Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen, ASA.
- Concrete immutable graph, separate StaticNAT and DynamicNAT, exact paired
  traffic, native order, unknown evidence and outside-change proofs remain.
- Decomposition means business requests by device/context/zone/NAT coordinates;
  no operation for splitting existing native rules is introduced.
- Migration includes policy dependencies, NAT, absolute and recurring schedules.
  Network objects keep their addresses; scopes, chains, zones, interfaces and VRFs
  require explicit mappings. Network configuration is not generated.
- Typed values, composition, consumer-owned small interfaces and the standard
  library are preferred. Vendor syntax and capabilities have explicit owners.
- Snapshot semantic format 10 and reconstruction format 2 reject old formats.
  Snapshot loading never reparses source. Old files are not deleted automatically.
- Selected migration closure is atomic. Unknown/unrepresentable effects produce
  issues and no executable plan; operational errors stop work.

## Work and ownership

1. Freeze current source and hashes; remove redundant parser/API forwarding and
   historical approval encodings without losing their behavioral tests.
2. Model absolute/weekly/calendar conditions, evaluate them and partition time
   exactly; connect native parsers and renderers with capture-bound clock evidence.
3. Improve exact demand coalescing, object reuse and evidence-rich analysis.
4. Compile migration dependencies into target-native declarations, preserving
   source behavior and target behavior outside the migration domain. Bind both
   snapshots and mappings into approval/reconstruction and independent readback.
5. Verify native positive/refusal cases, cross-vendor policy directions, source
   oracle differences, core and paired adapter tests/vet/build/race, focused fuzz
   and comparable benchmarks; document actual supported forms and remaining limits.

The original source snapshot is
`/private/tmp/firemon-domain-20261107-t9jtb4n9/baseline`; `manifest.json` in its
parent records 716 file hashes. Isolated component copies start from those bytes.
Integration checks that a destination still equals its baseline before replacing
it; conflicting changes are reconciled explicitly.

## Reference boundary

Perl `Config::Content::Static`, native parsers, `Policy::Searcher`,
`Policy::Designer`, `FireFlow::RuleOtimize`, `Config::Ruleopti` and `Config::Audit`
are actual business references. `Config::Policytranf` only loads plugins and its
Fortinet plugin contains empty creation methods, so migration is not claimed as
Perl algorithm parity. Existing oracle metadata's 31 source hashes were checked
against the local source before implementation. No private source is copied here.

Time syntax must preserve ASA absolute/periodic intersection and Junos weekday
overrides. PAN schedules affect new sessions, not existing-session termination.
Clock, endpoint and DST evidence are independent of intended configuration.

## Acceptance

Tests exercise observable behavior, exact set equivalence, atomic evidence,
scope isolation, time boundaries, independent native captures, corruption,
drift, cancellation and budgets. All local and real-device/CI evidence remains
separate. No commit, push, release or device operation is part of this execution.

## Completion and evidence

Implemented and integrated on 2026-11-07. The
[implementation report](../2026-11-07-domain-improvements.md) maps the business
changes to actual Perl sources and records remaining extensions. The
[schedule matrix](../../vendors/SCHEDULES.md) and
[migration matrix](../../vendors/MIGRATION.md) are the current capability authority.

- Typed weekly calendars, exact future partitions, seven native schedule drivers,
  indexed request coalescing, scoped complete-object reuse and risk context evidence
  are integrated. Oversized declarations are charged before materialization.
- The migration compiler preserves separate NAT types, derives selected-rule
  dependency closure, binds both snapshots and explicit mappings, and repeats
  source packet/target outside proofs on independent native readback.
- Approval 4, reconstruction 2 and snapshot semantic 10 replace historical formats;
  forwarding parser/application APIs and old byte-compatibility fixtures are removed.
- Final root test/vet/build/race and paired current-core adapter test/vet/build/race
  pass. All 42 basic policy directions, seven weekly targets and 16 full NAT
  migration cases pass. Five additional DNAT compiler/query cases do not establish
  unrestricted cross-vendor DNAT packet migration.
- Five focused 10-second fuzz runs pass. The current 31 Perl source hashes match;
  optimizer and schedule-boundary Oracles were rerun read-only without networking.
  Comparable local measurements and raw samples are in the
  [benchmark report](../2026-11-07-domain-benchmarks.md).

Unsupported selected effects deliberately produce issues and no plan. In
particular, ASA/Hillstone target NAT migration compilation, general reverse or
mixed-ownership DNAT migration, mixed recurrence timezones and unsupported native
calendar combinations are not advertised as implemented. Their refusal tests and
follow-up acceptance criteria are part of the delivered boundary, not compatibility
fallbacks. No commit, push, release, CI run or real-device validation was performed.
