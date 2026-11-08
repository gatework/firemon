# Native NAT migration boundary

The registry composes `plan.Renderer`, `plan.NativeRenderer` and
`plan.MigrationNATCompiler`. Native adapters retain their own command grammar.
`MigrationCompiler` resolves source addresses and services once per bounded
compilation, maps explicitly selected contexts and interfaces, and constructs
target-owned declarations. It retains separate `StaticNAT` and `DynamicNAT`
objects. Candidate objects have no source capture spans.

Compilation is not a proof or an authorization. `Planner.Migrate` binds the source
snapshot and target baseline, proves the source's selected effective policy and
packet behavior, and preserves target behavior outside that domain. Unsupported
target forms return `MigrationError` with an object, code and reason; no partial
delta is returned. Native rendering independently validates identities, release
gates, order, ownership and all dependencies before commands are available.

## Current verified boundary

| Target | Native compiler forms | Boundaries |
| --- | --- | --- |
| PAN-OS 10.2 | Fixed source mapping, source pools with/without PAT, captured interface PAT, single-host constant DNAT and destination-port translation, identity NAT | Append-only ordered NAT, one concrete service object, explicit source mapping, default selected vsys; unsupported native selectors are rejected |
| Junos 21.4R3 | Source pools with/without PAT; destination pool to a single host and optional fixed port | Exact prefix match values, one service rectangle, native ingress-only DNAT rule-set, explicit source/destination zones for source NAT; conflicting existing rule-set contexts are rejected |
| Huawei V500R005 | Source pools with/without PAT, captured interface PAT, destination pool to a single host and optional fixed port | Native `nat-policy` stages, literal ownership, retained pool and interface evidence |
| FortiOS 7.2 | New policy-owned overload pool or interface source NAT | Requires an explicitly mapped source policy owner; port allocation and interface address must remain identical |
| ScreenOS 6.3 | New policy-owned DIP or interface source NAT | Requires an explicitly mapped source policy owner and captured egress interface; DIP namespace and reserved-port domain are retained |
| ASA 9.16, Hillstone 5.5R8 | No target NAT migration compiler in this increment | Existing native creation/rendering remains available; selected migration effects receive an explicit refusal |

The compiler rejects implicit reverse/static bidirectional effects, VIP owner
rewrites, unknown match conditions, disabled selected translations, source-port
mapping forms, and compound source+destination declarations where target stages
cannot express the same native declaration. A source NAT object's full match is
not silently reduced to a selected policy's match: if that would affect an
unselected policy on the target, the planner's outside-domain proof rejects it.

The current allocation model resolves a zero PAT pool port field to 0–65535;
Huawei's explicitly stored 0–65535 has the same modeled allocation domain. SRX
and ScreenOS's 1024–65535 allocation is different and is never widened or narrowed
to make migration pass. No-PAT preserves the input source port regardless of a
stored pool port field. These are possible allocation relations, not observed
session bindings.

## Executable evidence

`migration_nat_test.go` provides full `Migrate` and independent native `Verify`
cases for PAN↔Huawei PAT, all six directed no-PAT pairs between PAN/Huawei/SRX,
PAN↔Huawei interface PAT, FortiOS policy-owned PAT to PAN and Huawei, and native policy-owned migration on
FortiOS and ScreenOS. PAN-to-PAN fixed source and destination+port migrations
also pass the full proof and independent readback. Native captures are written from the intended behavior;
only generated names are substituted. Generated commands are not replayed as
verification input.

The same tests reject pool endpoint drift, missing interface mappings, PAT port
domain changes, missing target forms, target NAT where the source has identity
behavior, and NAT effects that exceed a selected rule. Direct compiler tests
separately verify five native DNAT+port directions and PAN fixed source mapping.
Those compiler tests establish native expression and exact NAT query results;
they do not claim general cross-vendor DNAT packet migration. Native policy
coordinates and reverse dependencies still require the planner's full proof.

`migration_preimage_test.go` additionally proves Huawei-to-Huawei destination
address/port migration with an independently authored native capture and rejects
translation broadened to an unselected source. Selected policy ownership is
pulled back through `PacketPath.PolicyNAT` with `Engine.OriginalTraffic`, preserving
mixed selected/unselected traffic instead of rejecting every mixed partition.
Query aliases support reversible port offsets and singleton constants, with
native Match narrowing and full forward validation. This does not expand the
compiler's source-port or implicit reverse-NAT forms. Full SRX DNAT-port migration
still fails the existing equivalence proof; its alias/pullback tests are not
complete migration evidence.

`paloalto_native_test.go` exercises independently captured fixed source, pool
PAT, pool no-PAT, interface PAT, destination+port and identity forms, and refuses
a changed capture against the original typed delta.

## References and retained differences

The Perl references are
`Firewall/Config/Parser/Srx.pm` (`parseNatPool`),
`Firewall/Config/Parser/Huawei.pm` (NAT pool and NAT policy parsing),
`Firewall/Config/Element/NatPool/{Srx,Huawei}.pm`, and
`Firewall/Config/Element/DynamicNat/Huawei.pm` under the reference backend.
They retain pool direction, address ranges, native destination pool ports,
`fromZone`/`toZone`, `natSrcIpRange` and destination translation fields. Go keeps
these meanings while retaining explicit allocation mode, unknown evidence,
ordered relations and stricter packet-preservation proofs.

PAN's first-match NAT ordering and source/interface/destination translation
forms are described by the official [PAN-OS 10.2 NAT policy documentation](https://docs.paloaltonetworks.com/ngfw/help/10-2/policies/policies-nat)
and [translated packet fields](https://docs.paloaltonetworks.com/ngfw/help/10-2/policies/policies-nat/nat-translated-packet-tab).
The current reference Perl tree has no PAN-specific parser to substitute for
those native definitions. None of the local fixtures establish live-device
acceptance or vendor parity beyond the listed forms.
