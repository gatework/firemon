# Native NAT creation

The additive `plan.NativeRenderer` path creates explicit NAT declarations and their dependencies together with new policy owners or activating rules. Existing NAT and existing policy owners are not edited. Callers supply native identities, exact mappings, pool ranges and intended original traffic; there is no allocation service or random naming.

`Planner.PlanNativeBatch` proves the entire requested relation and preserves NAT outside it. A generated VIP source projection is owned by its requested parent VIP only after native-form validation; it remains subject to the outside proof and independent readback. Typed allocated readback identities distinguish declarations from generated projections. Inline address/service values must belong to a new native parent, and the vendor emitter must validate them before suppressing an independent declaration.

## Verified native forms

The original 20 rows below have synthetic native before/independently authored after captures in `vendors/native_commands_test.go`. Each row runs command/dependency-order assertions, a sample original-to-translated relation assertion, snapshot roundtrip, complete intended/outside relation proof, joint `PlanNativeBatch`, independent `Verify`, and deterministic reconstruction. The after capture is not constructed from emitted commands. This proves the supported offline model, not native device execution.

| Fixture name | Captured software | Form and native dependencies |
|---|---|---|
| hillstone-bnat | 5.5R8 | Equal-prefix bidirectional BNAT; explicit original address |
| hillstone-dnat | 5.5R8 | Directional singleton DNAT |
| hillstone-pool-pat | 5.5R8 | Source dynamic-port allocation over an explicit native range |
| hillstone-interface-pat | 5.5R8 | Source dynamic-port allocation on an explicit egress interface |
| srx-static | 21.4R3 | Zone-scoped static prefix mapping |
| srx-destination-pool | 21.4R3 | Singleton destination pool before its rule set/rule |
| srx-source-pat | 21.4R3 | Explicit source pool before its PAT rule |
| asa-object-static | 9.16(4) | Modern network-object static NAT; address declaration before NAT |
| asa-object-source-pat | 9.16(4) | Modern network-object singleton source PAT |
| netscreen-mip | 6.3.0 | Interface MIP plus a newly created activating policy |
| netscreen-vip | 6.3.0 | Interface VIP/service projection plus a newly created activating policy |
| netscreen-dip-owner | 6.3.0 | Explicit DIP range before a new policy-owned source NAT |
| netscreen-policy-dnat | 6.3.0 | New policy-owned singleton destination/port NAT |
| fortinet-vip | 7.2.8 | VIP, its generated source projection, and a new activating policy |
| fortinet-port-forward | 7.2.8 | VIP port-forward mapping/service and new activating policy |
| fortinet-source-pool | 7.2.8 | Explicit overload pool before a new NAT-enabled policy |
| fortinet-interface-pat | 7.2.8 | New NAT-enabled policy with one established egress interface |
| huawei-server-map | V500R005 | Simple equal-range server map with explicit `no-reverse` |
| huawei-source-pool | V500R005 | Explicit PAT source pool before native NAT policy |
| huawei-destination-pool | V500R005 | Singleton destination pool before native NAT policy |

## Boundaries

Hillstone creation and packet traversal require the narrow StoneOS 5.5R8 family. The packet model selects destination NAT before route lookup, uses original policy coordinates and performs final rewrites for permitted traffic; this is the documented-model inference described in `native-semantics.md`. Four creation fixtures additionally prove full `PacketProofs` and independent readback. Route partitions retain precise original/real/translated traffic. Missing route, wrong VRF, unknown policy and unsupported firmware remain unknown/refused.

For explicit effect proofs, Hillstone enumerates complete concrete interfaces in the captured scope; Fortinet further restricts them to the captured destination zone. Missing, disabled or invalid evidence retains an unknown domain or rejects an incomplete graph. Every applicable interface remains in the proof, with bounded, deterministic enumeration. Direct queries and intents without needed egress remain unknown/refused. This is not a substitute for packet route evidence.

SRX creation uses established zone-only rule-set contexts and singleton destination pools. ASA creation requires modern 8.3+/9.x object NAT syntax; legacy NAT/global and manual/twice-NAT creation are outside this path. Its candidate order must match native static-before-dynamic/source-size/address/name ordering. An insertion can change numeric ranks of surviving objects, but cannot reorder their relative native behavior or bypass outside proof.

ScreenOS creation requires a complete root/device capture for device-wide explicit DIP identity reservation. Selected-vsys capture is insufficient. Existing owner policy mutation, ambiguous egress and overlapping native compositions remain refused. Fortinet requires a selected captured VDOM; the caller enters that VDOM. Ordinary VIP source projections are validated against the parent and are not arbitrary additional NAT. Forced-source VIP creation, multi-interface PAT and unsupported central-NAT forms are not claimed by this matrix.

Huawei creation is gated to V500R005. Bidirectional server-map creation is explicitly refused: established forward/reverse hairpin overlap semantics can remain unknown, so no plan is made executable by excluding that traffic. Larger destination allocation pools, ambiguous Easy-IP and unsupported native modes remain outside the verified forms.

The 2026-11-07 continuation adds PAN-OS 10.2 ordered NAT rendering. Six separately
authored capture cases in `vendors/paloalto_native_test.go` cover fixed source,
pool PAT, pool no-PAT, captured interface PAT, destination plus port, and identity
translation. They establish native rendering and refusal of a changed capture
against the original typed delta. Their test depth is distinct from the original
20-row `PlanNativeBatch` matrix above. [Migration tests](../vendors/MIGRATION.md)
add complete source/target packet proof and independent `Verify` for their listed
PAN migration forms. Bidirectional fixed translation, unsupported selectors,
nondefault vsys and unrepresentable service or pool forms are refused.

Other native syntax beyond these matrices may be rejected even when parsing/query
supports it. Save/commit, native locking, real-device interoperability and
deployment authorization remain separate lifecycle steps.

## Actual Perl reference and intentional differences

The reference is the actual local `Firewall/Policy/Designer/{Hillstone,Srx,Asa,Netscreen,Fortinet,Huawei}.pm` implementation and its parser/searcher callers. The isolated synthetic oracle artifacts are recorded in `.superpowers/sdd/2026-10-30-business-lifecycle/oracle-preparation.md`; no private Perl sources are copied into this repository.

The Go emitters retain explicit caller-owned identities instead of random/date-only names. They emit Fortinet `set extintf`, use Hillstone native syntax rather than the legacy helper's Fortinet pool text, and retain exact requested allocation ranges instead of reusing a wider containing pool. Huawei source prefixes and destination pools are rendered from the requested actual range rather than the observed legacy regex/public-address mistakes. ASA always needs the network object's host/subnet declaration: the old Perl /32 source-PAT branch can omit it. The Go inline guard also rejects an undeclared ASA owner instead of reproducing that invalid command sequence. These are native-valid and safety differences, not textual Perl parity.
