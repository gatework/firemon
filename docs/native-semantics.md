# Native semantics evidence

## Hillstone

The [StoneOS 5.5R8 E-Pro guide](https://www.hillstonenet.com/wp-content/uploads/StoneOS_WebUI_User_Guide_E-Pro.pdf), printed pages 29–31, places BNAT before ordinary NAT in each direction, destination selection before routing and source selection after routing. Address rewriting occurs after session establishment. The implementation infers original-packet selection for the combined pipeline from that delayed rewrite sequence and enables mixed regular chains only for the explicit `5.5R8` software family. A real-device trace is still needed to validate interoperability; other version families remain unsupported for mixed evaluation.

The [5.5R5 CLI guide](https://kb.hillstonenet.com/en/wp-content/uploads/2017/11/StoneOS_CLI_User_Guide_Complete_Book_5.5R5-1.pdf), NAT chapter, identifies `static`, `dynamicip` and `dynamicport` as separate SNAT modes and defines BNAT as a bidirectional fixed mapping. Fixed SNAT is represented by `StaticNAT`; pool allocation remains `DynamicNAT`. This source does not establish mixed-chain behavior for 5.5R5.

Native SNAT and DNAT IDs have separate namespaces inside each VRF. Go catalog IDs retain VRF and chain (for example `trust-vr/snat:1`); `Object.Name` retains the device ID. BNAT's inverse is an execution reference to the same `StaticNAT`, not another persisted object. Multi-step results carry each selected reference in `NATRelation.Steps`.

Unsupported selectors, invalid references and unproven mappings consume potential traffic as unknown. Missing egress evidence cannot satisfy an `eif` selector. Each stage shares the evaluation visit budget.
