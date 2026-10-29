# Firewall operations remediation

Approved by the user's “执行方案” following the Perl/Go review. Baseline: `72b5aef`.

The implementation retains the seven approved vendors, concrete StaticNAT and
DynamicNAT objects, immutable snapshots, staged cursor parsing, conservative
unknown evidence, and host-owned inventory, credentials and authorization.

## Work units

- Policy proof: establish unchanged NAT catalogs, dependencies, activation and
  effective translation ownership for transfer and ordinary design; rerun the
  same proof against independent readback.
- Device sessions: acquire owned PAN configuration locks before baseline,
  persist recovery tokens, handle queued commits, and exercise seven native
  login/read/execute/persist/readback profiles using synthetic transcripts.
- Lifecycle: explicit migration chain mapping, versioned compound audit
  predicates, revision-bound member usage and bounded convergence discovery.
- Domain: typed VIP-to-NAT and source-map-to-VIP references, validated graph
  resolution and a new snapshot semantic version.
- Policy architecture: one private vendor semantic selection boundary shared by
  policy, NAT, packet and proof operations; small consumer-owned contracts.
- Application: embeddable capture/parse/publication and design/apply/recovery
  assembly, with host-injected storage, sessions and authorization.
- Delivery: focused regressions, full race/vet checks for root and adapter,
  simplification, independent review, documentation and authorized GitHub push.

## Verification contract

Each behavioral correction must first reproduce the original defect, then pass
with the implementation. Exercise native fixtures and independent reparse where
commands are generated. Unknown observations, partial writes, stale revisions,
lock ownership uncertainty and unsupported native semantics must never yield a
successful proof or publication. Local transcript tests do not establish live
device compatibility. No real devices, releases, database or account platform
are part of this work.

## Shared-workspace ownership

The lifecycle worker owns `analysis/`; the device worker owns `deploy/` and the
adapter excluding module files; the domain worker owns the graph, snapshot codec
and Fortinet VIP producer/consumers. The parent owns planner proof, subsequent
policy dispatch, application assembly, docs, module pins and Git integration.
Workers do not commit or stage files.

## Execution evidence

All implementation units are present. Root (21 packages) and current-core
adapter race/vet suites pass. Regressions also corrected parser firmware/time
substitution, out-of-window positive usage evidence, ordinary-address reuse of
VIP selectors, and Fortinet persistence preflight before policy writes.
Cross-vendor contracts and exact test boundaries are recorded in
[contracts](../contracts.md) and [verification](../verification.md).
The simplification pass and independent full review are complete. Review found
three defects in authorization ordering, partial capture retention and unsupported
context labels; all have regression-backed corrections. Native NAT readback and
future ownership transitions also have explicit coverage. Publication and the
adapter's published-core consumer check are the remaining delivery gates;
implementation evidence does not imply device validation.
