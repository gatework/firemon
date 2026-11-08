# Business requests through recovery

This iteration applies the actual Perl business abstractions to the immutable Go
graph. The sources and intentionally stronger checks are recorded in
[Perl business evidence](business-oracle.md). Parser construction remains the
separate [Content/Builder design](parser-design.md).

| Business step | Go boundary | Preserved evidence |
| --- | --- | --- |
| Collection | `Collector.CollectBatch` | Per-device CAS, incomplete captures, independent failures and session closure |
| Location and query | `inventory.Cache`, `inventory.Index`, `Searcher.Query` | One manifest generation, revision-bound ownership/ingress, exact coordinate views |
| Inspection/analysis | `Inspector`, `RevisionComparer`, `RiskAnalyzer.AnalyzeBatch` | Typed paths, declaration versus effective behavior, unknown truth and versioned standards |
| Design | `Planner.PlanBatch`, `PlanNativeBatch`, `BatchDesigner.Design` | Independent input disposition, one final device plan, whole-target and outside proofs |
| Native additions | `NativeRequest` | Exact NAT effects, atomic dependencies and optional finite schedule/packet proof |
| Usage/lifecycle | `NativeUsage`, `Reclaimer`, `Migrator`, `Converger` | Positive tuples, counter epochs/windows, explicit selections and mappings |
| Apply/recover | `BatchExecutor`, existing `deploy.Engine` | Durable explicit selection, original snapshot reconstruction, exact authorization, no uncertain replay |

## Request shape and partial results

The usual input contains source, destination and optional service text:

```json
{"requests":[
  {"id":"web","src":"192.0.2.1, 192.0.2.2","dst":"198.51.100.10","service":"443"},
  {"id":"dns","src":"192.0.2.3","dst":"198.51.100.53","service":"udp/53"}
]}
```

Within one row, the normalized source × destination × service product is the
application, as in Perl `RuleOtimize.changeRuleToSet`. Different rows retain
independent exact associations. Addresses accept hosts, CIDRs and inclusive
ranges; services accept ports/ranges with optional `tcp/` or `udp/`. Bare ports
mean TCP. Whitespace, list punctuation, full-width ASCII, enclosing quotes and
clipboard BOM are cleaned; duplicate/overlapping values are normalized. Invalid
addresses, masks, ports or unmatched address families reject that whole row with
its original offending token, while valid siblings continue. Resource exhaustion
or cancellation aborts the batch and invalidates every proposed plan.

Omitted service means all services for query and cannot authorize a new rule.
Explicit `any` is separate intent, still subject to renderer and safety proofs.
`normalized.service_specified` records the distinction even for blank clipboard
cells. `version` defaults to 1 in requests. `src`/`dst`/`service` cannot be combined
with native traffic or effects. The lower-level `traffic` representation remains
an exact union of paired regions; for an explicit native policy target:

```json
{
  "version": 1,
  "requests": [{
    "id": "ticket-item-1",
    "sources": ["ticket-42"],
    "traffic": [{
      "Source": {"First": "192.0.2.10", "Last": "192.0.2.10"},
      "Destination": {"First": "198.51.100.20", "Last": "198.51.100.20"},
      "Protocol": {"Low": 6, "High": 6},
      "SourcePort": {"Low": 1024, "High": 65535},
      "DestinationPort": {"Low": 443, "High": 443},
      "ICMPType": {"Low": 0, "High": 255},
      "ICMPCode": {"Low": 0, "High": 255}
    }],
    "targets": [{
      "device": "lab", "revision": "IMMUTABLE_REVISION",
      "policy": {"from_zone": "inside", "to_zone": "outside"}
    }]
  }]
}
```

Use `firemon request-query --store DIR --file request.json` or `request-plan`.
These commands are offline; JSON output is for review. Set target `packet: true`
to require the vendor packet pipeline with explicit ingress and VRF. A policy
target alone does not assert route reachability or wire admission.

Omitting `targets` searches both endpoints through local address indexes and
native packet contexts. Connected networks, named values, non-default routes and
NAT declarations identify candidates; they never prove protection or ingress.
Topology evidence is applied to exact traffic fractions, so an unknown source
does not discard another source with established ingress and protection. Missing
forwarding still permits conditional declaration lookup in actual native chains,
including named ASA ACLs. Without topology, results remain `conditional` and cannot
produce a plan. A default
route alone does not discover a device. Reversible aliases are forward checked,
static translations can discover related devices, and dynamic pool possibilities
are never propagated as exact packets. Associations retain scope, VRF, time and
source references; they do not claim one end-to-end physical path.

Configure `SearcherOptions.Topology` and `BatchDesignerOptions.Topology` once, or
supply `--topology topology.json` for CLI queries and designs.
The topology has `version: 1` and `bindings`, each with `device`, `revision`,
`scope`, `vrf`, `zone`, `role` (`protection` or `ingress`), `view`
(`original`, `real`, `translated`), `networks` and optional `sources`.
Protection identifies business ownership; ingress identifies where packets
enter. Routes supply forwarding evidence, never ownership. Scope/VRF null means
all contexts; an empty string selects the default. All bindings are checked
against one frozen manifest and its immutable revisions.

`real` means post-destination/pre-source translation; `translated` means final
translation. Supported static aliases propose wire candidates, then ordered
forward packet evaluation proves the exact view. Explicit `wire_candidates`
can supply other proposals. Ambiguity, missing mappings, unsupported inverse
composition, dynamic allocation and unknown routing stay visible; they do not
become successful business requests. `NativeRequests` retain evaluator/planner request coordinates separately from
wire/real/translated traffic. Actual `Policy` decisions can use a different view
(for example post-DNAT Fortinet traffic); `PacketPath.PolicyNAT` records that
relationship and `OriginalTraffic` restores the exact wire fraction.

A long-lived `Searcher` holds a bounded `inventory.Cache`; share that cache with
`BatchDesigner` to reuse graphs across query and design. Each call freezes a fresh
manifest. Loading a revision never reparses configuration or reads a database.
The cache stores neither manifest state nor decisions, so a publication,
reservation or time change is visible on the next call. Incomplete published
evidence remains queryable with diagnostics and conditional outcomes, and cannot
produce a configuration plan.

`at` defaults to one sampled instant for the batch. Alternatively, `window` has
inclusive `Start` and exclusive `End`; every known policy/NAT boundary and timezone
transition partitions the interval exactly, including repeated states. Unknown
schedules retain unknown evidence. Each rule match reports declared geometry,
effective first-match traffic, original coordinates, disabled state and schedule
status (`always`, `active`, `inactive`, `not_started`, `expired`, `unknown`).
`traffic_view` distinguishes original packet from direct native-policy coordinates;
`DeclaredKnown`, `EffectiveKnown` and `OriginalKnown` are independent evidence.
Fortinet VIP selection and ASA multi-ACL contexts remain native engine behavior.

Finite design uses capture-bound `BatchDesignerOptions.Clocks`, keyed by device,
or CLI `--clocks clocks.json`. The resulting native lifetime proves before,
throughout and after the interval. Missing clock evidence leaves the input
pending; it never falls back to an unrestricted lifetime.

Input dispositions are `covered`, `accepted`, `rejected`, `pending`. An
independent invalid input does not discard safe siblings. Policy plus requested
NAT and schedule effects for one input form one atomic candidate: refusal leaves
no orphan declarations. Accepted candidates share names and one final whole-device
proof/render. Operational failures, cancellation, proof-budget exhaustion or a
failed final wire recheck produce no executable plan for that device. Attempts
are bounded explanations; a non-nil final Plan is the executable boundary.
`BatchSource` links device-local inputs back to original input/outcome indexes.

## Capability and evidence boundaries

- [Native NAT creation](native-nat-creation.md) lists verified creation forms,
  including the subsequent PAN addition. Existing NAT and NAT-owner edits remain refused.
- [Temporary policies](temporary-policies.md) support narrow absolute-window
  forms on Hillstone, Fortinet, Huawei and ScreenOS. Capture-bound clock and native
  endpoint evidence are required. Existing session termination is not modeled.
- [Analysis reports](analysis-reports.md) cover address paths, risk, revision
  comparison, convergence and batch collection. [Native usage](native-usage.md)
  covers bounded session/counter input and offline reclamation/migration commands.
  Usage absence is not deletion authority. The subsequent
  [migration implementation](../vendors/MIGRATION.md) adds selected NAT dependencies
  and [typed schedules](../vendors/SCHEDULES.md) with complete-plan proofs.
- [Selected execution](batch-execution.md) covers the persistence and recovery API.
  The host supplies sessions and per-device authorization; the offline CLI has no
  credential or online execution mode.

The 2026-11-07 development cleanup replaces legacy approval encodings with version
4 and explicit intent kinds. Reconstruction format 2 replays business inputs and
requires both retained snapshots for migration. Snapshot semantic format 10
persists the typed calendar model and rejects older formats. Reimport original
captures with independently verified clock evidence into a new store; restoration
never reparses or retroactively upgrades evidence. See the
[domain implementation report](2026-11-07-domain-improvements.md) for those lifecycle
changes and the [query implementation report](2026-11-07-search.md) for the current
simple-input, cache and matching APIs. Earlier approval byte fixtures are removed.

Local tests use synthetic native captures, isolated Perl sources and simulated
sessions. [Verification and measurements](business-verification.md) separate
those results from CI publication and real-device/firmware acceptance.
