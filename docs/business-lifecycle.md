# Business requests through recovery

This iteration applies the actual Perl business abstractions to the immutable Go
graph. The sources and intentionally stronger checks are recorded in
[Perl business evidence](business-oracle.md). Parser construction remains the
separate [Content/Builder design](parser-design.md).

| Business step | Go boundary | Preserved evidence |
| --- | --- | --- |
| Collection | `Collector.CollectBatch` | Per-device CAS, incomplete captures, independent failures and session closure |
| Location and query | `inventory.Topology`, `BatchDesigner.Query` | One manifest generation, revision-bound ownership/ingress, exact coordinate views |
| Inspection/analysis | `Inspector`, `RevisionComparer`, `RiskAnalyzer.AnalyzeBatch` | Typed paths, declaration versus effective behavior, unknown truth and versioned standards |
| Design | `Planner.PlanBatch`, `PlanNativeBatch`, `BatchDesigner.Design` | Independent input disposition, one final device plan, whole-target and outside proofs |
| Native additions | `NativeRequest` | Exact NAT effects, atomic dependencies and optional finite schedule/packet proof |
| Usage/lifecycle | `NativeUsage`, `Reclaimer`, `PolicyMigrator`, `Converger` | Positive tuples, counter epochs/windows, explicit selections and mappings |
| Apply/recover | `BatchExecutor`, existing `deploy.Engine` | Durable explicit selection, original snapshot reconstruction, exact authorization, no uncertain replay |

## Request shape and partial results

Each traffic element is one paired source/destination/protocol/port region. An
array represents their union; independent source and destination lists are never
cross-multiplied. For an explicit native policy target:

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

Omitting `targets` requests automatic location using `--topology topology.json`.
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
become successful business requests. `NativeRequests` retain the actual vendor
policy coordinates separately from wire/real/translated traffic.

Input dispositions are `covered`, `accepted`, `rejected`, `pending`. An
independent invalid input does not discard safe siblings. Policy plus requested
NAT and schedule effects for one input form one atomic candidate: refusal leaves
no orphan declarations. Accepted candidates share names and one final whole-device
proof/render. Operational failures, cancellation, proof-budget exhaustion or a
failed final wire recheck produce no executable plan for that device. Attempts
are bounded explanations; a non-nil final Plan is the executable boundary.
`BatchSource` links device-local inputs back to original input/outcome indexes.

## Capability and evidence boundaries

- [Native NAT creation](native-nat-creation.md) lists the 20 supported creation
  forms across six vendors. PAN retains its existing policy planning; new PAN NAT
  creation is outside this matrix. Existing NAT and NAT-owner edits remain refused.
- [Temporary policies](temporary-policies.md) support narrow absolute-window
  forms on Hillstone, Fortinet, Huawei and ScreenOS. Capture-bound clock and native
  endpoint evidence are required. Existing session termination is not modeled.
- [Analysis reports](analysis-reports.md) cover address paths, risk, revision
  comparison, convergence and batch collection. [Native usage](native-usage.md)
  covers bounded session/counter input and offline reclamation/migration commands.
  Usage absence is not deletion authority; no NAT/schedule migration is promised.
- [Selected execution](batch-execution.md) covers the persistence and recovery API.
  The host supplies sessions and per-device authorization; the offline CLI has no
  credential or online execution mode.

Existing single-plan APIs and legacy approval digest bytes remain available.
Policy batches retain effective options; native approval v2 adds explicit effects
and v3 adds finite lifetime. Reconstruction format v1 is separate. Snapshot
semantic format remains 9. Current parser versions are Hillstone 5, Fortinet 3,
Huawei 3, ScreenOS 3, ASA 3, SRX 2 and PAN 4 (vendor `*-go-N` identifiers).
Old v9 snapshots keep their stored interpretation; reimport original captures
with independently verified clock evidence to obtain newly understood schedules.
Restoration never reparses old snapshots or retroactively upgrades evidence.

Local tests use synthetic native captures, isolated Perl sources and simulated
sessions. [Verification and measurements](business-verification.md) separate
those results from CI publication and real-device/firmware acceptance.
