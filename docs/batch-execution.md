# Selected execution and restart

`operations.BatchDesigner` produces reviewable per-device plans and independent
input issues. A report is not an executable import or write authorization.
The caller explicitly selects `Device`, immutable `Revision`, and `PlanDigest`.
`NewBatchExecutor(directory, deploymentEngine, snapshotStore)` then provides:

```go
prepared, err := executor.Prepare(ctx, "ticket-42", report, selected)
// Persist prepared.ID and prepared.Digest in the host's approval record.
result, err := executor.Apply(ctx, prepared.ID, prepared.Digest)
// A fresh process uses the same selection directory, snapshot store and journal.
recovered, err := executor.Recover(ctx, prepared.ID, prepared.Digest)
```

`Prepare` verifies every selected plan can be reconstructed using production
renderers. It persists the complete detached review (including unresolved inputs,
topology, original/real/translated coordinates and source mappings), plus exact
reconstruction material, with file and directory fsync before any device action.
An advisory lock serializes preparation across processes. Reusing an identity
with different review, selection order or material returns `ErrSelectionConflict`.
The SHA-256 selection digest covers the exact persisted bytes. The host must
retain that digest independently; a checksum does not authenticate arbitrary
material supplied with a new checksum.

Execution is sequential in explicit selection order. Each device uses the
existing `deploy.Engine.Apply` or `Recover`, with a stable operation ID derived
from length-prefixed batch, device, revision and plan-digest bytes. The engine
retains its own reservation, authorization, fresh-baseline, native configuration
ownership, receipt, persistence and independent readback requirements. Changing
the batch ID is a new operation, not a way to recover an uncertain write.

Results retain the full review and separate device outcomes: `applied`, `failed`,
`uncertain`, `aborted`, `cancelled`, `unstarted`. Device failures are in each
outcome's `Error` (excluded from JSON); the batch error represents selection/load
failure or context cancellation. A failure does not erase a successful peer or
roll it back. Cancellation stops subsequent devices. A terminal aborted journal
is not success. Repeated apply delegates to the same journal and never replays
pending commands. Recovery makes no Execute/Save calls and never starts an
unstarted device. Missing original snapshots cause local reconstruction failure;
other selected devices can still proceed.

`EncodePlan` / `RestorePlan` use strict bounded JSON version 1, algorithm
`firemon-business-v1`, with a 4 MiB material limit. It stores original baseline
revision, metadata, source/semantic digests, all original ordered inputs including
rejections, effective planner options and expected approval digest. Native inputs
retain NAT steps, declarations, provenance, packet proof requests, schedule clock
and finite windows. Snapshot bytes stay in the immutable snapshot store; retain
those blobs for the entire operation/recovery lifetime. `snapshot.Store.Load`
verifies their content hash. Restoration never reads a latest head, reparses
source or trusts a stored after-graph, commands or proof flags. It reruns full
planning, rendering and proof and requires the same plan digest.

The `plan` module owns this format independently of report documents.
`operations.EncodePlan` and `operations.RestorePlan` retain their existing
interfaces and delegate to it. A host with its own snapshot and renderer adapters
can use the core interface directly:

```go
checksum, err := plan.EncodeReconstruction(ctx, writer, revision, original)
// Retain checksum independently; decoding does not authorize a write.
material, err := plan.DecodeReconstruction(ctx, reader, checksum)
// After checking err, load material.Revision() from the immutable snapshot store.
baseline, err := store.Load(ctx, material.Revision())
// After checking err, supply a renderer selector with the existing shape.
rebuilt, err := material.Rebuild(ctx, baseline, vendors.Renderer)
```

`DecodeReconstruction` checks the checksum, strict format and input budgets before
returning opaque, owned material. `Rebuild` checks baseline completeness,
metadata and semantic identity before invoking the selector. Every rebuild runs
planning and proof again with the saved effective options and checks the approval
digest. Decoded material is immutable and supports independent concurrent
rebuilds; nil and zero values cannot be rebuilt. Cancellation takes precedence at
each core entry point. `operations.ErrReconstruction` aliases
`plan.ErrReconstruction`; the existing nil-reader error in `RestorePlan` remains
`operations.ErrInvalid`. The core module imports no snapshot or vendor adapter.

Material permits at most 100 inputs, 10,000 candidates, 10,000,000 visits, 65,536
regions and 65,536 combinations; effective original options must fit these
ceilings. Region and nested native containers are charged before materialization.
The complete persisted selection is limited to 16 MiB and 100 distinct devices.
Unsupported versions, extra fields/trailing JSON, checksum mismatch, unavailable
baseline or changed algorithm output stop reconstruction. Keep the original
algorithm available across software upgrades; this format does not promise
silent migration to a future planner.

Policy-batch approval bytes and native permanent approval version 2 remain
unchanged. Finite native approval is version 3. Reconstruction version 1 is a
separate transport format. Only `PlanBatch` / `PlanNativeBatch` business plans are
supported; legacy single-target and lifecycle plans do not retain all required
original intent and are not reconstructed by guessing defaults.

Tests use temporary stores and synthetic sessions with the real deployment
engine, production renderers and independent native parsers. They cover restart,
selection/authorization binding, uncertainty without replay, aborted operations,
unstarted recovery, baseline drift, missing blobs, corruption and cancellation.
Twenty supported native NAT forms and finite packet intent reconstruct and
revalidate locally. These checks do not establish real-device acceptance.

See the [planning glossary](../GLOSSARY.md) and
[intent refactor evidence](intent-verification.md) for ownership and compatibility
checks.
