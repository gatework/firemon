# Firewall planning

Planning turns business intent into a proven change against an immutable firewall
snapshot. These terms distinguish requested behavior, approval and recovery.

## Language

**Planning intent**:
The requested behavior and its proof obligation: access, policy batch, native
batch, preservation or transfer. Original inputs include refused requests;
accepted targets identify only the behavior proven by the resulting plan.
_Avoid_: mode flags, command list

**Proven plan**:
An immutable planning result containing the before/after graphs, changes,
rendered commands and evidence for its intent. It still requires authorization,
a fresh baseline and independent readback before execution can succeed.
_Avoid_: approved script, executable report

**Approval digest**:
The identifier of the exact planning result presented for approval, using the
intent family's established encoding. It is distinct from reconstruction and
selection checksums and does not grant authorization by itself.
_Avoid_: reconstruction checksum, authorization token

**Reconstruction material**:
Versioned original batch inputs, effective options, baseline identity and
expected approval digest sufficient to rerun planning. Material becomes a proven
plan only after reconstruction against the retained snapshot succeeds.
_Avoid_: saved plan, imported proof

**Baseline revision**:
The content-addressed immutable snapshot used for the original plan. Recovery
loads that exact revision, independently of any current device head.
_Avoid_: latest configuration, current revision

**Durable selection**:
The persisted review and explicit ordered device/revision/plan choices bound to
one execution identity and checksum. It includes reconstruction material while
retaining unresolved inputs for review.
_Avoid_: batch script, report approval
