# Firewall planning

Planning turns business intent into a proven change against an immutable firewall
snapshot. These terms distinguish requested behavior, approval and recovery.

## Language

**Candidate change**:
A proposed modification against a baseline revision, awaiting safety and native
representation checks. It does not yet establish a proven plan or authorization.
_Avoid_: approved change, executable candidate

**Candidate attempt**:
Evaluation of a candidate change through complete safety and native
representation checks. Discovering or ruling out an append before these checks
is not a candidate attempt.
_Avoid_: rule visit, discovery count

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

**Change-safety proof**:
The evidence within a proven plan that a candidate change provides its intended
target behavior while all traffic outside the target keeps its baseline
ownership, with no incomplete or unknown evaluation. Full equivalence of an
unchanged policy is a different obligation.
_Avoid_: verification, safety check, equivalence proof

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

**Target provenance**:
The stable association between an original business input and one discovered
target outcome. It survives refusal and partial planning. A device's planning
index is a separate projection; business and topology sources retain their
own meaning, order and repeated entries.
_Avoid_: deduplicated request ID, report array offset

**Native declaration ownership**:
The relationship between a newly created native policy or NAT declaration and
the address or service values its syntax generates. Shared literal values may
have multiple owners. Generated values must not also be emitted as independent
declarations; a matching object ID alone does not establish ownership.
_Avoid_: suppressed object, same-name NAT object

**Confirmed completion**:
A publication or deployment terminal state established by durable evidence.
An error while closing a session or journal lease remains reportable without
undoing that state. An unconfirmed write still requires independent recovery.
_Avoid_: no error, successful transport close
