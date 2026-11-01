# Absolute temporary policy admission

`plan.NativeRequest.Lifetime` adds one `ScheduleIntent` to the original policy
request. The immutable schedule's UTC `[Start, End)` must match that intent
exactly. Supply it through `NativeAdditions.Schedules`, or reuse an identical
existing declaration. `ScheduleName(window, timezone)` provides a deterministic
28-character name which distinguishes different expiry times on the same day.
Existing policies and schedules are never edited. Recurring schedule creation
and ASA/SRX/Palo Alto schedule creation are unsupported.

`config.Source.ScheduleClock` is an explicit **trusted integration boundary**.
The capturing integration must independently verify the device timezone and
native schedule endpoint convention. Its `firemon.ScheduleClock` binds device,
vendor, software, selected context, capture timestamp and exact source SHA256 to
an IANA timezone, evidence reference, `exclusive` or `inclusive` end convention,
and a verified tick of 1 or 60 seconds. The library validates this binding; it
cannot authenticate an assertion supplied by its caller. Do not construct it
from a default timezone, the host clock, or a planned schedule. Without it native
schedules remain unresolved. Readback needs a **new independently established**
clock bound to the observed capture. Reusing the baseline digest is refused.

Parsing stores UTC windows and timezone in the existing schedule record;
snapshot format remains 9. Loading snapshots never reparses native text. New
parser versions are Hillstone 5, Fortinet 3, Huawei 3 and ScreenOS 3.

The supported creation subset is minute-aligned absolute civil times:

| Vendor family | Declaration | Policy reference |
| --- | --- | --- |
| StoneOS 5.5R8 / R8P | `schedule`, `absolute start ... end ...` | `schedule` |
| FortiOS 7.2.x | `config firewall schedule onetime`, `set start/end` | `set schedule` |
| USG V500R005 | `time-range`, `absolute-range ... to ...` | `time-range` |
| ScreenOS 6.3.x | `set scheduler ... once start ... stop ...` | `schedule` |

These syntax gates do not establish a device's endpoint semantics. The clock
contract makes that missing evidence explicit. Inclusive endpoints are converted
by adding the verified tick during parse and subtracting it during rendering;
there is no rounding. Both native endpoints must be representable, at least one
minute apart, and round-trip exactly. Repeated or nonexistent local times around
clock changes are refused, even if the caller supplied an unambiguous UTC instant
whose native civil spelling would be ambiguous. Creation is limited to years
1970–2099. StoneOS parsing also retains supported seconds syntax when verified;
creation deliberately uses the narrower minute subset.

The version-3 native approval digest binds the finite intent and clock contract.
The joint proof evaluates every existing and new schedule transition, including
before start and after end, and requires exact targets throughout their active
intervals. Policy ownership outside the finite target is preserved at every
interval. Explicit NAT intent inherits the same lifetime; policy-owned Fortinet
and ScreenOS source NAT are covered by joint synthetic tests. Independently
parsed readback repeats full declaration, policy and NAT proofs.

This models **new policy admission/matching**, not termination of established
sessions. No session-kill command is added. The actual Perl `createSchedule`
methods informed the native forms; their date-only name collisions, host-local
time conversion and inclusive Perl comparison were not treated as device proof.
Huawei parsing uses `to`, agreeing with the actual Perl parser rather than the
historical designer's inconsistent `end` spelling.

All evidence here is synthetic local parsing, command, snapshot, boundary and
proof testing. No device acceptance or CI execution is claimed.
