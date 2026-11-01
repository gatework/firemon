# Native usage and offline lifecycle commands

`analysis.NativeUsage` consumes bounded `io.Reader` streams against an explicitly
supplied immutable revision and semantic graph digest. Defaults are 16 MiB,
100000 lines, 64 KiB per line and 100 retained issues (256-byte excerpts). Policy
visit/region/combination budgets additionally bound identity checks, member
resolution and output. Cancellation and stream failure never publish partial
observations as complete evidence. Issues retain line/source context and a count
of omitted issues.

`ReadASACounters` takes two `CounterSample` values. Each supplies source, capture
time, revision, graph digest and completeness. A nonempty identical **verified
counter generation** (`Epoch`) is mandatory for a delta: nondecreasing counters
alone cannot exclude a reset between samples. Complete native ACL tokens identify
the parent declaration; operational line numbers and display hashes are discarded.
Expansion rows, duplicate declarations/samples, revision drift, missing window or
counter generation and decreases remain unknown. No guessed positive delta is
sent with a reset flag. Aggregate ACL counts never generate member or tuple hits.
A zero delta with complete bound samples can establish unused for that window;
unused alone still cannot authorize deletion.

`ReadSessions` accepts the actual Perl Cleaner's SRX `session created` grammar and
ScreenOS `policy_id/proto/src/dst/src_port/dst_port` grammar, with an explicit
RFC3339 timestamp. TCP/UDP ports are required; missing fields are never replaced
with port 65535. The parser binds the native rule, checks the tuple's effective
first-match ownership against the graph, and retains each paired tuple separately.
Exact repeated timestamp/rule/tuple records are conservatively deduplicated. This
is positive use evidence, not a precise session counter. Only matching role
members receive positive observations; no cross-products are synthesized.

No records means no usage conclusion, even when the log file is declared complete.
Session ingestion deliberately produces no zero-hit observations. NAT-bearing
graphs need a separate established log-coordinate contract and currently report
`unknown_log_nat_coordinates`. A record naming an explicit ScreenOS policy cannot
prove its use when the captured intrazone bypass actually owns the tuple. Tests
use `set zone inside block` when explicit intrazone policy evaluation is intended.

These strengthen the actual `Firewall::Policy::Cleaner::AnalyzeLog` behavior:
its ASA persistent positive counters, timestamp-free SRX records and missing-port
ScreenOS fallback are reference algorithms, not sufficient Go usage evidence.
The three synthetic formats and edge cases were exercised against actual Perl
sources in an isolated container; no database, remote log service or device ran.

All commands below are offline and take `--store DIR --revision EXACT --file JSON`.
Input is strict version-1 JSON bounded to 4 MiB, output to 16 MiB.

- `usage-report`: SRX/ScreenOS document fields are `file`, `revision`,
  `graph_digest`, `source`, `scope`, `window` and `complete`. ASA instead supplies
  exactly two `samples`, each with `file`, `at`, `revision`, `graph_digest`,
  `source`, `epoch` and `complete`.
- `reclamation-report`: `request` is a `ReclamationRequest` containing the usage
  window and bound observations. Rules and member evidence remain separate.
- `reclamation-plan`: additionally requires explicit `rules` IDs. The existing
  Reclaimer validates selection and proves the whole resulting graph.
- `migration-report` / `migration-plan`: require `target_revision`, explicit
  `zones` (`from`/`to`), `pairs`, optional `chains`, selected `rules` and `at`.
  Both produce a review artifact for the existing effective-partition migrator;
  unsupported representation fails. No NAT migration or device write occurs.
- `convergence-plan`: explicit `rules` and `at`; one jointly proven plan.
  Existing `risk-report` and `convergence-report` commands remain available.

Returned plans are review documents, not executable import tokens or authorization.
Usage assertions belong to the capture integration; the library validates their
binding and consistency, not the authenticity of an arbitrary caller's assertions.
