# Actual Perl business reference

The reference is the real `backend/lib/Firewall` tree, including callers and
vendor plugins. No private source is copied into this repository. The synthetic
[harnesses and artifacts](../analysis/testdata/perl-business/) record source and
artifact SHA-256 hashes in `source-references.json` and `artifacts.json`.
The exact image is
`sha256:01405e21111b41c379e6f75d1aaf82cb56ee0b0908faae82c6aabb247b18e609`.

Reproduction requires that separately installed local source and image:

```sh
python3 analysis/testdata/perl-business/run.py \
  --source /path/to/algosec/backend/lib --output /tmp/firemon-oracle-new
```

The runner verifies all 31 referenced source hashes first. Every container uses
`--network=none --read-only`, read-only source/harness mounts, and only 1 MiB
temporary `/tmp` and `/wls` filesystems for the legacy error sink. No database,
device or credentials are used. Search replaces only DAO loading and the
Perl-5.44-incompatible indirect constructor factory. Convergence replaces only
DAO loading/result persistence. Vendor algorithms are actual source methods.

All 37 invocations passed on 2026-10-31. Search, optimization, inspection,
convergence, static aliases, schedules, risk and usage JSON matched the retained
reference outputs. Huawei NAT date/random rule names, SRX random pool/rule names
and ScreenOS random DIP IDs changed; inspected diffs preserve their relationships
and all semantic values. Raw outputs remain unnormalized. ASA convergence emits
two actual `isDisable` uninitialized-value warnings; its retained stderr is not
represented as a warning-free run. Other invocations have empty stderr.

| Actual reference methods | Adopted business abstraction | Deliberate Go boundary |
| --- | --- | --- |
| `Searcher::getValidRuleSign/searchPolicy/selectAModifyPolicy`, six plugins | Covered, append-compatible, new-rule alternatives | Full ordered target/outside/NAT proof, not declaration containment alone |
| `FireFlow::RuleOtimize::optimizeRule/changeRuleToSet/optimize` | Fixed-point exact request union | Preserve paired traffic and every input index; decode Perl TCP/UDP numeric offsets explicitly |
| `Config::Ruleopti::optirule`, six parsers | Contain/combine compatible declarations | Exact signature grouping plus full safety/render/readback proof; no automatic merging of separate plans |
| `FindIp::searchAddressGroup`, six parsers | Address lookup and reference paths | Typed nested groups, ranges, wildcard exposure and first-match ownership go beyond flat Perl membership |
| SRX `createMainAddr/createPrivateIp` | Static subnet-offset aliases | Round-trip alone is insufficient; ordered forward view, ambiguity and route evidence required |
| `Config::Audit::_audit` | AND/OR versioned standards | An empty intersection is false, correcting actual Perl OR object-truthiness behavior |
| Four `Designer::createSchedule` and schedule elements | Finite policy lifetime | Exact UTC half-open windows; trusted independent clock/endpoints, collision-safe names |
| Five static NAT methods; five dynamic NAT methods; Huawei modern NAT | Declaration dependencies, pool reuse and policy-owned effects | Exact complete relation reuse; independent captured syntax and native proof |
| `Cleaner::AnalyzeLog::{asa,srx,netscreen}` | Rule and actual tuple observations | Revision, timestamp, window and counter-generation proof; missing evidence stays unknown |

Concrete differences are intentional and tested:

- Fortinet's native default service excludes source port 0. The old search ignores
  that distinction. ScreenOS intrazone permit is an actual implicit policy absent
  from old candidate search. Unbound ASA ACL creation is refused. Search tests
  compare common behavior and explicitly assert these three native differences.
- All four legacy schedule designers reuse the same date-based name for two
  different end times. Go names include the exact window and timezone. Perl's
  actual schedule evaluation uses inclusive seconds and process timezone; this
  is not proof of a device endpoint or timezone. Go requires capture-bound evidence.
- The old Fortinet pool helper reuses a containing `.1–.254` pool for `.30/32`.
  Go refuses that allocation widening. Legacy Fortinet static NAT text omits `set`
  before an interface field. ASA source PAT may omit its host/subnet declaration.
  Neither command defect is copied into the native renderers.
- Huawei source-prefix pool generation has an actual `/d+` regex defect, producing
  an empty pool. Its destination pool uses the public address where real is needed.
  Go fixtures assert independent native relations rather than raw text parity.
- ScreenOS missing log ports become `tcp_65535` in Perl; timestamp-free SRX still
  marks a hit; one ASA zero counter has no continuity proof. Go does not invent
  ports/times or infer inactivity. Two counters require an independently verified
  continuous epoch. Session logs yield only positive paired tuples.

`analysis/perl_business_test.go` consumes retained oracle results for exact
optimizer traffic/provenance, six-vendor search dispositions and explicit native
differences, schedule boundary conversion and artifact integrity. The supporting
native creation, usage, alias, risk, convergence and readback tests prove the
stronger Go contracts. No fixture establishes live-device interoperability.
