# Parser rewrite implementation plan

Approved scope: all seven native parsers; keep Parse, Source, Limits, XML node readers, immutable graph and snapshot format 9. Preserve all prior WIP. No commits, pushes, releases or devices in this task.

1. Freeze working-tree fixtures and benchmark executables, including prior Hillstone work.
2. Replace content/cursor and Session/Stage coordination with Content and a single typed Builder. Explicit phases own atomic record/evidence updates. Retain source bounds and native structure isolation.
3. Migrate Hillstone, Huawei, Fortinet, SRX, Netscreen, ASA, Palo Alto, preserving native scopes, order, duplicate semantics and unknown evidence. Remove duplicate parser data and legacy orchestration. Increment all parser versions.
4. Verify six Perl reference parsers on bounded synthetic common syntax, with separate PAN XML/set evidence. Keep private reference code out of this repository.
5. Compare normalized graphs, snapshots, policy/NAT/planning outcomes; race, vet, build, adapter integration, scanning fuzz and ten repeated benchmark samples. Fix significant regressions above 5%.
6. Update parser design and verification records; independent final code review.
