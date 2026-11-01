# Parser rewrite measurements and local checks

Baseline is the full working tree before this rewrite, including the preceding
uncommitted Hillstone refinement; it is not bare Git HEAD. The core HEAD is
19d1fb999feb63a2f5cf7c2450dec1e7e63da01a. Before/after benchmark binaries are frozen
and identified in metadata.json. Production config/vendor file hashes identify
the final measured source. The added topology benchmark was compiled into both
binaries without altering baseline production code.

Ten paired 200ms samples run in alternating serial processes, GOMAXPROCS=4.
Raw output and numeric samples are retained. comparison.md reports medians and
an exact two-sided paired log-time sign-flip test (1024 sign permutations);
these are exploratory comparisons without a multiple-comparison adjustment.
Pair 10 was rerun after adapter checks ended to remove known CPU contention;
that decision was made before inspecting the replacement results. The metadata
and rerun script record this. Benchmarks are synthetic, not device throughput.

To reproduce with separately built before.test and after.test binaries, place
them alongside measure.py and run python3 measure.py. Their source versions must
be provided independently; no binaries or private dependency source are stored
here. Go uses the standard testing benchmark harness. Tests and broad benchmark
runs were not intentionally run concurrently (the known last-pair overlap was
replaced as described above).

The independent review found a deep-copy regression with 500 interfaces and
1000 policies, corrected it, and reran its targeted harness. That case now lives
in benchmarks/topology_bench_test.go. review-perf-results.txt records the defect
and fix, while the main before/after comparison measures the final code.

All accompanying logs are local evidence. The adapter's pinned-core run and
current-core workspace run are distinct. No CI, releases, pushes or device
operations were performed. Check integrity with shasum -a 256 -c SHA256SUMS
from this directory.
