# Bounded Perl parser oracle

These synthetic cases exercise one interface/zone, a named address and reference group,
a two-port TCP service and reference group, and one policy referencing both groups.
ASA additionally exercises `access-group` before ACL interpretation. The runner
also asserts Content defer/rewind semantics independently before each parse.

`reference.pl` invokes the actual separately mounted Perl Parser; it is not a port
of that implementation. It projects resolved named address ranges, destination-port
sets, interface/zone bindings and ordered explicit policy matches. Fortinet `accept`
is normalized to `permit`; Perl/Go literal-object versus group representation is
intentionally compared through resolved sets. Built-in Go policies are excluded.

Run with local reference source and Docker image already present:

```sh
python3 verify.py --source /path/to/perl/algosec/backend --go-root /path/to/firemon
```

The command compares results, never updates expected JSON. It runs the reference
with `--network none --read-only` and read-only mounts. Only these synthetic inputs
are supplied. No devices, database or private dependency sources are included.

Execution evidence: [parser verification](../../../docs/parser-rewrite-verification.md), Perl 5.44.0, image digest
`sha256:01405e21111b41c379e6f75d1aaf82cb56ee0b0908faae82c6aabb247b18e609`.
The exact source functions and file hashes are in `source-references.json`.

This is a bounded importer comparison. It does not prove all firmware syntax,
NAT, multi-context behavior, service source-port pairing, schedules, unknown
conditions, device acceptance, or semantic equivalence of the full policy engines.
Those contracts require the existing Go native tests and separate evidence.

A separate diagnostic experiment demonstrated an existing Perl limitation:
unindented `service "apps"` inside a Hillstone rule is claimed by the first-pass
`isService` dispatcher, leaving the policy without its service. The Go structural
scanner correctly keeps it in the rule. The common fixture uses native member
indentation, and Go must retain its stronger structural isolation.
