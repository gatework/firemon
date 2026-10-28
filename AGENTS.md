# Firemon

Use golang-how-to for Go work, selecting relevant secondary skills.

Vendor scope approved by the user: Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA only. H3C, Topsec, Neteye and other vendors are out of scope for now.

- Concrete immutable firewall graph; separate StaticNAT and DynamicNAT domain objects.
- Read docs/spec.md and docs/plans/go-firewall.md before architectural changes.
- Preserve pending/unknown evidence. Never turn unsupported syntax into an unrestricted match.
- Stateful scoped parsers commit drafts and source evidence atomically. Bind interfaces before routes.
- Snapshot files are the persistence authority. Loading never reparses or consults a database.
- Standard-library-first, consumer-owned small interfaces, explicit context and resource limits.
- Synthetic/sanitized fixtures only. No device credentials, actual production configurations, or private dependency source.
- Preserve concurrent work. Commit, push, release and real device operations require explicit authorization.
- Go tests must exercise observable behavior; verify meaningful changes with go test and go vet.
