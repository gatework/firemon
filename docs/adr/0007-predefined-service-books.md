# 0007 — Predefined service books

Status: accepted (2026-11-17)

## Context

Rules reference built-in services ("HTTPS", "SNMP", "service-http") that configurations never declare. Their ports differ by vendor, and Hillstone states that the predefined services vary with the device model and release. The Perl reference loaded them from per-vendor database tables that are not part of the repository.

## Decision

- `firemon.ServiceBook` maps predefined names to entries; its JSON form uses the service expression syntax (`{"DNS": ["tcp/53", "udp/53"]}`).
- Each vendor embeds a default book (`vendors/<vendor>/predefined_services.json`). The Hillstone default holds only names whose ports are protocol standards (IANA); names with model- or release-specific ports, such as HTTP-EXT, are deliberately absent, so rules using them are undecidable instead of wrong. PAN-OS ships `service-http` (tcp/80, tcp/8080) and `service-https` (tcp/443).
- A device book passed with `--service-book` (parser `Options.Services`) replaces default entries of the same name; services declared in the configuration take precedence over both.
- Parsed configurations carry the predefined services they used, so snapshots keep the book they were collected with.

## Consequences

`firemon services` prints the effective book for review against the device. When a device's book differs from the default, operators save the corrected JSON and pass it with every command for that device (or collect a snapshot with it once).
