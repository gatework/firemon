# Changelog

## v0.1.0 - 2026-11-07

First versioned release of `github.com/gatework/firemon/adapter/netconnector`,
tagged `adapter/netconnector/v0.1.0`. Requires Go 1.27 or newer.

- Pin the published Firemon core v0.1.0; retain go-net-connector v0.2.0 and
  go-expect v0.4.0 without local replacement directives or vendored source.
- Supply fresh read-only and deployment sessions, configuration isolation,
  bounded capture, durable command receipts and affirmative save/commit evidence
  for Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA.
- Preserve incomplete capture evidence and independently recover uncertain
  operations without replaying writes or taking over foreign configuration locks.
- Verify adapter behavior with synthetic native captures and simulated connector
  sessions, both against the versioned core and the current checked-out core.

The host supplies inventory, credentials, authorization and durable storage.
Supported native contexts and persistence modes are documented in [README](README.md).
No real-device acceptance or unrestricted firmware interoperability is claimed.
