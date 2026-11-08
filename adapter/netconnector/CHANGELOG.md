# Changelog

## v0.2.1 - 2026-11-08

- Pin published Firemon core v0.2.1 for graph sealing improvements and exact NAT
  mapping arithmetic; preserve the existing connector interfaces and native
  lifecycle contracts.
- Retain go-net-connector v0.2.0 and go-expect v0.4.0 without replacements.

## v0.2.0 - 2026-11-08

Requires Go 1.27 or newer. This development release removes vendor aliases;
callers must use the seven canonical names documented in [README](README.md).

- Pin published Firemon core v0.2.0; retain go-net-connector v0.2.0 and
  go-expect v0.4.0 without local replacements or vendored dependency source.
- Map canonical Firemon names to connector profiles internally, preserving host
  metadata and rejecting legacy aliases before dialing.
- Decode verified UTF-8/GBK/GB18030 response history without terminal repainting.
  Earlier save rejections remain visible, while verified prompt names are kept
  outside persistence evidence.
- Require a complete, unambiguous Fortinet automatic-save setting. Treat ordinary
  configuration values containing error words as data; reject malformed,
  conflicting or unsupported save evidence.

Validation uses synthetic captures and simulated sessions. No real-device
acceptance or unrestricted firmware interoperability is claimed.

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
- Preserve cancellation evidence alongside transport or receipt failures when
  an operation is canceled or its session is closed.
- Verify adapter behavior with synthetic native captures and simulated connector
  sessions, both against the versioned core and the current checked-out core.

The host supplies inventory, credentials, authorization and durable storage.
Supported native contexts and persistence modes are documented in [README](README.md).
No real-device acceptance or unrestricted firmware interoperability is claimed.
