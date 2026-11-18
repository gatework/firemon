// Package deploy applies a verified design plan to a device.
//
// Deployment runs on the go-netops apply state machine: the intent of every
// write is journaled before it is sent, nothing is retried or replayed, and
// a failure after a write may have reached the device is reported as
// uncertain. Around the writes, the plan adds two checks:
//
//   - before: the running configuration must have the fingerprint the plan
//     was designed against, so a changed device is never modified blindly;
//   - after: the configuration read back must compile, and planning the
//     same intent again must need no change.
//
// The package performs no I/O itself; the session opener and the journal
// are injected.
package deploy
