# 0005 — Deploy safety model

Status: accepted (2026-11-17)

## Decision

1. Plans carry the fingerprint of the configuration they were designed against. Deploy reads the running configuration first and refuses to continue when the fingerprint differs.
2. Deploy is a dry run unless the operator passes `--apply`; the dry run prints the exact script.
3. The script is sent once inside one net-connector operation. Any failure stops the deployment; nothing is retried or replayed, because a partially applied script is not idempotent.
4. After sending, the configuration is read back, compiled and queried; the receipt states whether the intent is now allowed.
5. Rollback is manual: the renderer also produces the inverse script, which is shown but never sent automatically.
