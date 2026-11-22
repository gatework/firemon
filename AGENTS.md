# firemon development notes

Follow [the gatework Go engineering standard](https://github.com/gatework/go-standards/blob/main/STANDARD.md) (go-standards/STANDARD.md); this file adds only what is specific to firemon. Run `make check` before every commit.

Before any Go coding, review, debugging or setup task, load the `samber/cc-skills-golang@golang-how-to` skill first.

## Maturity

v2 is a rewrite and is not in production: no compatibility promise (GEN-1). The algorithm reference is the Perl implementation under `algosec/backend/lib/Firewall`; intended differences are listed in [ADR 0003](docs/adr/0003-ordered-first-match.md) and pinned by tests.

## Boundaries

- `traffic` is pure set algebra; the root package `firemon` is the domain model and compiler. Neither performs I/O. `architecture.yaml` enforces the direction; register every new package there first.
- `vendors/<vendor>` owns all device syntax: parsing to `firemon.Config` and rendering design plans to commands. Nothing outside a vendor package switches on `firemon.Vendor`; vendor behaviour reaches the engine through `firemon.Semantics`.
- `adapter/netconnector` is the only package that imports net-connector. Device dialogues, save and commit evidence belong to the net-connector drivers; parsing builds on netops `parse`, deployment on netops `apply`.
- Vendors are wired explicitly in `internal/bootstrap`; no `init` registration.

## Semantics that must not regress

- Never widen what cannot be evaluated. Domain names, dynamic groups, application matches, unknown objects and cycles make a rule undecidable (`Rule.Decidable() == false`). Evaluation either settles the rule under a premise it records, or treats it as a possible match and reports `Indeterminate`, never `Allowed`. Premises are the standard application of the ports and user, URL-category, domain-name and schedule criteria the request does not give ([ADR 0017](docs/adr/0017-determinate-verdicts-with-premises.md)). An unrecorded assumption must never make a result `Allowed`, and inference must agree with `Strict` wherever `Strict` decides.
- Rules are evaluated in device order, first match wins, deny rules included.
- A design plan is accepted only if, applied to the configuration, it makes the intent allowed and permits nothing outside the intent.
- Deploy is dry-run unless explicitly applied, refuses a device whose configuration fingerprint differs from the plan baseline, and never retries a partially sent script.

## Data

Fixtures in `testdata/` are synthetic. Real configurations stay outside the repository: point `FIREMON_CORPUS` at a directory of backups and run `make corpus`; tests print only aggregate counts.
