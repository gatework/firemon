# 0018 — Hop chaining, change risk and operations output

Status: accepted (2026-11-21). Builds on 0006 (locating), 0010 (report and candidates) and 0017 (premises).

## Context

A review of the reports on production backups found four gaps:
- **Wide requests were unreadable.** A /16 to any request printed 1.7 MB, one line of it 1 MB long.
- **The report contradicted itself.** A firewall was "部分命中" while the flow table said what it did per flow. A plan added a rule and never said why it modified none.
- **Firewalls were evaluated on the original addresses.** Traffic one firewall translates reached the next one unchanged in the model.
- **Changes were neither graded for risk nor packaged for operations.** There was no expiry, no batch of tickets, and no ticket-ready output.

## Decision

- **Bounded output.** Premise and hop traffic accumulates as spaces and is written once. Past 240 characters it becomes the hull of its addresses and ports with a piece count. Premises merge per rule, application premises across firewalls. Lists are bounded by default: 10 premises, 3 rules per hop, 20 flows (only those needing action), 300 characters per free-text line. `-v` and `--json` keep everything. A wide request opens with a zone-pair summary (`Firewall.ZonePairs`).
- **One reading of the result.**
  - The flow table carries the deciding rules with what they match.
  - A firewall is described by the flows it permits and the flows that need a change (`Firewall.FlowCounts`).
  - The conclusion says whether the plans add or modify rules.
  - When a plan only adds, the closest candidates are listed with the reasons they were not extended.
  - Applications are spelled as the configuration spells them (`Firewall.ApplicationDisplay`).
- **Hop chaining.**
  1. After the per-firewall evaluation, every path whose NAT rewrites addresses or ports hands its leaving traffic (`Path.Leaving`) to the firewalls its routes reach (`inventory.followNAT`).
  2. Each such firewall is evaluated again with the translated part replacing the original one (`Part.Service` carries a translated port), and records `Crossing.Upstream`. Plans for it use the translated addresses.
  3. Crossings are numbered along next hops (`Crossing.Seq`).
  4. A flow orders its firewalls by ownership first: the source owner, then transit by sequence, then the destination owner. Two firewalls routing to each other carry flows both ways, so ownership is the only thing that tells the direction apart.
  5. Without NAT the result is unchanged.
- **Change risk** (`Plan.Risks`) grades what each new or extended permit opens: any address, a network wider than /16, any service, more than 100 ports, or a sensitive service across zones (`design.SensitiveServices`). It also grades each deny the plan bypasses: high when the deny isolates a network for every service, medium otherwise. Risks inform; they never block a plan or change the exit code.
- **Temporary access** (`Intent.Until`, `--until`): a validity window on vendors whose rules carry one (`Capabilities.RuleWindows`), otherwise a one-time schedule created with the plan. It is verified as a scheduled access.
- **Batch tickets** (`--file`): each CSV row is a request named by its ticket. Each is designed on the inventory with the verified plans before it applied (`Inventory.Applied`), so objects are reused, rule IDs do not collide, and a later ticket may extend an earlier ticket's rule. The summary says so (`depends_on`). The exit status is the worst one.
- **`--format markdown`** renders the same report for a ticket: conclusion, premises, flow table, and per firewall the rules in full, the risks, the commands and the rollback.

## Consequences

Reports on wide requests are summaries with exact JSON behind them. Batch results depend on order: a ticket that extends an earlier ticket's rule must be deployed after it. The risk thresholds and sensitive services are constants of the design package; making them settings is future work.
