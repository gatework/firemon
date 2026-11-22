# 0019 — Fleet health, cleanup output and application-aware coverage

Status: accepted (2026-11-21). Builds on 0014 (convergence) and 0017 (premises).

## Context

A self-review on the configuration backups (22 firewalls, 13 clusters) found four gaps:
- **No fleet view.** Nothing answered "which firewall needs attention first". `converge --inventory` rejected a backup directory.
- **Unreadable output.** `converge` listed every finding with internal IDs (one firewall: 12 categories, 222 unused objects, 115 redundant rules). `--plan` printed 5,624 lines. Nothing was summarized.
- **Rules with application criteria were left out of coverage analysis.** On a rulebase where 37 rules match by application, those rules could neither be found redundant nor cover others, inconsistent with 0017.
- **Coverage analysis ran out of budget** on broad rules (ten rules on two firewalls), so those findings were never made.

## Decision

- **`firemon health`** reviews every cluster of `--inventory` (backup directory or inventory file) on its evaluated member, in parallel.
  - It scores each firewall: 100 less stated deductions (package `health`). Each deduction is the measured share times a weight:
    - rules that never take effect: 40;
    - broad permits among permits: 30;
    - unlogged permits: 10;
    - unused or empty objects: 10;
    - unreadable lines and undecidable rules: 10.
  - Priorities rank each firewall's costliest factor by points × log10(1 + items affected), so a share of a large rulebase outranks the same share of a handful of rules. Each priority names the command that acts on it.
- **`converge` and `audit` answer with a summary** per firewall: rules that never take effect by reason, objects, mergeable rules, what needs review, and what a verified cleanup can remove.
  - `-v` lists the findings with their selectors.
  - `--plan --out DIR` writes `<device>-cleanup.txt` and `<device>-rollback.txt`.
  - `--cluster` narrows the fleet. `converge --inventory` accepts a backup directory.
- **Application-aware coverage.** A rule whose only unresolved part is its applications takes part in coverage analysis.
  - An earlier rule covers it when it covers its five-tuple and either matches any application or admits every application it names (groups expanded).
  - A rule for any application is never covered by one restricted to applications.
  - `TestConvergeLoop_Corpus` proves the cleanups keep every decision.
- **Coverage analysis finishes.**
  - A projection test first: if the candidate covering rules together miss a source, a destination or a service of the rule, the rule is reachable. This is exact and cheap.
  - When subtraction in device order fragments past the budget, coverage is decided by subtracting the largest covering rules first. Whether a rule is covered does not depend on order. The kind does: the rule is redundant when every covering rule shares its action; otherwise it is reported shadowed, the reading that asks a person to look.
- **Wording.** `parse` and `audit` count rules matching by application, user, URL category or domain as conditional ("按条件匹配"): a query settles them under premises. Only the rest is undecidable (`Rule.Conditional`).
- **Not changed:** StoneOS `ip A B` with B no netmask (seen on one firewall) stays an invalid entry. Its device semantics are unconfirmed, and an earlier review pinned it as undecidable rather than guessed.

## Consequences

On the corpus, coverage analysis now completes on every firewall (it was cut short on ten rules). Redundant and shadowed findings grew where application rules are involved (SZX9-IN: 115 redundant, 51 shadowed). The fleet health review takes about one second. The wide query fell from 1.7 s to 0.76 s once report building gathers spaces instead of merging regions piece by piece. Verified cleanup plans take about one second, most of it the per-rule verification, which is kept exhaustive.
