# 0017 — Determinate verdicts with stated premises

Status: accepted (2026-11-20). Refines 0009, 0013 and 0016 for requests that do not name an application, user, URL category or domain.

## Context

Operators ask by five-tuple. Under 0016, each application, user, URL-category and FQDN rule ahead of the deciding rule was a possible match, so most queries on production firewalls ended "需确认". A tcp/22 request reported that `TO_HTTPS` (HTTP/HTTPS applications) and `Allow_Any_Any_OSPF` (routing protocols) "may match first", which no operator would accept. On the corpus, 5,255 of 25,146 probes (a host of each rule on six common services) were indeterminate; with this decision 83 are, all caused by unknown objects or applications. Commercial planners (AlgoSec, FireMon) answer the same question by taking the traffic as the standard application of its port and showing that assumption.

## Decision

- **Application identification by standard ports.** Unless the request names applications or is `Strict`, each part of the service is identified as the applications with the fewest standard ports that hold it (`Firewall.IdentifyApplications`): tcp/22 → ssh, ssh-putty; tcp/443 → https, ssl3, tls1. Applications sharing exactly those ports form a family and are matched together. Predefined groups (`Config.ApplicationGroups`, StoneOS `APP_ROUTING_PROTOCOL`) match their members. Ports no application claims are unidentified: rules restricted to known applications do not match them, but rules naming an application neither the book nor a group knows stay possible matches there.
- **Premises instead of possibilities.** On a plain address target, a rule undecidable only by user, URL category or the domain names it may resolve to is taken not to match. Its certain part still decides. The rest is recorded on the decision (`Decision.Assumed`). `Decision.Conditional` returns the rules whose action would change the outcome. The report states them as premises with what they would decide. URL categories never match identified non-web traffic. `Request.Users` and `URLCategories` settle the criteria exactly. A scheduled rule inactive at the evaluated instant is a premise in the same way.
- **What stays indeterminate.** NAT that cannot be decided, unknown zones, an exhausted budget, unknown objects and cycles, and unknown applications on unidentified ports.
- **Inference refines strict.** `Request.Strict` (`--strict`) keeps the 0016 reading. Wherever strict evaluation decides, inference gives the same verdict, and it never leaves undecided what strict decides; `TestInference_Corpus` checks both on production configurations. The oracle tests compare with strict evaluation.
- **Reports by flow.** Each source item × destination item is a flow, followed through its firewalls in order (source owner, transit, destination owner), with the deciding rule on each. Devices are named `NAME(management address)`. Planned rules are printed in full, and modified rules before and after.

## Consequences

The result of a five-tuple query is now determinate, under premises the report lists. An operator who knows the traffic is another application asks with `--service app:NAME`, or uses `--strict` for the conservative reading. Design plans are verified under the same premises as the query (`Intent.Strict`, `Users`, `URLCategories`). The application books are part of the model: an application missing from a book with a broad default (unknown apps) only keeps rules possible on unclaimed ports. The stored model is version 5 (`ApplicationGroups`).
