# 0010 — Query report, candidates and aggregation

Status: accepted (2026-11-18)

## Decision

- Per cluster the report classifies access control as full match, partial match, need new, blocked (a specific deny) or indeterminate (an undecidable rule may decide), lists the permitting, blocking and possibly-matching rules with the traffic each decides, and names the rule that decides the undecided traffic otherwise.
- Candidates replace the Perl contain3/belong3/equal2 heuristics: every permit rule applying to the zone pair is related to the remaining need per dimension (equal, contains, contained, overlap, disjoint). A candidate is extendable only when it lacks one dimension and carries none of: wider than the request in a covered dimension, zone any, schedule, applications, undecidable, after the deciding deny. The planner's choice is marked recommended; at most three are reported.
- Designs aggregate three or more objects of one field into an address or service group, reusing an equal existing group.
- Input is read tolerantly by `intake`; every correction is a coded note shown in the report. Operator text is Chinese, kept in one table (`internal/cli/text_zh.go`); JSON stays English.
