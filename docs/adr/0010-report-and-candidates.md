# 0010 — Query report, candidates and aggregation

Status: accepted (2026-11-18)

## Decision

- Per cluster the report classifies access control as full match, partial match, need new, blocked (a specific deny) or indeterminate (an undecidable rule may decide), lists the permitting, blocking and possibly-matching rules with the traffic each decides, and names the rule that decides the undecided traffic otherwise.
- The planner prices eligible single-field extensions on each zone pair using the changes the catalog would emit. One new object, group member, or appended rule reference counts as one entry. Equal-cost extensions prefer the same endpoints, logging, then device order. The first verified extension is recommended. If eight trials fail and further candidates remain, the plan reports the incomplete search. The report shows up to three candidates and includes the full trial record with the plan.
- Designs aggregate three or more objects of one field into an address or service group, reusing an equal existing group.
- Input is read tolerantly by `intake`; every correction is a coded note shown in the report. Operator text is Chinese, kept in one table (`internal/cli/text_zh.go`); JSON stays English.
