# Native schedule contract

The native entry point is `Parser.Parse(ctx, source, metadata)`. Fortinet selects
`Metadata.Context` (default `root`); Palo Alto selects the named virtual system
(default `vsys1`) for both set and XML captures. The package-level `Parse` and
Fortinet `ParseVDOM` aliases have been removed. PAN command generation currently
requires the default virtual-system context; other contexts are rejected.

Schedules require a capture-bound `Source.ScheduleClock`. Configuration timezone
text alone is not evidence of endpoint or calendar behavior. Weekly schedules
also require `CalendarCivil`, which asserts local civil weekday behavior including
DST transitions. Native endpoints are converted to half-open graph intervals;
no host timezone or current time is substituted. Unsupported members remain on
the owning schedule and keep its match unknown. These operations describe new
policy admission; established session expiration is a separate device behavior.

The release gates are centralized in `internal/render.SupportsSchedule`:

| Target | Parsed and rendered forms | Composition and limits |
| --- | --- | --- |
| StoneOS 5.5R8 | `absolute`, `periodic` weekday/daily/range | One absolute bound intersects periodic entries. Named weekday-to-weekday spans are split exactly. Start-only bounds are supported with recurrence. |
| PAN-OS 10.2 | non-recurring, daily, weekly; set and XML | Absolute entries are a union; recurring entries are a union. Mixed native schedule types and a time range crossing midnight are unknown. Split days must be explicit. |
| ASA 9.16 | `time-range` absolute and periodic | Absolute bounds intersect all periodic entries. A missing absolute start depends on creation time and remains unknown. |
| Junos 21.4R3 | scheduler dates, daily/weekday intervals, `exclude`, `all-day` | Specific weekday entries replace daily entries. Date bounds intersect the resolved week. Incomplete or overnight day entries remain unknown. |
| ScreenOS 6.3 | once and recurrent weekday schedules | Up to two intervals per weekday. Native type conflicts and repeated weekday declarations remain unknown. |
| FortiOS 7.2 | onetime and recurring | Stop-before-start crosses midnight. Equal endpoints mean 24 civil hours. Rendering requires one common interval on selected weekdays; heterogeneous periods are rejected. |
| Huawei V500R005 | absolute-range and period-range | Isolated absolute and periodic entries are supported. Combined absolute/periodic semantics lack sufficient release-specific evidence and remain unknown. |

Renderers reject unsupported versions, precision loss, mixed date/weekly unions,
nonrepresentable native combinations, and identifiers outside their conservative
31-character safe-token subset. They never replace such a schedule with `always`.
The seven-vendor fixtures use independent native captures, and test graph activity,
snapshot restoration, missing evidence, recurrence, native command forms and rule
attachments. They do not constitute real-device acceptance.

## Sources and deliberate differences

The business vocabulary and native syntax were traced to
`Firewall/Config/Parser/{Hillstone,Asa,Srx,Netscreen,Fortinet,Huawei}.pm` and their
`Firewall/Config/Element/Schedule/*.pm` implementations in the Perl reference.
Relevant parsing methods are `parseSchedule`; model methods are `createTimeRange`
and `isEnable`. Those implementations use process-local time and sometimes retain
only one repeated definition. Go keeps capture-bound time, every supported entry,
and native combination semantics instead of copying those losses.

Additional primary references:

- [StoneOS CLI System Management](https://kb.hillstonenet.com/en/wp-content/uploads/2018/08/StoneOS_CLI_User_Guide_System_Management_5.5R6.pdf), Configuring Schedule: periodic entries within absolute bounds; daily, weekday lists and continuous weekly periods. This documents the earlier grammar, corroborated by the Perl parser; it is not a physical 5.5R8 test.
- [ASA 9.16 access objects](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/firewall/asa-916-firewall-config/access-objects.html), Configure Time Ranges: absolute and periodic intersection, optional bounds, weekday-to-weekday syntax.
- [Junos policy scheduling](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/scheduling-security-policy.html): daily overrides, exclusions, date bounds and policy scheduler references.
- [PAN-OS 10.2 schedules](https://docs.paloaltonetworks.com/ngfw/help/10-2/objects/objects-schedules) and [spanning two days](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClZOCA0): recurring/non-recurring types and explicit midnight splitting.
- [FortiOS 7.2 recurring CLI](https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/298620/config-firewall-schedule-recurring) and [Fortinet schedule behavior](https://community.fortinet.com/fortigate-3/technical-tip-configuring-a-firewall-policy-which-is-valid-only-at-certain-days-or-hours-by-using-a-schedule-93758): selected weekdays, overnight intervals and 24-hour equal endpoints.

Remaining extensions need evidence plus fixture coverage: Huawei combined date and
weekly ranges; additional native precision and name forms; holiday/calendar
exceptions; source-defined unbounded absolute windows; PAN nondefault-vsys command
generation. A parser recognizing a header does not advertise these as supported.
