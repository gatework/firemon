# Optional device connector adapter

This separate module implements the same `deploy.Factory` and `deploy.Session` contract for Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA using the pinned private `github.com/gatework/go-net-connector` dependency. The root module remains independent of the connector. No private dependency source or local `replace` directive is included.

The published core pin is `v0.0.0-20261029031126-c9d9f251ed20`. See the [API migration guide](../../docs/refactoring.md) for the domain refactor and [delivery status](../../docs/status.md) for its standalone versioned-consumer verification.

The host supplies identity, credentials and transport options through `Factory.Resolve`. `Factory.Open` creates a fresh device for each initial connection, independent readback and recovery. `Profile(vendor)` exposes the supported native profile; SRX, Huawei, Hillstone, Fortinet and PAN reuse the pinned connector profiles with narrowly scoped adapter adjustments. ASA and ScreenOS profiles are provided here. `New` transfers ownership of an already constructed device on success; its caller must set bounded transport limits and a validated profile.

`Metadata.Context` identifies the selected native configuration domain and is retained through capture, parsing, planning and journal recovery. Fortinet requires an explicit VDOM, including `root`. All other profiles require an empty `Metadata.Context` and operate in their default native domain. Nonempty labels are rejected by `New` before dialing or capture because this adapter does not select ASA contexts, PAN vsys or Junos logical systems. A connected identity or domain mismatch never becomes a successful readback.

All vendors use `BeginConfiguration`, `Read`, `Execute`, `Save`, `EndConfiguration` and `Close`. `deploy.Session` requires the configuration lifecycle, with explicit handling for immediate-running devices as well as candidate devices. A read-only collector can call `Read` without beginning a configuration transaction. Native differences stay inside this adapter.

| Vendor | Running and saved capture | Persistence and configuration isolation |
| --- | --- | --- |
| Palo Alto | Native set-format collection with candidate-diff checks; saved `show config saved running-config.xml` requires complete XML | Config lock acquired before the fresh baseline, ownership checked before writes and commit; numeric commit job must reach matching `Commit FIN OK` |
| SRX | Operational `show configuration \| display set \| no-more` for both views; `run` prefix inside configuration mode selects committed state | `configure exclusive` before baseline, empty candidate comparison, `commit comment "firemon:<token>"` and affirmative completion; lock held through commit |
| Huawei | Native `dis cur`; `display saved-configuration` | Interactive `save`, connector confirmation handling and affirmative save evidence; immediate-running USG/VRP command model |
| Hillstone | `show configuration running`; `show configuration startup` | Native `save all` and affirmative connector validation |
| Fortinet | `show full-configuration` in the selected, verified VDOM | `execute cfg save`; saved evidence requires `cfg-save automatic` before and after capture/save, under which completed edits persist to memory and flash |
| Netscreen | `get config`; `get config saved` | `save`, followed by nonempty matching running/saved native configuration bodies |
| ASA | `show running-config`; `show startup-config` | `write memory`, configuration-building response and standalone `[OK]` without failure evidence |

SRX renderer scripts must have the recognized outer `configure`/`exit` wrapper and only supported root `set`/`delete`/`insert` edits. The adapter validates this form and executes `top` for those wrapper steps inside its already held exclusive session, preserving receipt indexes. Operational capture cannot accidentally promote an uncommitted candidate into the baseline. This is ordinary permanent commit, without batch, scheduled or confirmed-commit workflows. Huawei's adapter uses `save`, not the Comware `save force` command; two-stage candidate/commit variants are outside this profile.

Fortinet preflights automatic save mode and verifies the selected VDOM in `BeginConfiguration`, before the baseline or policy writes. It verifies `get system status` and the existing VDOM inventory before changing context. It never uses `edit` to create a missing VDOM. Manual, revert, workspace and unknown save modes do not provide supported saved-view evidence and fail closed; the adapter does not change the device's save mode. Transport success alone never establishes supported policy or NAT semantics: all native capture content still passes through firemon's parser and plan verification.

PAN deployment requires `Options.ExclusivePANAdmin = true`. This is an explicit host attestation that the administrative account is dedicated to this automation and serialized across every process and host that can use it. PAN configuration locks identify administrators rather than CLI sessions; another connection using the same account cannot be distinguished by the device lock. Local journal leases alone cannot provide that guarantee. Without the attestation, acquisition and recovery release fail before modifying locks. Forced administrator intervention remains outside this guarantee.

After exact-plan host authorization, the engine durably journals a random ownership token before acquiring native isolation. PAN writes it into the lock comment, then verifies the owner's `entry name` attribute and exact comment with `show config-locks vsys all` using XML output. The supported shape is `response/result/config-locks/entry`, also allowing CLI output rooted at `result` or `config-locks`; the vendor SDK documents leaf `name`, `type`, `loggedin` and `comment` fields. Nested or ambiguous ownership output fails closed. This is a configuration lock, separate from a commit lock. PAN removes locks after commit completion; release accepts an absent lock only after a clean candidate check. It never takes over or removes a foreign lock.

Cancellation, an uncertain acquisition, an early baseline failure or process death can leave the token and a PAN device lock pending. `Close` interrupts I/O and closes transport; it does not claim administrative cleanup. `Engine.Recover` opens a fresh session and calls ownership-checked `EndConfiguration` before any recovery read or publication. A foreign lock, dirty PAN candidate or failed release remains uncertain for explicit reconciliation. No reset, discard, replay, forced unlock or automatic reconnect is attempted. SRX exclusive ownership is session scoped; recovery opens a new session and verifies committed state independently.

Failed reads retain bounded evidence from the matching configuration command before returning the error. Completed responses use the connector's decoded output; the pinned connector exposes only `Attempt.Raw()` for failed commands, so interrupted or rejected responses retain those bytes as incomplete evidence. They never establish complete semantics. Pager setup, VDOM selection, save-mode checks and PAN candidate-diff responses are not configuration payloads. A later PAN diff failure retains the already received `show` configuration. Collector publishes this incomplete evidence and a repeat of the same publication ID returns it without reconnecting.

`Execute` persists each command receipt before sending the next command. Receipt errors, rejected commands, cancellation, connection loss and unconfirmed persistence retire the session. PAN polling accepts native queued rows with missing dequeue time or queue position, then active and completed states; job identity, type, error text, bounds and completion remain strict. Reads, execution preparation and polling have output and time bounds. An observer cannot reenter a busy session.

Native references used for these choices:

- [PAN lock ownership and automatic removal](https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/launch-the-web-interface/manage-locks-for-restricting-configuration-changes), [native operation commands](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-cli-ops-command-hierarchy), and the vendor SDK's [ConfigLocks response path](https://github.com/PaloAltoNetworks/pango/blob/v0.10.2/client.go) and [lock XML structure](https://github.com/PaloAltoNetworks/pango/blob/main/xmlapi/lock.go).
- [PAN native queued job output](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNvwCAG&lang=en_US).
- [Junos commit persistence, exclusive ownership and commit comments](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/junos-configuration-commit.html) and [operational versus candidate configuration](https://www-origin.junipercloud.net/documentation/us/en/software/junos/cli/topics/topic-map/junos-configuration-viewing.html).
- [FortiOS save modes](https://docs.fortinet.com/document/fortigate/7.6.1/administration-guide/228450/using-configuration-save-mode), [vendor save-mode explanation](https://community.fortinet.com/fortigate-3/technical-tip-configuration-file-save-mode-for-configuration-changes-96154) and [VDOM inventory output](https://community.fortinet.com/fortigate-3/technical-tip-how-to-find-the-vdom-index-94580).
- [Juniper ScreenOS command mapping](https://www.juniper.net/assets/jp/jp/local/pdf/additional-resources/screenos-to-junos-mapping.pdf) and [Juniper saved configuration collection](https://www.juniper.net/assets/jp/jp/local/pdf/service-descriptions/9060154-en.pdf).
- Huawei's [HCIA Security V4.0 lab guide, section 1.2](https://www.scribd.com/document/994479070/HCIA-Security-V4-0-Lab-Guide-eNSP-Pro), a manufacturer-authored guide accessed through a third-party mirror, documents USG `save` and current/saved capture separately. This is documentation evidence, not a hardware certification.

Tests use synthetic `net.Pipe` conversations with the actual connector profiles, native firemon parsers and renderers, the deployment engine, durable journals and snapshot storage. Each of the seven vendors covers successful application and independent recovery after a lost save response, proving writes are not replayed. Additional tests cover PAN lock ownership, queued jobs, cancellation, resource limits and malformed output, SRX dirty candidates, Fortinet missing VDOMs and unproved persistence modes. No real device, database or network credential was used. Firmware interoperability and externally forced administrator changes remain unverified.

With authenticated Git access to the private connector repository:

```sh
cd adapter/netconnector
GOWORK=off GOPRIVATE=github.com/gatework/go-net-connector go test -count=1 -race ./...
GOWORK=off GOPRIVATE=github.com/gatework/go-net-connector go vet ./...
GOWORK=off GOPRIVATE=github.com/gatework/go-net-connector go mod verify
```

The public root CI does not have access to the private connector and does not test this nested module. Further native semantic limits are in [the semantics notes](../../docs/native-semantics.md).
