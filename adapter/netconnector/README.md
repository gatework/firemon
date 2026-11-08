# Optional device connector adapter

This separate module implements `operations.ReadOnlyFactory`, `device.Reader`, `deploy.Factory` and `deploy.Session` contracts for Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA using published `github.com/gatework/go-net-connector v0.2.0` and `github.com/gatework/go-expect v0.4.0`. The root module remains independent of the connector. No dependency source or local `replace` directive is included.

Version v0.1.0 requires Go 1.27 or newer and pins Firemon core v0.1.0 in
[go.mod](go.mod). Install it from an application without a local workspace or
replace directive:

```sh
go get github.com/gatework/firemon/adapter/netconnector@v0.1.0
```

This nested module uses the repository tag `adapter/netconnector/v0.1.0`;
the root module uses `v0.1.0`. See the
[migration guide](../../docs/refactoring.md#connector-v020) and
[integration verification](../../docs/integration-verification.md) for connector
contracts and standalone/current-core evidence. Releases contain source modules,
without precompiled CLI binaries.

The host supplies identity, credentials and transport options through `Factory.Resolve`. `Factory.Open` creates a fresh device for each initial connection, independent readback and recovery. `Profile(vendor)` exposes the supported native profile; SRX, Huawei, Hillstone, Fortinet and PAN reuse the pinned connector profiles with narrowly scoped adapter adjustments. ASA and ScreenOS profiles are provided here. `New` transfers ownership of an already constructed device on success; its caller must set bounded transport limits and a validated profile.

On the development branch after v0.1.0, `Profile` and `Metadata.Vendor` accept
only `paloalto`, `srx`, `huawei`, `hillstone`, `fortinet`, `netscreen` and `asa`.
The adapter maps `paloalto` to the connector's `palo_alto` profile and `srx` to
`juniper` internally. `New` accepts a device profile with its canonical name or
the corresponding connector name, including customized canonical profiles;
it never rewrites metadata. Vendor aliases are rejected before dialing.

`Metadata.Context` identifies the selected native configuration domain and is retained through capture, parsing, planning and journal recovery. Fortinet requires an explicit VDOM, including `root`. All other profiles require an empty `Metadata.Context` and operate in their default native domain. Nonempty labels are rejected by `New` before dialing or capture because this adapter does not select ASA contexts, PAN vsys or Junos logical systems. A connected identity or domain mismatch never becomes a successful readback.

All vendors use `BeginConfiguration`, `Read`, `Execute`, `Save`, `EndConfiguration` and `Close`. `deploy.Session` requires the configuration lifecycle, with explicit handling for immediate-running devices as well as candidate devices. A read-only collector can call `Read` without beginning a configuration transaction. Native differences stay inside this adapter.

Persistence checks separate the verified prompt and command echo from response
history. The connector's verified UTF-8/GBK/GB18030 encoding is decoded without
terminal repainting, so a carriage return cannot erase an earlier rejection.
Fortinet automatic-save evidence requires one complete `config system global`
block with exactly one `set cfg-save automatic`. Other setting values are data;
ordinary hostnames or titles containing `error` or `failed` do not imply failure.
Malformed, ambiguous or unsupported evidence never produces a durable receipt.

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

Failed reads retain bounded evidence from the matching configuration command before returning the error. Responses use the connector's decoded output when available; decoding failures retain raw bytes as incomplete evidence together with the decoding and operation errors. They never establish complete semantics. Pager setup, VDOM selection, save-mode checks and PAN candidate-diff responses are not configuration payloads. A later PAN diff failure retains the already received `show` configuration. Collector publishes this incomplete evidence and a repeat of the same publication ID returns it without reconnecting.

`Execute` persists each command receipt before sending the next command. Receipt errors, rejected commands, cancellation, connection loss and unconfirmed persistence retire the session. PAN polling accepts native queued rows with missing dequeue time or queue position, then active and completed states; job identity, type, error text, bounds and completion remain strict. Reads, execution preparation and polling have output and time bounds. An observer cannot reenter a busy session.

Native references used for these choices:

- [PAN lock ownership and automatic removal](https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/launch-the-web-interface/manage-locks-for-restricting-configuration-changes), [native operation commands](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-cli-ops-command-hierarchy), and the vendor SDK's [ConfigLocks response path](https://github.com/PaloAltoNetworks/pango/blob/v0.10.2/client.go) and [lock XML structure](https://github.com/PaloAltoNetworks/pango/blob/main/xmlapi/lock.go).
- [PAN native queued job output](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNvwCAG&lang=en_US).
- [Junos commit persistence, exclusive ownership and commit comments](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/junos-configuration-commit.html) and [operational versus candidate configuration](https://www-origin.junipercloud.net/documentation/us/en/software/junos/cli/topics/topic-map/junos-configuration-viewing.html).
- [FortiOS save modes](https://docs.fortinet.com/document/fortigate/7.6.1/administration-guide/228450/using-configuration-save-mode), [vendor save-mode explanation](https://community.fortinet.com/fortigate-3/technical-tip-configuration-file-save-mode-for-configuration-changes-96154) and [VDOM inventory output](https://community.fortinet.com/fortigate-3/technical-tip-how-to-find-the-vdom-index-94580).
- [Juniper ScreenOS command mapping](https://www.juniper.net/assets/jp/jp/local/pdf/additional-resources/screenos-to-junos-mapping.pdf) and [Juniper saved configuration collection](https://www.juniper.net/assets/jp/jp/local/pdf/service-descriptions/9060154-en.pdf).
- Huawei's [HCIA Security V4.0 lab guide, section 1.2](https://www.scribd.com/document/994479070/HCIA-Security-V4-0-Lab-Guide-eNSP-Pro), a manufacturer-authored guide accessed through a third-party mirror, documents USG `save` and current/saved capture separately. This is documentation evidence, not a hardware certification.

Tests use synthetic `net.Pipe` conversations with the actual connector profiles, native firemon parsers and renderers, the deployment engine, durable journals and snapshot storage. Each of the seven vendors covers successful application and independent recovery after a lost save response, proving writes are not replayed. Additional tests cover PAN lock ownership, queued jobs, cancellation, resource limits and malformed output, SRX dirty candidates, Fortinet missing VDOMs and unproved persistence modes. No real device, database or network credential was used. Firmware interoperability and externally forced administrator changes remain unverified.

Both connector dependencies are public. Check this module independently of any local workspace:

```sh
cd adapter/netconnector
GOWORK=off go test -count=1 -race ./...
GOWORK=off go vet ./...
GOWORK=off go build ./...
GOWORK=off go mod verify
```

Public CI runs these checks on Go 1.27.0 and 1.27.x. Separate jobs use a temporary workspace to pair this adapter with the checked-out core; those jobs establish current-source compatibility and do not replace the versioned-consumer checks. No workspace file is committed. Further native semantic limits are in [the semantics notes](../../docs/native-semantics.md).

## Read-only collection contract

`Factory.OpenReadOnly(ctx, deviceID)` returns an independently owned
`device.Reader` with only `Read` and `Close`. Opening it does not begin native
configuration isolation. `Factory.Open` returns a fresh `deploy.Session` for
controlled writes. Neither method reuses an earlier session. Capture/view types
live in `device`, and parser contracts live in `config`. Application composition
uses `operations.New` or the checked `NewCollector`, `NewDesigner` and
`deploy.New` constructors; see the core [migration guide](../../docs/refactoring.md).
