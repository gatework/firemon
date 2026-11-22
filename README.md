# firemon

Firewall policy automation for Hillstone StoneOS and Palo Alto PAN-OS: parse a running configuration, answer "is this traffic allowed and by which rule", design the smallest verified change that permits a request, render it as device commands, and deploy it safely.

Module `github.com/gatework/firemon`, Go 1.26 or later.

## Install

```sh
go install github.com/gatework/firemon/cmd/firemon@latest
```

## Command line

The everyday question is source, destination and service:

```sh
export FIREMON_INVENTORY=~/firemon/firemon.yaml   # or set it once in the settings file
firemon search --src 10.248.30.5 --dst 10.250.116.25 --service 9600 --name REQ-1001
firemon search --src "10.250.119.0 255.255.255.0，10.250.120.5-9" --dst "1.1.1.1、api.example.com" --service "443, udp 53, app:ssh"
firemon nat --ip 10.0.5.20          # NAT both ways: how an internal address goes out and is published, or what a public one maps to
firemon block --dst 203.0.113.66 --service 445   # block on every firewall: already blocked, or a verified deny rule
firemon health --inventory ~/backups              # fleet policy health: score per firewall and what to fix first
firemon converge --inventory ~/backups --cluster SZX9-IN --plan --out ./cleanup   # verified cleanup script and rollback
```

The inventory locates each part of the request by protected networks, zone bindings and routing. The report shows the active HA member, the first deciding rule for each part, NAT, and traffic that needs confirmation. An L3 binding that conflicts with a determinate route requires confirmation for the affected addresses.

For missing access, the planner prices each eligible existing rule by the actual new objects, group members and rule references. At equal cost it prefers matching endpoints, logging, then device order. It verifies the selected change against the exact traffic and requested schedule. A new rule logs at session start and end by default. Use `--no-log` to disable logging or `log_setting` to select a PAN-OS forwarding profile.

A five-tuple is identified as the standard application of its ports (tcp/22 is SSH), and rules for other applications do not match it. Rules by user, URL category or domain name, and scheduled rules inactive at the query time, are taken not to match. Each such assumption is listed under 前提 together with what it would change (ADR 0017). Use `--service app:SSH` when the application is different, `--user` and `--url-category` to settle those criteria, or `--strict` for the conservative reading. The answer is the scripts, firewall by firewall. Each existing rule that already permits the traffic is printed as the device configuration holds it: the parser records every object's text, and the addresses, services and schedules the rule names come first, group members before the group. Each rule still needed comes with the script that adds or modifies it, its rollback, and a warning when it bypasses a deny that isolates a network. Add `-v` for the reasoning (rule details, premises, risks, why existing rules were not modified) and `-vv` for paths, NAT, candidate costs and every listed item. Use `--no-design` for query only and `--resolve` for DNS. Exit codes are 0 for full coverage, 3 for a verified change, 4 for confirmation, and 2 for usage errors.

Operations (ADR 0018):

```sh
firemon search --src 10.248.30.5 --dst 10.250.116.25 --service 22 --until 2026-12-31     # temporary access: validity window or one-time schedule
firemon search --file tickets.csv          # ticket,src,dst,service[,from zone,to zone,until,description]; each ticket designed on the ones before
firemon search --format markdown ...       # paste into the ticket; --format json (or --json) for tools
```

Every planned change is graded for risk:
- any address, or a network wider than /16;
- any service, or more than 100 ports;
- a sensitive service (SMB, RDP, Telnet, ...) across zones;
- placement before a deny, rated high when that deny isolates a network.

When a plan adds rules but modifies none, the report names the closest existing rules and why they were not extended. Wide requests start with a summary by zone pair, and long lists are bounded (`-v` or `--json` holds everything). A firewall whose NAT rewrites the traffic hands the translated packet to the next firewall. That firewall is evaluated, and planned, for the addresses and port it really sees.

Per firewall search lists the request flow by flow — permitted and by which rule, denied and by which rule, or permitted by nothing — then one action: the rules to add or modify, the commands and the rollback; every part of the request crossing one firewall is designed together, numbered on. `block` checks every firewall of the inventory: traffic its deny rules already decide between every pair of zones is reported blocked by them; otherwise one deny rule for any zone (named B-YYYYMMDD-NNN, logging denies) goes before the first rule that may match the traffic, verified to deny it everywhere and change nothing else. `deploy` refreshes the stored snapshot after a verified change (`--snapshot`, or the one collected from the same address); commands run by hand need `firemon collect`, or the next search designs the change again. Snapshots stored by an older firemon are parsed again from their text automatically.

Defaults come, in order, from the flags, the environment (`FIREMON_STORE`, `FIREMON_INVENTORY`, `FIREMON_TIMEZONE`), the inventory's `store:` (relative to the inventory file), and the settings file. firemon follows the shared gatework layout: the settings file is `$FIREMON_CONFIG`, else `./firemon.yml`, else `~/.gatework/firemon.yml` (relative paths in it are relative to it); device passwords (`FIREMON_PASSWORD`, `FIREMON_ENABLE_PASSWORD`) may go in the 0600 `.env` beside it, under the process environment; snapshots default to `~/.local/share/gatework/firemon/snapshots` and deploy journals to `~/.local/share/gatework/firemon/deploy`.

```yaml
# ~/.gatework/firemon.yml
inventory: firemon/inventory.yaml   # ~/.gatework/firemon/inventory.yaml
timezone: Asia/Shanghai
```

```yaml
# ~/.gatework/firemon/inventory.yaml
# store: snapshots      # optional snapshot directory, relative to this file
firewalls:
  - name: SZX9-IN-FW01
    cluster: SZX9-IN
    role: active          # the member evaluated and planned on; the backup follows by HA
    zones:
      - {zone: l2-trust, protected: true, networks: [10.250.0.0/16, 10.254.0.0/16]}
      - {zone: l2-untrust, networks: [0.0.0.0/0]}   # not protected: where the far end is
  - name: SZX9-IN-FW02
    cluster: SZX9-IN
    role: backup
    zones:
      - {zone: l2-trust, protected: true, networks: [10.250.0.0/16, 10.254.0.0/16]}
      - {zone: l2-untrust, networks: [0.0.0.0/0]}
```

`--inventory` also accepts a configuration backup directory (`<name>-<ip>.txt` files, as a backup run writes them): every Hillstone and PAN-OS configuration in it becomes a member, read directly instead of from the snapshot store. Members the configured inventory file names (settings or `FIREMON_INVENTORY`, matched by `<name>-<ip>`) keep its clusters, roles and zone bindings; the others pair into HA clusters by name (`X-FW01` with `X-FW02`, when both run HA) and own the networks their routes reach. Commands that work on the snapshot store (`converge`) still need an inventory file.

```sh
firemon search --src 10.248.30.5 --dst 10.250.116.25 --service 22 --inventory ~/Documents/2026-10-14
```

The older `protected:`/`protected_zone:` keys still read as protected zones. A transparent (layer-2) firewall needs the far side bound too; without it search says which binding is missing instead of guessing.

Without `--inventory`, a command reads one firewall: a configuration file with `--config FILE` (the vendor is recognised from the file; `--vendor` overrides), a stored snapshot with `--snapshot NAME` (directory `--store`), or the device with `--vendor`, `--host` and `--user` (the password comes from `FIREMON_PASSWORD`, an enable password from `FIREMON_ENABLE_PASSWORD`). `--json` prints machine-readable output.

```sh
# Store a device's configuration as a snapshot; later commands use --snapshot fw1
firemon collect --vendor hillstone --host 10.0.0.1 --user ops --name fw1
firemon collect --list

# One firewall from its configuration file: verdict, deciding rules, verified change (-v for paths and NAT)
firemon search --config pa1.txt --src 10.1.0.0/24 --dst 192.0.2.10 --service tcp/443 --name REQ-1001

# Objects, diagnostics and rules that cannot be evaluated offline
firemon parse --config fw1.txt

# Which objects and rules reference an address
firemon usage --config fw1.txt --addr 10.250.119.11

# Redundant, shadowed, expired and disabled rules, permit-any rules, unused objects
firemon audit --config fw1.txt

# Transparent (layer-2) HA clusters: bind the protected zone and the far side (see firemon.yaml
# above); the active member is evaluated and planned on.
firemon search --inventory firemon.yaml --src 10.248.30.5 --dst 10.250.116.25 --service tcp/9600

# Publish a server port (DNAT) with its security rule; NAT rules match in order, so the
# new rule goes before the rule that would otherwise match first (snat and static work alike)
firemon search --config fw1.txt --src any --dst 10.0.5.20 --service tcp/443 \
  --nat dnat --nat-ip 198.51.100.50 --nat-port 8443 --name REQ-1002

# Policy convergence: unused objects, ineffective, broad and mergeable rules; --plan writes the
# safe cleanups as commands verified to keep every decision, with rollback
firemon hits --host 10.0.0.2 --user ops --vendor paloalto --name pa1   # optional: read-only hit counters
firemon converge --snapshot pa1 --plan

# Migration to another vendor: draft the mapping, fill in the ports, translate
firemon migrate --config fw1.txt --to paloalto --init-mapping map.yaml
firemon migrate --config fw1.txt --to paloalto --mapping map.yaml --out pa-migration

# Design on the live device; with --apply push, verify and save/commit after confirmation
firemon deploy --vendor hillstone --host 10.0.0.1 --user ops --src 10.1.0.5 --dst 192.0.2.10 --service tcp/8443 --apply
```

Built-in services differ by vendor, model and release. `firemon predefined-service --vendor hillstone` prints the predefined service book firemon assumes; when the device differs, save a corrected JSON book (`{"MODEL-PORTS": ["tcp/8080"]}`) and pass it with `--predefined-service` (see ADR 0007). Names missing from the book leave the rest of a rule's service list decisive: traffic that a known service matches is decided by the rule, the rest is reported as possibly matched.

Addresses accept `10.0.0.1`, `10.0.0.0/24`, `10.0.0.1-10.0.0.9` and `any`; services accept `tcp/443`, `udp/53`, `tcp/8000-8010`, `icmp`, `icmp/8`, `89` and `any`, comma separated. Transparent (layer-2) firewalls take zones from the inventory bindings, or from `--from-zone` and `--to-zone`, because routing cannot derive them.

## Library

| Package | Role |
|---|---|
| `traffic` | Exact set algebra: addresses (IPv4/IPv6), services, spaces and regions |
| `firemon` | Domain model (`Config`) and compiler (`Compile` → `Firewall`) |
| `query` | Ordered first-match evaluation with routing and NAT |
| `design` | Verified change plans: reuse objects, extend rules, add rules |
| `audit` | Shadowing, redundancy and hygiene review |
| `inventory` | Firewalls a flow crosses: protected networks, routing fallback, next-hop chains, HA clusters |
| `intake` | Tolerant reading of operator input with coded notes |
| `report` | Per-firewall classification, candidate rules and plans |
| `adapter/yamlfile`, `adapter/dns` | Operator inventory file; optional domain resolution |
| `deploy` | Fingerprint-checked, journaled deployment on netops `apply` (records in netops `store/journal`) |
| `vendors/hillstone`, `vendors/paloalto` | Parsing and rendering per vendor |
| `adapter/netconnector` | Device access through net-connector `connector` (SSH, Hillstone/PAN-OS drivers, PAN-OS guarded config read and commit) |
| `adapter/filestore` | Snapshot directory: raw text, parsed configuration, fingerprint |

See the package examples (`go doc github.com/gatework/firemon/query`) and the [ADRs](docs/adr) for the model and the semantics.

## Semantics in one paragraph

Rules are evaluated in device order and the first match decides, deny rules included; disabled rules and rules outside their schedule do not match. Anything that cannot be evaluated offline (domain names, application identification, dynamic groups, unknown objects) makes a rule undecidable: the query reports `indeterminate` instead of guessing. A design extends an existing rule only when the extension cannot permit anything outside the request, places a new rule before a specific deny that blocks the request (check warns to confirm it), and is verified by applying it to a copy of the configuration before it is shown.

## Development

```sh
make check                                  # the full gate (STANDARD.md MOD-5)
make fuzz                                   # fuzz the algebra and both parsers
FIREMON_CORPUS=/path/to/backups make corpus # parse and prove on private configurations, aggregate output only
```

Test layers: unit and golden tests use synthetic fixtures under `testdata/`; the corpus tests run only when `FIREMON_CORPUS` is set; nothing in the test suite connects to a device. `internal/oracle` decides single packets by reading the rules top down, independently of the query engine, and `make corpus` proves the core algorithms on every configuration with it: the engine's first-match decisions on the boundary packets of every rule, designs that permit exactly the request and read back as predicted, cleanups that keep every decision and roll back exactly, and migrations that decide like the source.
