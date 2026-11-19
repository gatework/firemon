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
firemon check --src 10.248.30.5 --dst 10.250.116.25 --service 9600 --name REQ-1001
firemon check --src "10.250.119.0 255.255.255.0，10.250.120.5-9" --dst "1.1.1.1、api.example.com" --service "443, udp 53, app:ssh"
```

It reads the addresses and services in any common form, locates the firewalls through the protected networks of the inventory (falling back to routing), evaluates NAT and access control on each HA cluster, and answers per firewall 完全命中 / 部分命中 / 需要新增策略 / 需确认 — a request a deny rule blocks needs a new rule, which goes before that deny with a warning to confirm the bypass — with the existing rules that decide it (zones, objects and their values, to compare with the device), the part not yet permitted, and the action: nothing to do, or the verified commands and rollback to run on the active member (the backup receives them by HA). `-v` adds paths, NAT, input notes, the application-port inference, candidate rules and objects expanded member by member. A port-only request judges rules restricted to applications with service any by the applications' standard ports (SSH tcp/22, HTTP tcp/80…): off those ports they do not match, and the report says so; name the application (`--service app:SSH`) when a port carries it. `--no-design` only queries; `--resolve` resolves domains so address-based rules can be decided; `--json` prints the report, commands included. Exit status: 0 fully matched, 3 a verified change is ready, 4 needs confirmation, 2 usage.

Defaults come, in order, from the flags, the environment (`FIREMON_STORE`, `FIREMON_INVENTORY`, `FIREMON_TIMEZONE`), the inventory's `store:` (relative to the inventory file), and the settings file `~/.config/firemon/config.yaml` (or `FIREMON_CONFIG`):

```yaml
# ~/.config/firemon/config.yaml
inventory: ~/firemon/firemon.yaml
timezone: Asia/Shanghai
```

```yaml
# firemon.yaml
store: snapshots        # snapshot directory, next to this file
firewalls:
  - name: SZX9-FW01
    cluster: SZX9-FW
    protected:
      - zone: INSIDE
        networks: [10.250.0.0/16]
  - name: SZX9-FW02
    cluster: SZX9-FW
```

Every command reads the configuration from `--config FILE`, from a stored snapshot with `--snapshot NAME` (directory `--store`), or from the device with `--host` and `--user` (the password comes from `FIREMON_PASSWORD`, an enable password from `FIREMON_ENABLE_PASSWORD`). `--json` prints machine-readable output.

```sh
# Store a device's configuration as a snapshot; later commands use --snapshot fw1
firemon collect --vendor hillstone --host 10.0.0.1 --user ops --name fw1
firemon collect --list

# Objects, diagnostics and rules that cannot be evaluated offline
firemon parse --vendor hillstone --config fw1.txt

# How the firewall treats traffic: zones, NAT, deciding rules, verdict (exit 3 unless allowed)
firemon query --vendor paloalto --config pa1.txt --src 10.1.0.0/24 --dst 192.0.2.10 --service tcp/443

# Which objects and rules reference an address
firemon usage --vendor hillstone --config fw1.txt --addr 10.250.119.11

# Which firewalls among all snapshots a flow crosses, each verdict, and per-firewall plans
firemon locate --src 10.1.0.5 --dst 192.0.2.10 --service tcp/443 --design

# Redundant, shadowed, expired and disabled rules, permit-any rules, unused objects
firemon audit --vendor hillstone --config fw1.txt

# Transparent (layer-2) HA clusters: protected networks act as routes to the protected zone,
# everything else is reached through the peer zone; the active member is evaluated and planned on.
#   firewalls:
#     - {name: szx9-in-fw01, cluster: SZX9-IN, role: active, protected_zone: l2-trust,
#        protected: [{networks: [10.250.0.0/16, 10.254.0.0/16]}]}
#     - {name: szx9-in-fw02, cluster: SZX9-IN, role: backup, protected_zone: l2-trust,
#        protected: [{networks: [10.250.0.0/16, 10.254.0.0/16]}]}
firemon check --inventory firemon.yaml --src 10.248.30.5 --dst 10.250.116.25 --service tcp/9600

# Design and render the change that permits a request (no device access)
firemon design --vendor paloalto --config pa1.txt --src 10.1.0.5 --dst 192.0.2.10 --service tcp/8443 \
  --name REQ-1001 --description "ticket 1001"

# Publish a server port (DNAT) with its security rule; NAT rules match in order, so the
# new rule goes before the rule that would otherwise match first (snat and static work alike)
firemon design --vendor hillstone --config fw1.txt --src any --dst 10.0.5.20 --service tcp/443 \
  --nat dnat --nat-ip 198.51.100.50 --nat-port 8443 --name REQ-1002

# Policy convergence: unused objects, ineffective, broad and mergeable rules; --plan writes the
# safe cleanups as commands verified to keep every decision, with rollback
firemon hits --host 10.0.0.2 --user ops --vendor paloalto --name pa1   # optional: read-only hit counters
firemon converge --snapshot pa1 --plan

# Migration to another vendor: draft the mapping, fill in the ports, translate
firemon migrate --vendor hillstone --config fw1.txt --to paloalto --init-mapping map.yaml
firemon migrate --vendor hillstone --config fw1.txt --to paloalto --mapping map.yaml --out pa-migration

# Design on the live device; with --apply push, verify and save/commit after confirmation
firemon deploy --vendor hillstone --host 10.0.0.1 --user ops --src 10.1.0.5 --dst 192.0.2.10 --service tcp/8443 --apply
```

Built-in services differ by vendor, model and release. `firemon services --vendor hillstone` prints the predefined service book firemon assumes; when the device differs, save a corrected JSON book (`{"MODEL-PORTS": ["tcp/8080"]}`) and pass it with `--service-book` (see ADR 0007). Names missing from the book leave the rest of a rule's service list decisive: traffic that a known service matches is decided by the rule, the rest is reported as possibly matched.

Addresses accept `10.0.0.1`, `10.0.0.0/24`, `10.0.0.1-10.0.0.9` and `any`; services accept `tcp/443`, `udp/53`, `tcp/8000-8010`, `icmp`, `icmp/8`, `89` and `any`, comma separated. Transparent (layer-2) deployments need `--from-zone` and `--to-zone`, because zones cannot be derived from routing.

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
| `deploy` | Fingerprint-checked, journaled deployment on go-netops `apply` |
| `vendors/hillstone`, `vendors/paloalto` | Parsing and rendering per vendor |
| `adapter/netconnector` | Device access through net-connector |
| `adapter/filestore` | Snapshot directory: raw text, parsed configuration, fingerprint |

See the package examples (`go doc github.com/gatework/firemon/query`) and the [ADRs](docs/adr) for the model and the semantics.

## Semantics in one paragraph

Rules are evaluated in device order and the first match decides, deny rules included; disabled rules and rules outside their schedule do not match. Anything that cannot be evaluated offline (domain names, application identification, dynamic groups, unknown objects) makes a rule undecidable: the query reports `indeterminate` instead of guessing. A design extends an existing rule only when the extension cannot permit anything outside the request, places a new rule before a specific deny that blocks the request (check warns to confirm it; `design` needs `--override`), and is verified by applying it to a copy of the configuration before it is shown.

## Development

```sh
make check                                  # the full gate (STANDARD.md MOD-5)
make fuzz                                   # fuzz the algebra and both parsers
FIREMON_CORPUS=/path/to/backups make corpus # parse and prove on private configurations, aggregate output only
```

Test layers: unit and golden tests use synthetic fixtures under `testdata/`; the corpus tests run only when `FIREMON_CORPUS` is set; nothing in the test suite connects to a device. `internal/oracle` decides single packets by reading the rules top down, independently of the query engine, and `make corpus` proves the core algorithms on every configuration with it: the engine's first-match decisions on the boundary packets of every rule, designs that permit exactly the request and read back as predicted, cleanups that keep every decision and roll back exactly, and migrations that decide like the source.
