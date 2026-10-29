package netconnector_test

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors/fortinet"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/huawei"
	"github.com/gatework/firemon/vendors/netscreen"
	"github.com/gatework/firemon/vendors/paloalto"
	"github.com/gatework/firemon/vendors/srx"
	"github.com/gatework/go-net-connector/connector"
)

type nativeCase struct {
	vendor, prompt, raw, from, to, domain string
	parser                                config.ParseFunc
	renderer                              plan.Renderer
}

func nativeCases() []nativeCase {
	return []nativeCase{
		{vendor: "hillstone", prompt: "fw(M)", from: "inside", to: "outside", parser: hillstone.Parse, renderer: hillstone.Renderer{}, raw: "zone inside\nexit\nzone outside\nexit\ninterface eth0\nzone inside\nip address 192.0.2.1 255.255.255.0\nexit\ninterface eth1\nzone outside\nip address 198.51.100.1 255.255.255.0\nexit"},
		{vendor: "paloalto", prompt: "audit@fw>", from: "inside", to: "outside", parser: paloalto.Parse, renderer: paloalto.Renderer{}, raw: "set network interface ethernet eth1 layer3 ip 192.0.2.1/24\nset network interface ethernet eth2 layer3 ip 198.51.100.1/24\nset zone inside network layer3 eth1\nset zone outside network layer3 eth2"},
		{vendor: "srx", prompt: "audit@fw>", from: "inside", to: "outside", parser: srx.Parse, renderer: srx.Renderer{}, raw: "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\nset interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24\nset security zones security-zone inside interfaces ge-0/0/0.0\nset security zones security-zone outside interfaces ge-0/0/1.0"},
		{vendor: "netscreen", prompt: "fw->", from: "Trust", to: "Untrust", parser: netscreen.Parse, renderer: netscreen.Renderer{}, raw: "set interface ethernet0/1 zone Trust\nset interface ethernet0/1 ip 192.0.2.1/24\nset interface ethernet0/2 zone Untrust\nset interface ethernet0/2 ip 198.51.100.1/24"},
		{vendor: "huawei", prompt: "<fw>", from: "trust", to: "untrust", parser: huawei.Parse, renderer: huawei.Renderer{}, raw: "firewall zone trust\n add interface GigabitEthernet1/0/1\n#\nfirewall zone untrust\n add interface GigabitEthernet1/0/2\n#\ninterface GigabitEthernet1/0/1\n ip address 192.0.2.1 24\n#\ninterface GigabitEthernet1/0/2\n ip address 198.51.100.1 24\n#"},
		{vendor: "fortinet", prompt: "FGT (root) #", from: "lan1", to: "wan1", domain: "blue", renderer: fortinet.Renderer{}, parser: func(ctx context.Context, s config.Source, m fm.Metadata) (*fm.Firewall, error) {
			return fortinet.ParseVDOM(ctx, s, m, m.Context)
		}, raw: "config system interface\nedit \"lan1\"\nset vdom \"blue\"\nset ip 192.0.2.1 255.255.255.0\nset type physical\nnext\nedit \"wan1\"\nset vdom \"blue\"\nset ip 198.51.100.1 255.255.255.0\nset type physical\nnext\nend"},
	}
}

func nativeAfter(t *testing.T, vendor, raw string, commands []string) string {
	t.Helper()
	var lines []string
	depth := 0
	for i, command := range commands {
		switch vendor {
		case "srx", "paloalto":
			if strings.HasPrefix(command, "set ") {
				lines = append(lines, command)
			}
		case "hillstone":
			if i > 0 && i < len(commands)-1 {
				lines = append(lines, command)
			}
		case "netscreen":
			lines = append(lines, strings.ReplaceAll(command, " top from ", " from "))
		case "fortinet":
			if !strings.HasPrefix(command, "move ") {
				lines = append(lines, command)
			}
		case "huawei":
			switch {
			case command == "system-view" || command == "return":
			case command == "quit":
				depth--
				if depth == 0 {
					lines = append(lines, "#")
				}
			case strings.HasPrefix(command, "rule move "):
			default:
				lines = append(lines, strings.Repeat(" ", depth)+command)
				if command == "security-policy" || strings.HasPrefix(command, "ip address-set ") || strings.HasPrefix(command, "ip service-set ") || strings.HasPrefix(command, "rule name ") {
					depth++
				}
			}
		}
	}
	if depth != 0 {
		t.Fatal("unclosed synthetic view")
	}
	return raw + "\n" + strings.Join(lines, "\n")
}

// Build a small independent saved-XML capture using only the fixture's native
// address/service/rule/interface forms. Unsupported forms fail the test setup.
func nativePANXML(t *testing.T, raw string) string {
	t.Helper()
	cursor, err := config.NewCursor(context.Background(), config.Source{Text: raw, Complete: true}, config.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	statements, err := config.Statements(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	type node struct {
		name, attribute, text string
		children              []*node
	}
	root := &node{name: "config"}
	child := func(parent *node, name, attribute string) *node {
		for _, n := range parent.children {
			if n.name == name && n.attribute == attribute {
				return n
			}
		}
		n := &node{name: name, attribute: attribute}
		parent.children = append(parent.children, n)
		return n
	}
	for _, st := range statements {
		w := st.Words
		if len(w) < 4 || w[0] != "set" {
			t.Fatal(st)
		}
		n := root
		var path []string
		var value string
		member := false
		switch w[1] {
		case "network":
			path = []string{"network", "interface", "ethernet", "@" + w[4], "layer3", "ip", "@" + w[7]}
		case "zone":
			path = []string{"zone", "@" + w[2], "network", "layer3", "member"}
			value = w[5]
		case "address":
			path = []string{"address", "@" + w[2], w[3]}
			value = w[4]
		case "service":
			path = []string{"service", "@" + w[2], "protocol", w[4], w[5]}
			value = w[6]
		case "rulebase":
			path = []string{"rulebase", "security", "rules", "@" + w[4], w[5]}
			switch w[5] {
			case "from", "to", "source", "destination", "application", "service":
				member = true
			}
			values := w[6:]
			if values[0] == "[" {
				values = values[1 : len(values)-1]
			}
			if len(values) != 1 {
				t.Fatal("fixture needs one XML field value", w)
			}
			value = values[0]
		default:
			t.Fatal("unsupported fixture XML statement", w)
		}
		for _, part := range path {
			if strings.HasPrefix(part, "@") {
				n = child(n, "entry", part[1:])
			} else {
				n = child(n, part, "")
			}
		}
		if member {
			n = child(n, "member", "")
		}
		n.text = value
	}
	var out strings.Builder
	var write func(*node)
	write = func(n *node) {
		out.WriteString("<" + n.name)
		if n.attribute != "" {
			out.WriteString(` name="`)
			if err := xml.EscapeText(&out, []byte(n.attribute)); err != nil {
				t.Fatal(err)
			}
			out.WriteString(`"`)
		}
		out.WriteString(">")
		if err := xml.EscapeText(&out, []byte(n.text)); err != nil {
			t.Fatal(err)
		}
		for _, c := range n.children {
			write(c)
		}
		out.WriteString("</" + n.name + ">")
	}
	write(root)
	return out.String()
}

func TestNativeVendorsApplyAndRecoverLostSaveWithoutReplay(t *testing.T) {
	for _, tc := range nativeCases() {
		modes := []string{"apply", "recover"}
		if tc.vendor == "fortinet" {
			modes = append(modes, "manual", "revert", "unknown")
		}
		for _, mode := range modes {
			lost := mode == "recover"
			rejectMode := mode != "apply" && mode != "recover"
			cfgSave := "automatic"
			if rejectMode {
				cfgSave = mode
			}
			t.Run(tc.vendor+"/"+mode, func(t *testing.T) {
				ctx := context.Background()
				metadata := fm.Metadata{Device: "fw", Vendor: tc.vendor, Context: tc.domain}
				before, err := tc.parser(ctx, config.Source{Text: tc.raw, Complete: true}, metadata)
				if err != nil || !before.Complete() {
					t.Fatal(before, err)
				}
				src, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.10/32"))
				dst, _ := flow.PrefixRange(netip.MustParsePrefix("198.51.100.10/32"))
				traffic, err := flow.NewTraffic(8, flow.Box{Source: src, Destination: dst, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1000, High: 1000}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
				if err != nil {
					t.Fatal(err)
				}
				p, err := (plan.Planner{Renderer: tc.renderer}).Plan(ctx, before, []policy.Request{{Traffic: traffic, Scope: tc.domain, FromZone: fm.ID(tc.from), ToZone: fm.ID(tc.to)}})
				if err != nil {
					t.Fatal(err)
				}
				commands := p.Commands()
				wire := append([]string(nil), commands...)
				if tc.vendor == "srx" {
					wire[0], wire[len(wire)-1] = "top", "top"
				}
				afterRaw := nativeAfter(t, tc.vendor, tc.raw, commands)
				afterSavedRaw := afterRaw
				if tc.vendor == "paloalto" {
					afterSavedRaw = nativePANXML(t, afterRaw)
				}
				after, err := tc.parser(ctx, config.Source{Text: afterRaw, Complete: true}, metadata)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := p.Verify(ctx, after); err != nil {
					t.Fatal(err, after.Diagnostics(), commands)
				}
				if tc.vendor == "paloalto" {
					persisted, err := tc.parser(ctx, config.Source{Text: afterSavedRaw, Complete: true}, metadata)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := p.Verify(ctx, persisted); err != nil {
						t.Fatal(err, persisted.Diagnostics())
					}
				}
				var peers sync.WaitGroup
				var mu sync.Mutex
				running, saved := tc.raw, tc.raw
				writes, saves, opens, captures := 0, 0, 0, 0
				panLock := ""
				var connections []*observedConnection
				factory := adapter.Factory{Options: adapter.Options{ExclusivePANAdmin: true, PollInterval: time.Millisecond}, Resolve: func(_ context.Context, id string) (adapter.Target, error) {
					return adapter.Target{Metadata: metadata, Connection: connector.ConnectionConfig{Host: "synthetic"}, DeviceOptions: []connector.Option{connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
						for _, c := range connections {
							if !c.closed.Load() {
								t.Error("prior connection is still open")
							}
						}
						a, b := net.Pipe()
						client := &observedConnection{Conn: a}
						connections = append(connections, client)
						opens++
						peers.Add(1)
						go func() {
							defer peers.Done()
							defer b.Close()
							prompt := tc.prompt
							domain := "root"
							configMode := false
							panChecks, panPolls := 0, 0
							_, _ = io.WriteString(b, prompt)
							scanner := bufio.NewScanner(b)
							for scanner.Scan() {
								command := scanner.Text()
								body := ""
								drop := false
								mu.Lock()
								if writes < len(wire) && command == wire[writes] && (tc.vendor != "paloalto" || panChecks >= 3) {
									if tc.vendor == "srx" && !configMode {
										t.Error("candidate edit without exclusive mode")
									}
									if tc.vendor == "fortinet" && domain != tc.domain {
										t.Error("write in wrong VDOM")
									}
									writes++
									if writes == len(wire) && tc.vendor != "srx" && tc.vendor != "paloalto" {
										running = afterRaw
									}
									if tc.vendor == "huawei" {
										if command == "return" {
											prompt = "<fw>"
										} else {
											prompt = "[fw]"
										}
									}
									if tc.vendor == "paloalto" {
										if command == "configure" {
											prompt = "audit@fw#"
										}
										if command == "exit" {
											prompt = "audit@fw>"
										}
									}
								} else {
									if strings.HasPrefix(command, `request config-lock add comment "firemon:`) {
										if panLock != "" {
											t.Error("lock takeover attempted")
										}
										panLock = strings.TrimSuffix(strings.TrimPrefix(command, `request config-lock add comment "firemon:`), `"`)
									} else {
										nativeCommand := command
										if tc.vendor == "srx" {
											if command == "commit" {
												t.Error("SRX commit requires an audit comment")
											}
											if strings.HasPrefix(command, `commit comment "firemon:`) && strings.HasSuffix(command, `"`) {
												nativeCommand = "commit"
											}
										}
										switch nativeCommand {
										case "su":
											body = "privilege level is 3"
										case "screen-length 0 temporary":
										case "terminal length 0", "set cli pager off", "set cli config-output-format set", "set cli op-command-xml-output on", "set cli op-command-xml-output off":
										case "show config-locks vsys all":
											panChecks++
											body = emptyPANLocks
											if panLock != "" {
												body = strings.ReplaceAll(ownedPANLock, lockToken, panLock)
											}
										case "request config-lock remove":
											panLock = ""
										case "show config diff":
										case "configure":
											prompt = "audit@fw#"
										case "show":
											body = running + "\n[edit]"
										case "configure exclusive":
											configMode = true
											prompt = "audit@fw#"
											body = "Entering configuration mode\n[edit]"
										case "show | compare | no-more":
											body = "[edit]"
										case "exit":
											configMode = false
											prompt = "audit@fw>"
										case "run show configuration | display set | no-more", "show configuration | display set | no-more", "get config", "dis cur":
											body = running
										case "show configuration running":
											body = running
										case "show configuration startup", "show config saved running-config.xml":
											body = saved
										case "show jobs id 42":
											panPolls++
											body = "2026/01/01 00:00:00 42 1 Commit QUEUED PEND 0%"
											if panPolls == 2 {
												body = "2026/01/01 00:00:00 00:00:01 42 Commit ACT PEND 50%"
											}
											if panPolls >= 3 {
												body = "2026/01/01 00:00:00 00:00:01 42 Commit FIN OK 00:00:02"
												panLock = ""
											}
										case "get config saved", "display saved-configuration":
											body = saved
										case "get system status":
											body = "Current virtual domain: " + domain + "\nVirtual domain configuration: enable"
										case "config global":
											prompt = "FGT (global) #"
										case "diagnose sys vd list":
											body = "name=root index=0 enabled\nname=blue index=1 enabled"
										case "end":
											prompt = "FGT #"
											domain = "root"
										case "config vdom":
											prompt = "FGT (vdom) #"
										case `edit "blue"`:
											domain = "blue"
											prompt = "FGT (blue) #"
										case "show full-configuration system global":
											body = "config system global\nset cfg-save " + cfgSave + "\nend"
										case "show full-configuration":
											captures++
											if domain != tc.domain {
												t.Error("capture in wrong VDOM")
											}
											body = running
										case "commit", "save", "execute cfg save", "save all":
											if tc.vendor == "huawei" {
												_, _ = io.WriteString(b, "Are you sure to continue?[Y/N]")
												if !scanner.Scan() || scanner.Text() != "y" {
													t.Error("missing Huawei save confirmation")
													mu.Unlock()
													return
												}
											}
											saves++
											running = afterRaw
											saved = afterSavedRaw
											drop = lost
											if nativeCommand == "commit" {
												body = "commit complete\n[edit]"
												if tc.vendor == "paloalto" {
													body = "Commit job enqueued with jobid 42"
													if lost {
														panLock = ""
													}
												}
											}
											if command == "save all" {
												body = "Saving configuration is finished."
											}
											if tc.vendor == "huawei" {
												body = "Info: The configuration has been saved successfully."
											}
										default:
											t.Errorf("unexpected native command %q", command)
											mu.Unlock()
											return
										}
									}
								}
								mu.Unlock()
								if drop {
									return
								}
								if _, err := io.WriteString(b, command+"\r\n"+body+"\r\n"+prompt); err != nil {
									return
								}
							}
						}()
						return client, nil
					})}}, nil
				}}
				t.Cleanup(func() {
					for _, c := range connections {
						_ = c.Close()
					}
					peers.Wait()
				})
				store, err := snapshot.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				base, err := store.Publish(ctx, before, snapshot.PublishOptions{PublicationID: "base"})
				if err != nil {
					t.Fatal(err)
				}
				journal, err := deploy.OpenJournal(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				engine := configuredEngine{Options: deploy.Options{Store: store, Journal: journal, Sessions: factory, Parser: tc.parser, Authorizer: deploy.AuthorizeFunc(func(context.Context, deploy.Authorization) error { return nil })}, t: t}
				result, err := engine.Apply(ctx, "op", base.Revision, p)
				if rejectMode {
					peers.Wait()
					mu.Lock()
					defer mu.Unlock()
					if !errors.Is(err, adapter.ErrPersistence) || !errors.Is(err, deploy.ErrUncertain) || writes != 0 || saves != 0 || captures != 0 {
						t.Fatalf("unsupported mode reached baseline/writes: captures=%d writes=%d saves=%d err=%v", captures, writes, saves, err)
					}
					return
				}
				if lost {
					if !errors.Is(err, deploy.ErrUncertain) {
						t.Fatal("save loss accepted", result, err)
					}
					result, err = engine.Recover(ctx, "op", p)
				}
				if err != nil || result.Phase != deploy.Published {
					t.Fatal(result, err)
				}
				current, _, err := store.Current(ctx, "fw")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := p.Verify(ctx, current); err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				defer mu.Unlock()
				if writes != len(wire) || saves != 1 || opens != 2 {
					t.Fatalf("writes=%d saves=%d opens=%d", writes, saves, opens)
				}
			})
		}
	}
}
