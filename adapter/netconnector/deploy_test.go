package netconnector_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	fm "github.com/gatework/firemon"
	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors/asa"
	"github.com/gatework/go-net-connector/connector"
)

type observedConnection struct {
	net.Conn
	closed atomic.Bool
}

func (c *observedConnection) Close() error { err := c.Conn.Close(); c.closed.Store(true); return err }

func TestNativeASADeployAndLostSaveRecoveryUseIndependentReadback(t *testing.T) {
	for _, lostSaveReply := range []bool{false, true} {
		t.Run(map[bool]string{false: "apply", true: "recover-lost-save"}[lostSaveReply], func(t *testing.T) {
			ctx := context.Background()
			const raw = "interface inside0\n nameif inside\n security-level 100\n ip address 192.0.2.1 255.255.255.0\n!\ninterface outside0\n nameif outside\n security-level 0\n ip address 198.51.100.1 255.255.255.0\n!\naccess-list IN extended deny ip any4 any4\naccess-group IN in interface inside\n"
			metadata := fm.Metadata{Device: "fw", Vendor: "asa", Software: "9.12"}
			before, err := asa.Parse(ctx, config.Source{Text: raw, Complete: true}, metadata)
			if err != nil || !before.Complete() {
				t.Fatal(before, err)
			}
			src, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.10/32"))
			dst, _ := flow.PrefixRange(netip.MustParsePrefix("198.51.100.10/32"))
			traffic, err := flow.NewTraffic(16, flow.TrafficRegion{Source: src, Destination: dst, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
			if err != nil {
				t.Fatal(err)
			}
			request := policy.Request{Traffic: traffic, RuleSet: "IN", FromZone: "inside"}
			p, err := (plan.Planner{Renderer: asa.Renderer{}}).Plan(ctx, before, []policy.Request{request})
			if err != nil {
				t.Fatal(err)
			}
			commands := p.Commands()
			var objects, entries []string
			inObject := false
			for _, command := range commands {
				switch {
				case command == "configure terminal" || command == "end":
				case command == "exit":
					inObject = false
					objects = append(objects, "!")
				case strings.HasPrefix(command, "object "):
					inObject = true
					objects = append(objects, command)
				case strings.HasPrefix(command, "access-list IN line 1 extended "):
					entries = append(entries, strings.Replace(command, " line 1 ", " ", 1))
				case inObject:
					objects = append(objects, " "+command)
				default:
					t.Fatalf("unexpected native command: %q", command)
				}
			}
			afterRaw := strings.Join(objects, "\n") + "\n" + strings.Join(entries, "\n") + "\n" + raw
			var mu sync.Mutex
			var peers sync.WaitGroup
			var connections []*observedConnection
			running, saved := raw, raw
			applied, saves, savedReads := 0, 0, 0
			factory := adapter.Factory{Resolve: func(_ context.Context, id string) (adapter.Target, error) {
				return adapter.Target{
					Metadata: metadata, Connection: connector.ConnectionConfig{Host: "synthetic"}, DeviceOptions: []connector.Option{connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
						for _, prior := range connections {
							if !prior.closed.Load() {
								t.Error("readback opened before the previous connection closed")
							}
						}
						a, b := net.Pipe()
						client := &observedConnection{Conn: a}
						connections = append(connections, client)
						peers.Add(1)
						go func() {
							defer peers.Done()
							defer b.Close()
							_, _ = io.WriteString(b, "fw#")
							scanner := bufio.NewScanner(b)
							for scanner.Scan() {
								command := scanner.Text()
								body := ""
								drop := false
								mu.Lock()
								switch command {
								case "enable", "terminal pager 0":
								case "show running-config":
									body = running
								case "show startup-config":
									savedReads++
									body = saved
								case "write memory":
									saves++
									saved = running
									body = "Building configuration...\n[OK]"
									drop = lostSaveReply
								default:
									if applied >= len(commands) || command != commands[applied] {
										t.Errorf("unexpected configuration write: %q", command)
										mu.Unlock()
										return
									}
									applied++
									if applied == len(commands) {
										running = afterRaw
									}
								}
								mu.Unlock()
								if drop {
									return
								}
								if _, err := io.WriteString(b, command+"\r\n"+body+"\r\nfw#"); err != nil {
									return
								}
							}
						}()
						return client, nil
					})},
				}, nil
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
			base, err := store.Publish(ctx, before, snapshot.PublishOptions{PublicationID: "baseline"})
			if err != nil {
				t.Fatal(err)
			}
			journal, err := deploy.OpenJournal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			engine := configuredEngine{Options: deploy.Options{Store: store, Journal: journal, Sessions: factory, Parser: config.ParseFunc(asa.Parse), Authorizer: deploy.AuthorizeFunc(func(_ context.Context, a deploy.Authorization) error {
				if a.Device != "fw" || a.PlanDigest != p.Digest() || a.BaselineRevision != base.Revision {
					return errors.New("wrong authorization")
				}
				return nil
			})}, t: t}
			result, err := engine.Apply(ctx, "operation", base.Revision, p)
			if lostSaveReply {
				if !errors.Is(err, deploy.ErrUncertain) {
					t.Fatal("lost save was accepted", result, err)
				}
				result, err = engine.Recover(ctx, "operation", p)
			}
			if err != nil || result.Phase != deploy.Published || result.Recovered != lostSaveReply {
				t.Fatal(result, err)
			}
			current, head, err := store.Current(ctx, "fw")
			if err != nil || head.Revision == base.Revision {
				t.Fatal(head, err)
			}
			if _, err := p.Verify(ctx, current); err != nil {
				t.Fatal(err)
			}
			query, err := (policy.Engine{}).Query(ctx, current, request)
			covered, coverageErr := query.Allowed.Contains(traffic, 16)
			bounded, boundsErr := traffic.Contains(query.Allowed, 16)
			if err != nil || coverageErr != nil || boundsErr != nil || !covered || !bounded {
				t.Fatal(query, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(connections) != 2 || applied != len(commands) || saves != 1 || savedReads != map[bool]int{false: 0, true: 1}[lostSaveReply] {
				t.Fatal("unexpected replay or readback", len(connections), applied, saves, savedReads)
			}
		})
	}
}
