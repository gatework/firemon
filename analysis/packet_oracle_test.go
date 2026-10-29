package analysis_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// This reference deliberately uses point comparisons, raw DTOs and its own
// rule ordering. Do not use production set algebra, matching or proof helpers
// to compute expectations. It models ordinary policy, not native NAT paths.
type oraclePacket struct {
	source, destination                                       netip.Addr
	protocol, sourcePort, destinationPort, icmpType, icmpCode uint16
}
type oracleDecision struct {
	class                 string
	rule                  fm.ID
	action                fm.Action
	known                 bool
	log, logStart, logEnd fm.Status
}

func oracleContains(bounds flow.AddressRange, address netip.Addr) bool {
	return address.BitLen() == bounds.First.BitLen() && address.Compare(bounds.First) >= 0 && address.Compare(bounds.Last) <= 0
}
func oracleInterval(bounds flow.Interval, value uint16) bool {
	return bounds.Low <= value && value <= bounds.High
}
func oracleRegion(region flow.TrafficRegion, packet oraclePacket) bool {
	return oracleContains(region.Source, packet.source) && oracleContains(region.Destination, packet.destination) &&
		oracleInterval(region.Protocol, packet.protocol) && oracleInterval(region.SourcePort, packet.sourcePort) &&
		oracleInterval(region.DestinationPort, packet.destinationPort) && oracleInterval(region.ICMPType, packet.icmpType) &&
		oracleInterval(region.ICMPCode, packet.icmpCode)
}
func oracleTraffic(traffic flow.Traffic, packet oraclePacket) bool {
	for _, region := range traffic.Regions() {
		if oracleRegion(region, packet) {
			return true
		}
	}
	return false
}
func oracleAddresses(t *testing.T, data fm.Data, refs []fm.AddressRef, any bool, address netip.Addr) (bool, bool) {
	t.Helper()
	if any {
		return true, true
	}
	matched := false
	for _, ref := range refs {
		if ref.Kind != fm.AddressObject {
			t.Fatal("oracle fixture requires direct address references")
		}
		found := false
		for _, record := range data.Addresses {
			if record.ID != ref.ID {
				continue
			}
			found = true
			if record.FQDN != "" || len(record.Unsupported) != 0 {
				return true, false
			}
			for _, bounds := range record.Ranges {
				matched = matched || oracleContains(bounds, address)
			}
		}
		if !found {
			return true, false
		}
	}
	return matched, true
}
func oracleServices(t *testing.T, data fm.Data, refs []fm.ServiceRef, any bool, packet oraclePacket) (bool, bool) {
	t.Helper()
	if any {
		return true, true
	}
	matched := false
	for _, ref := range refs {
		if ref.Kind != fm.ServiceObject {
			t.Fatal("oracle fixture requires direct service references")
		}
		found := false
		for _, record := range data.Services {
			if record.ID != ref.ID {
				continue
			}
			found = true
			if len(record.Unsupported) != 0 {
				return true, false
			}
			for _, term := range record.Terms {
				matched = matched || (oracleInterval(term.Protocol, packet.protocol) && oracleInterval(term.SourcePort, packet.sourcePort) &&
					oracleInterval(term.DestinationPort, packet.destinationPort) && oracleInterval(term.ICMPType, packet.icmpType) && oracleInterval(term.ICMPCode, packet.icmpCode))
			}
		}
		if !found {
			return true, false
		}
	}
	return matched, true
}
func oracleSchedule(data fm.Data, id fm.ID, at time.Time) (bool, bool) {
	if id == "" {
		return true, true
	}
	for _, schedule := range data.Schedules {
		if schedule.ID != id {
			continue
		}
		if at.IsZero() || len(schedule.Unsupported) != 0 || len(schedule.Recurring) != 0 || len(schedule.Windows) == 0 {
			return true, false
		}
		for _, window := range schedule.Windows {
			if !at.Before(window.Start) && at.Before(window.End) {
				return true, true
			}
		}
		return false, true
	}
	return true, false
}
func oracleEvaluate(t *testing.T, data fm.Data, packet oraclePacket, at time.Time) oracleDecision {
	t.Helper()
	rules := slices.Clone(data.Rules)
	slices.SortFunc(rules, func(a, b fm.RuleRecord) int {
		if a.Position < b.Position {
			return -1
		}
		if a.Position > b.Position {
			return 1
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	for _, rule := range rules {
		if rule.Disabled || rule.Scope != "" || rule.RuleSet != "security" {
			continue
		}
		match := rule.Match
		if !match.AnyFromZone || !match.AnyToZone || match.ZoneRelation != fm.AnyZoneRelation {
			t.Fatal("oracle fixture requires any zones")
		}
		source, sourceKnown := oracleAddresses(t, data, match.Sources, match.AnySource, packet.source)
		destination, destinationKnown := oracleAddresses(t, data, match.Destinations, match.AnyDestination, packet.destination)
		service, serviceKnown := oracleServices(t, data, match.Services, match.AnyService, packet)
		if !source || !destination || !service {
			continue
		}
		active, scheduleKnown := oracleSchedule(data, match.Schedule, at)
		if scheduleKnown && !active {
			continue
		}
		known := sourceKnown && destinationKnown && serviceKnown && scheduleKnown && len(rule.Unsupported) == 0 &&
			len(match.Unsupported) == 0 && len(match.Applications) == 0 && len(match.Users) == 0
		class := "unknown"
		switch rule.Action {
		case fm.Permit:
			if known {
				class = "allowed"
			}
		case fm.Deny, fm.Reject, fm.Drop, fm.ResetClient, fm.ResetServer, fm.ResetBoth:
			if known {
				class = "denied"
			}
		default:
			known = false
		}
		return oracleDecision{class, rule.ID, rule.Action, known, rule.Log, rule.LogStart, rule.LogEnd}
	}
	return oracleDecision{class: "unmatched", known: true}
}
func oraclePackets(ipv6 bool) []oraclePacket {
	var packets []oraclePacket
	address := func(last byte, destination bool) netip.Addr {
		if ipv6 {
			subnet := byte(0)
			if destination {
				subnet = 1
			}
			return netip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, subnet, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last})
		}
		subnet := byte(2)
		if destination {
			subnet = 3
		}
		return netip.AddrFrom4([4]byte{192, 0, subnet, last})
	}
	for source := range byte(3) {
		for destination := range byte(3) {
			for _, protocol := range []uint16{0, 1, 6, 17} {
				for sourcePort := range uint16(2) {
					for destinationPort := range uint16(2) {
						for icmpType := range uint16(2) {
							for icmpCode := range uint16(2) {
								packets = append(packets, oraclePacket{address(source, false), address(destination, true), protocol, sourcePort, destinationPort, icmpType, icmpCode})
							}
						}
					}
				}
			}
		}
	}
	return packets
}
func oraclePoint(packet oraclePacket) flow.TrafficRegion {
	point := func(value uint16) flow.Interval { return flow.Interval{Low: value, High: value} }
	return flow.TrafficRegion{Source: flow.AddressRange{First: packet.source, Last: packet.source}, Destination: flow.AddressRange{First: packet.destination, Last: packet.destination},
		Protocol: point(packet.protocol), SourcePort: point(packet.sourcePort), DestinationPort: point(packet.destinationPort), ICMPType: point(packet.icmpType), ICMPCode: point(packet.icmpCode)}
}
func oracleSeal(t *testing.T, data fm.Data) *fm.Firewall {
	t.Helper()
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}
func oracleMakeTraffic(t *testing.T, regions ...flow.TrafficRegion) flow.Traffic {
	t.Helper()
	traffic, err := flow.NewTraffic(4096, regions...)
	if err != nil {
		t.Fatal(err)
	}
	return traffic
}
func oracleRule(id fm.ID, position int, action fm.Action) fm.RuleRecord {
	return fm.RuleRecord{Object: fm.Object{ID: id, Name: string(id)}, Position: position, Action: action, RuleSet: "security",
		Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant,
		Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}
}
