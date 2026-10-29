package policy

import (
	"context"
	"strings"

	fm "github.com/gatework/firemon"
)

type nativeSemantics struct {
	queryPolicy      func(Engine, context.Context, *fm.Firewall, Request) (Result, error)
	queryNAT         func(Engine, context.Context, *fm.Firewall, Request, *int) (NATResult, error)
	queryPacket      func(Engine, context.Context, *fm.Firewall, PacketRequest) (PacketResult, error)
	normalizeRequest func(Request) Request
	staticTransform  func(*natTransform, fm.StaticNATRecord)
	dynamicTransform func(*natTransform)
	reverseStatic    func(natTransform, fm.StaticNATRecord) natTransform
	activeNAT        func(Engine, context.Context, *fm.Firewall, *int) (map[fm.NATRef]bool, error)
	policyBoundNAT   bool
	linearPolicy     bool
	zonePairOrder    bool
	pairBuiltins     bool
	globalDefault    bool
}

func semantics(vendor string) nativeSemantics {
	s := nativeSemantics{queryPolicy: Engine.ordinaryQuery, reverseStatic: stoneReverseStatic, linearPolicy: true}
	switch vendor {
	case "paloalto":
		s.queryNAT, s.queryPacket = Engine.paloaltoNAT, Engine.paloaltoPacket
	case "asa":
		s.queryNAT, s.queryPacket, s.reverseStatic = Engine.asaNAT, Engine.asaPacket, reverseStatic
	case "srx":
		s.queryNAT, s.queryPacket, s.reverseStatic = Engine.srxNAT, Engine.srxPacket, reverseStatic
		s.zonePairOrder, s.globalDefault = true, true
	case "netscreen":
		s.queryNAT, s.queryPacket, s.reverseStatic = Engine.netscreenNAT, Engine.netscreenPacket, reverseStatic
		s.dynamicTransform = screenOSTransform
		s.policyBoundNAT, s.zonePairOrder, s.pairBuiltins, s.globalDefault = true, true, true, true
	case "fortinet":
		s.queryPolicy, s.queryNAT, s.queryPacket = Engine.fortinetQuery, Engine.fortinetNAT, Engine.fortinetPacket
		s.activeNAT, s.policyBoundNAT, s.linearPolicy = Engine.fortinetActiveVIPs, true, false
	case "hillstone":
		s.queryNAT, s.staticTransform, s.dynamicTransform = Engine.hillstoneNAT, stoneStaticTransform, stoneDynamicTransform
	case "huawei":
		s.queryNAT, s.queryPacket, s.reverseStatic = Engine.huaweiNAT, Engine.huaweiPacket, reverseStatic
		s.dynamicTransform = huaweiTransform
		s.normalizeRequest = func(q Request) Request {
			q.FromZone, q.ToZone = fm.ID(strings.ToLower(string(q.FromZone))), fm.ID(strings.ToLower(string(q.ToZone)))
			return q
		}
	}
	return s
}

func (e Engine) ordinaryQuery(ctx context.Context, fw *fm.Firewall, q Request) (Result, error) {
	return e.queryRules(ctx, fw, q, nil)
}

// RuleOrder identifies one independently ordered native chain. Terminal rules
// follow every explicit rule in that chain. It is used for independent readback
// normalization; it never changes the order of policy evaluation.
// RuleChain identifies a native independently ordered chain within a policy chain.
type RuleChain struct {
	PolicyChain      fm.PolicyChain
	FromZone, ToZone fm.ID
}

type RuleOrder struct {
	Chain    RuleChain
	Terminal bool
}

// NativeRuleOrder retains vendor chain boundaries when comparing readback order.
func NativeRuleOrder(vendor string, r fm.RuleRecord) RuleOrder {
	s := semantics(vendor)
	order := RuleOrder{Chain: RuleChain{PolicyChain: r.Chain()}}
	if s.zonePairOrder && (!r.Builtin || s.pairBuiltins) && len(r.Match.FromZones) == 1 && len(r.Match.ToZones) == 1 && !r.Match.AnyFromZone && !r.Match.AnyToZone {
		order.Chain.FromZone, order.Chain.ToZone = r.Match.FromZones[0], r.Match.ToZones[0]
	}
	order.Terminal = s.globalDefault && r.Builtin && r.Match.AnyFromZone && r.Match.AnyToZone
	return order
}
