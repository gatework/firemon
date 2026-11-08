package plan

import (
	"context"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// MigrationRuleMapping retains the origin of every newly compiled policy rule.
// One source declaration may require several exact target partitions.
type MigrationRuleMapping struct {
	Source  fm.ID
	Targets []fm.ID
}

// NativeMigrationDraft contains policy declarations already compiled in target
// coordinates. A native compiler owns target identities, order, inline objects,
// pools and policy-bound NAT dependencies. It returns the complete additive delta.
// It cannot authorize execution: Migrate independently proves the resulting graph.
type NativeMigrationDraft struct {
	Input   MigrationInput
	Changes NativeChanges
	Rules   []MigrationRuleMapping
	Limits  policy.Limits
}

// MigrationNATCompiler is implemented by the target driver. Parsing source
// snapshots or inventing missing interface/VRF mappings is outside this boundary.
type MigrationNATCompiler interface {
	CompileMigrationNAT(context.Context, *fm.Firewall, *fm.Firewall, NativeMigrationDraft) (NativeChanges, error)
}

type migrationNATDomain struct {
	mapping        MigrationContextMapping
	source, target policy.Request
	steps          []policy.NATStep
}

func selectedMigrationNAT(input MigrationInput, step policy.NATStep) bool {
	switch step.Kind {
	case fm.StaticNATObject:
		return slices.Contains(input.StaticNATs, step.ID)
	case fm.DynamicNATObject:
		return slices.Contains(input.DynamicNATs, step.ID)
	default:
		return false
	}
}

// An omitted NAT selection means the effective dependency closure of the mapped
// source contexts. Explicit selection must include every step of a composition.
func (p Planner) resolveMigrationNAT(ctx context.Context, source, target *fm.Firewall, input MigrationInput, visits *visitBudget) (MigrationInput, error) {
	if source.StaticNATCount()+source.DynamicNATCount() == 0 {
		if len(input.StaticNATs)+len(input.DynamicNATs) > 0 {
			return input, ErrInvalid
		}
		return input, nil
	}
	implicit := len(input.StaticNATs)+len(input.DynamicNATs) == 0
	if implicit {
		for _, n := range source.StaticNATs() {
			if n.Record().Disabled {
				continue
			}
			input.StaticNATs = append(input.StaticNATs, n.ID())
		}
		for _, n := range source.DynamicNATs() {
			if n.Record().Disabled {
				continue
			}
			input.DynamicNATs = append(input.DynamicNATs, n.ID())
		}
	}
	seen := make(map[fm.NATRef]bool)
	for _, id := range input.StaticNATs {
		key := fm.NATRef{Kind: fm.StaticNATObject, ID: id}
		n := source.StaticNAT(id)
		if seen[key] || n == nil {
			return input, ErrInvalid
		}
		seen[key] = true
		if n.Record().Disabled {
			return input, migrationFailure(id, "disabled-nat", "selected translation is disabled")
		}
	}
	for _, id := range input.DynamicNATs {
		key := fm.NATRef{Kind: fm.DynamicNATObject, ID: id}
		n := source.DynamicNAT(id)
		if seen[key] || n == nil {
			return input, ErrInvalid
		}
		seen[key] = true
		if n.Record().Disabled {
			return input, migrationFailure(id, "disabled-nat", "selected translation is disabled")
		}
	}
	domains, err := p.migrationNATDomains(ctx, source, target, input, visits)
	if err != nil {
		return input, err
	}
	used := make(map[fm.NATRef]bool)
	for _, domain := range domains {
		for _, step := range domain.steps {
			used[fm.NATRef{Kind: step.Kind, ID: step.ID}] = true
		}
	}
	if implicit {
		input.StaticNATs = slices.DeleteFunc(input.StaticNATs, func(id fm.ID) bool { return !used[fm.NATRef{Kind: fm.StaticNATObject, ID: id}] })
		input.DynamicNATs = slices.DeleteFunc(input.DynamicNATs, func(id fm.ID) bool { return !used[fm.NATRef{Kind: fm.DynamicNATObject, ID: id}] })
	} else {
		for key := range seen {
			if !used[key] {
				return input, migrationFailure(key.ID, "inactive-nat-selection", "selected NAT has no effective relation in the mapped source contexts")
			}
		}
	}
	return input, nil
}

// migrationNATDomains derives authorization from actual packet paths, never the
// synthetic egress combinations used to prove preservation. Identity paths are
// retained: a time-limited source translation cannot become permanent.
func (p Planner) migrationNATDomains(ctx context.Context, source, target *fm.Firewall, input MigrationInput, visits *visitBudget, extra ...*fm.Firewall) ([]migrationNATDomain, error) {
	graphs := append([]*fm.Firewall{source}, extra...)
	contexts, err := p.Engine.Contexts(ctx, input.From, graphs...)
	if err != nil {
		return nil, err
	}
	var times []time.Time
	seenTimes := make(map[time.Time]bool)
	for _, q := range contexts {
		if !seenTimes[q.At] {
			seenTimes[q.At] = true
			times = append(times, q.At)
		}
	}
	slices.SortFunc(times, time.Time.Compare)
	interfaces := make(map[fm.ID]fm.ID, len(input.Interfaces))
	for _, mapping := range input.Interfaces {
		interfaces[mapping.Source] = mapping.Target
	}
	limit := p.Engine.Limits.WithDefaults().MaxRegions
	all, err := flow.AllTraffic(limit)
	if err != nil {
		return nil, err
	}
	var out []migrationNATDomain
	for _, at := range times {
		for _, mapping := range input.Contexts {
			if err := visits.take(ctx, source.DeclarationSize()); err != nil {
				return nil, err
			}
			q := mapping.Source.request(at, all)
			declared, err := p.Engine.Query(ctx, source, q)
			if err != nil {
				return nil, err
			}
			_, selected, err := migrationEffects(declared, source, func(r *fm.Rule) bool { return migrationSelected(input, r) }, limit)
			if err != nil {
				return nil, err
			}
			if selected.Empty() {
				continue
			}
			q.Traffic = selected
			packet := policy.PacketRequest{Request: q, VRF: mapping.Source.VRF}
			aliases, err := p.Engine.DiscoverStaticAliases(ctx, source, packet, policy.RealView)
			if err != nil {
				return nil, err
			}
			if !aliases.Unknown.Empty() || !aliases.Ambiguous.Empty() {
				return nil, migrationFailure("", "wire-domain", "selected native coordinates have unresolved or ambiguous original-wire aliases")
			}
			wire := selected
			for _, alias := range aliases.Candidates {
				if err := visits.take(ctx, alias.Wire.RegionCount()); err != nil {
					return nil, err
				}
				wire, err = wire.Union(alias.Wire, limit)
				if err != nil {
					return nil, err
				}
			}
			packet.Traffic = wire
			paths, err := p.Engine.QueryPacket(ctx, source, packet)
			if err != nil {
				return nil, err
			}
			if !paths.Complete || !paths.Unknown.Empty() {
				return nil, migrationFailure("", "source-packet-evidence", "selected source wire domain has unknown routes or policy behavior")
			}
			for _, path := range paths.Paths {
				if err := visits.take(ctx, len(path.NativeRequests)+len(path.Policy.Decisions)+len(path.NAT.Steps)); err != nil {
					return nil, err
				}
				if len(path.NativeRequests) != 1 {
					return nil, migrationFailure("", "native-policy-view", "selected packet path needs one established native policy view")
				}
				native := path.NativeRequests[0]
				if native.Chain() != mapping.Source.Chain {
					return nil, migrationFailure("", "native-policy-chain", "actual source packet path selects a different native chain")
				}
				_, owned, err := migrationEffects(path.Policy, source, func(r *fm.Rule) bool { return migrationSelected(input, r) }, limit)
				if err != nil {
					return nil, err
				}
				if owned.Empty() {
					continue
				}
				var original flow.Traffic
				same, err := native.Traffic.Equal(path.Original, limit)
				if err != nil {
					return nil, err
				}
				if same && migrationPolicyIdentity(source, path.NAT.Steps) {
					original, err = owned.Intersection(path.Original, limit)
					if err != nil {
						return nil, err
					}
				} else {
					covered, err := owned.Equal(native.Traffic, limit)
					if err != nil {
						return nil, err
					}
					if !covered || !path.Policy.Unmatched.Empty() {
						return nil, migrationFailure("", "mixed-native-ownership", "changed policy coordinates need an exact inverse for mixed selected ownership")
					}
					original = path.Original
				}
				if original.Empty() {
					continue
				}
				if path.FromZone != mapping.Source.FromZone || path.ToZone != mapping.Source.ToZone {
					return nil, migrationFailure("", "source-zone", "selected source route differs from the mapped zone pair")
				}
				for _, step := range path.NAT.Steps {
					if !selectedMigrationNAT(input, step) {
						return nil, migrationFailure(step.ID, "nat-dependency", "selected policy requires this additional native translation")
					}
				}
				egress := interfaces[native.EgressInterface]
				if native.EgressInterface == "" || target.Interface(egress) == nil {
					return nil, migrationFailure(native.EgressInterface, "interface-mapping", "selected packet path requires an explicit target egress interface")
				}
				sq := mapping.Source.request(at, original)
				sq.EgressInterface = native.EgressInterface
				tq := mapping.Target.request(at, original)
				tq.EgressInterface = egress
				if len(out) >= p.Engine.Limits.WithDefaults().MaxCombinations {
					return nil, policy.ErrBudget
				}
				out = append(out, migrationNATDomain{mapping: mapping, source: sq, target: tq, steps: slices.Clone(path.NAT.Steps)})
			}
		}
	}
	return out, nil
}

// Equality of projected address sets does not prove identity: a destination
// mapping may permute hosts. Until an exact ownership preimage is available,
// only a wholly selected native domain may cross such a transformation.
func migrationPolicyIdentity(fw *fm.Firewall, steps []policy.NATStep) bool {
	for _, step := range steps {
		if step.Reverse {
			return false
		}
		switch step.Kind {
		case fm.StaticNATObject:
			n := fw.StaticNAT(step.ID)
			if n == nil {
				return false
			}
			r := n.Record()
			if len(r.Destination)+len(r.DestinationPorts) > 0 {
				return false
			}
		case fm.DynamicNATObject:
			n := fw.DynamicNAT(step.ID)
			if n == nil {
				return false
			}
			r := n.Record()
			if r.DestinationMode != fm.NoTranslation || r.DestinationPool != "" || len(r.Destination)+len(r.DestinationPorts) > 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (p Planner) proveMigrationNAT(ctx context.Context, source, before, after *fm.Firewall, input MigrationInput, visits *visitBudget) (policy.NATProof, error) {
	domains, err := p.migrationNATDomains(ctx, source, before, input, visits, before, after)
	if err != nil {
		return policy.NATProof{}, err
	}
	if len(domains) == 0 {
		return policy.NATProof{}, migrationFailure("", "empty-nat-selection", "selection has no established original-wire policy domain")
	}
	var authorized []policy.Request
	for _, domain := range domains {
		if err := visits.take(ctx, source.DeclarationSize()+after.DeclarationSize()); err != nil {
			return policy.NATProof{}, err
		}
		vrfMapped := false
		for _, mapping := range input.VRFs {
			vrfMapped = vrfMapped || (mapping.Source == domain.mapping.Source.VRF && mapping.Target == domain.mapping.Target.VRF)
		}
		if !vrfMapped {
			return policy.NATProof{}, migrationFailure("", "vrf-mapping", "packet migration requires an explicit VRF mapping, including the default VRF")
		}
		sq := policy.PacketRequest{Request: domain.source, VRF: domain.mapping.Source.VRF}
		tq := policy.PacketRequest{Request: domain.target, VRF: domain.mapping.Target.VRF}
		iface := after.Interface(tq.EgressInterface)
		if iface == nil || iface.Zone() == nil {
			return policy.NATProof{}, migrationFailure(tq.EgressInterface, "interface-mapping", "mapped egress lacks a known target zone")
		}
		if tq.ToZone == "" {
			tq.ToZone = iface.Zone().ID()
		}
		if tq.ToZone != iface.Zone().ID() {
			return policy.NATProof{}, migrationFailure(tq.EgressInterface, "egress-zone", "mapped target interface and zone disagree")
		}
		// Includes no-NAT phases and checks the actual mapped egress, not just the
		// translation table's potential relation on an unreachable synthetic egress.
		if _, err := p.Engine.EquivalentPacketEffects(ctx, source, after, sq, tq); err != nil {
			return policy.NATProof{}, err
		}
		if len(domain.steps) > 0 {
			q := domain.target
			// Native table context enumeration also includes hypothetical interfaces.
			// Actual route/interface equivalence was proved above; this allowance is
			// limited to the same original traffic, zone/chain and exact time phase.
			q.EgressInterface = ""
			authorized = append(authorized, q)
		}
	}
	proof, err := p.Engine.PreserveNATOutside(ctx, before, after, input.From, authorized, source)
	if err != nil {
		return policy.NATProof{}, err
	}
	proof.IntentSatisfied = true
	return proof, nil
}
