package policy

import (
	"cmp"
	"context"
	"encoding/json"
	"net/netip"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// These descriptors describe relations, not native ownership. Original mapping
// intervals remain part of the key so a permutation cannot be hidden by an
// equal union of translated addresses. Step order and allocation modes remain
// explicit; independently named pools compare by resolved values.
type migrationNATStep struct {
	Source, Destination           []fm.Mapping
	SourcePorts, DestinationPorts []fm.PortMapping
	Allocation                    *migrationAllocation
}

type migrationAllocation struct {
	SourceMode, DestinationMode fm.TranslationMode
	SourcePool, DestinationPool *migrationPool
	InterfaceAddresses          []netip.Addr
}

type migrationPool struct {
	Ranges             []flow.AddressRange
	Ports              flow.Interval
	InterfaceAddresses []netip.Addr
	HasInterface       bool
}

type migrationNATSignature struct {
	Steps                     []migrationNATStep
	Exact, PossibleAllocation bool
}

type migrationStepView struct {
	transform  natTransform
	definition migrationNATStep
}

func migrationRelation(ctx context.Context, fw *fm.Firewall, path PacketPath, cache map[NATStep]migrationStepView, budget *packetProofBudget) (string, error) {
	r := path.NAT
	if len(r.Steps) > budget.limits.MaxCombinations {
		return "", ErrBudget
	}
	if err := budget.take(ctx, len(r.Steps)); err != nil {
		return "", err
	}
	if same, err := budget.equal(ctx, r.Original, path.Original); err != nil {
		return "", err
	} else if !same || len(r.Steps) == 0 && (r.ID != "" || r.Kind != fm.UnknownObject) {
		return "", ErrNotEquivalent
	}
	signature := migrationNATSignature{Exact: true}
	translated := r.Original
	for _, step := range r.Steps {
		if step.Reverse {
			return "", ErrNAT
		}
		view, ok := cache[step]
		if !ok {
			if err := budget.take(ctx, fw.DeclarationSize()); err != nil {
				return "", err
			}
			n, err := transform(fw, step)
			if err != nil {
				return "", err
			}
			if !n.known || n.disabled || n.inverseOf != nil {
				return "", ErrNAT
			}
			definition, err := migrationDefinition(n)
			if err != nil {
				return "", err
			}
			view = migrationStepView{transform: n, definition: definition}
			cache[step] = view
		}
		signature.Steps = append(signature.Steps, view.definition)
		// Mapping and allocation inspect each input region against declarations.
		// Charge their Cartesian work before apply allocates intermediate traffic.
		count := fw.DeclarationSize()
		if count != 0 && translated.RegionCount() > budget.remaining/count {
			return "", ErrBudget
		}
		if err := budget.take(ctx, count*translated.RegionCount()); err != nil {
			return "", err
		}
		var exact, possible bool
		var err error
		translated, exact, possible, err = view.transform.apply(translated, budget.limits.MaxRegions)
		if err != nil {
			return "", err
		}
		signature.Exact = signature.Exact && exact
		signature.PossibleAllocation = signature.PossibleAllocation || possible
	}
	if signature.Exact != r.Exact || signature.PossibleAllocation != r.PossibleAllocation {
		return "", ErrNotEquivalent
	}
	if same, err := budget.equal(ctx, translated, r.Translated); err != nil {
		return "", err
	} else if !same {
		return "", ErrNotEquivalent
	}
	encoded, err := json.Marshal(signature)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func migrationDefinition(n natTransform) (migrationNATStep, error) {
	definition := migrationNATStep{Source: append([]fm.Mapping(nil), n.source...), Destination: append([]fm.Mapping(nil), n.destination...), SourcePorts: append([]fm.PortMapping(nil), n.sourcePorts...), DestinationPorts: append([]fm.PortMapping(nil), n.destinationPorts...)}
	for _, mappings := range [][]fm.Mapping{definition.Source, definition.Destination} {
		slices.SortFunc(mappings, func(a, b fm.Mapping) int {
			if c := compareMigrationRange(a.Original, b.Original); c != 0 {
				return c
			}
			if c := compareMigrationRange(a.Translated, b.Translated); c != 0 {
				return c
			}
			return cmp.Compare(a.Mode, b.Mode)
		})
	}
	for _, mappings := range [][]fm.PortMapping{definition.SourcePorts, definition.DestinationPorts} {
		slices.SortFunc(mappings, func(a, b fm.PortMapping) int {
			for _, pair := range [][2]uint16{{a.Original.Low, b.Original.Low}, {a.Original.High, b.Original.High}, {a.Translated.Low, b.Translated.Low}, {a.Translated.High, b.Translated.High}} {
				if c := cmp.Compare(pair[0], pair[1]); c != 0 {
					return c
				}
			}
			return cmp.Compare(a.Mode, b.Mode)
		})
	}
	if n.dynamic == nil {
		return definition, nil
	}
	r := n.dynamic.Record()
	switch r.SourceMode {
	case fm.NoTranslation, fm.DynamicIP, fm.DynamicIPPort, fm.InterfaceIP:
	default:
		return migrationNATStep{}, ErrNAT
	}
	if r.DestinationMode != fm.NoTranslation && r.DestinationMode != fm.StaticIP {
		return migrationNATStep{}, ErrNAT
	}
	allocation := &migrationAllocation{SourceMode: r.SourceMode, DestinationMode: r.DestinationMode}
	var err error
	allocation.SourcePool, err = resolvedMigrationPool(n.dynamic.SourcePool())
	if err != nil {
		return migrationNATStep{}, err
	}
	if allocation.SourcePool != nil {
		if r.SourceMode == fm.DynamicIPPort || r.SourceMode == fm.InterfaceIP {
			if allocation.SourcePool.Ports == (flow.Interval{}) {
				allocation.SourcePool.Ports = flow.Interval{High: 65535}
			}
		} else {
			// Address-only allocation preserves the original source port;
			// a stored pool port field does not change that relation.
			allocation.SourcePool.Ports = flow.Interval{}
		}
	}
	allocation.DestinationPool, err = resolvedMigrationPool(n.dynamic.DestinationPool())
	if err != nil {
		return migrationNATStep{}, err
	}
	if allocation.DestinationPool != nil {
		allocation.DestinationPool.Ports = flow.Interval{}
	}
	if r.SourceMode == fm.InterfaceIP {
		if n.dynamic.Interface() == nil || n.dynamic.Interface().Disabled() || n.dynamic.Interface().HasUnsupported() {
			return migrationNATStep{}, ErrNAT
		}
		if r.InterfaceAddress.IsValid() {
			allocation.InterfaceAddresses = []netip.Addr{r.InterfaceAddress}
		} else {
			allocation.InterfaceAddresses = migrationInterfaceAddresses(n.dynamic.Interface())
		}
		if len(allocation.InterfaceAddresses) == 0 {
			return migrationNATStep{}, ErrNAT
		}
	}
	definition.Allocation = allocation
	return definition, nil
}

func compareMigrationRange(a, b flow.AddressRange) int {
	if c := a.First.Compare(b.First); c != 0 {
		return c
	}
	return a.Last.Compare(b.Last)
}

func migrationInterfaceAddresses(iface *fm.Interface) []netip.Addr {
	var addresses []netip.Addr
	for _, prefix := range iface.Record().Addresses {
		addresses = append(addresses, prefix.Addr())
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return slices.Compact(addresses)
}

func resolvedMigrationPool(pool *fm.NATPool) (*migrationPool, error) {
	if pool == nil {
		return nil, nil
	}
	if pool.HasUnsupported() {
		return nil, ErrNAT
	}
	r := pool.Record()
	set, err := flow.NewAddressSet(r.Ranges...)
	if err != nil {
		return nil, err
	}
	out := &migrationPool{Ranges: set.Ranges(), Ports: r.Ports}
	if iface := pool.Interface(); iface != nil {
		if iface.Disabled() || iface.HasUnsupported() {
			return nil, ErrNAT
		}
		out.HasInterface, out.InterfaceAddresses = true, migrationInterfaceAddresses(iface)
	}
	return out, nil
}
