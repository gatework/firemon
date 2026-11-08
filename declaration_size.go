package firemon

// declarationCounter saturates so a hostile or unusually large construction
// cannot wrap a positive preflight estimate into an affordable negative count.
type declarationCounter int

func (c *declarationCounter) add(counts ...int) {
	const maximum = int(^uint(0) >> 1)
	for _, count := range counts {
		if count < 0 || count > maximum-int(*c) {
			*c = declarationCounter(maximum)
			return
		}
		*c += declarationCounter(count)
	}
}

func (c *declarationCounter) object(o Object) { c.add(1, len(o.Spans), len(o.Unsupported)) }
func (c *declarationCounter) match(m Match) {
	c.add(
		len(m.Sources),
		len(m.Destinations),
		len(m.Services),
		len(m.FromZones),
		len(m.ToZones),
		len(m.Applications),
		len(m.Users),
		len(m.Unsupported),
	)
}

func declarationSize(d Data) int {
	var count declarationCounter
	count.add(len(d.Evidence), len(d.Diagnostics))
	for _, r := range d.Zones {
		count.object(r.Object)
		count.add(len(r.Networks))
	}
	for _, r := range d.Interfaces {
		count.object(r.Object)
		count.add(len(r.Addresses))
	}
	for _, r := range d.Routes {
		count.object(r.Object)
		count.add(len(r.PolicyMatch))
	}
	for _, r := range d.Addresses {
		count.object(r.Object)
		count.add(len(r.Ranges))
	}
	for _, r := range d.AddressGroups {
		count.object(r.Object)
		count.add(len(r.Members))
	}
	for _, r := range d.Services {
		count.object(r.Object)
		count.add(len(r.Terms))
	}
	for _, r := range d.ServiceGroups {
		count.object(r.Object)
		count.add(len(r.Members))
	}
	for _, r := range d.Schedules {
		count.object(r.Object)
		count.add(len(r.Windows), len(r.Weekly))
		for _, period := range r.Weekly {
			count.add(len(period.Windows))
		}
	}
	for _, r := range d.Rules {
		count.object(r.Object)
		count.match(r.Match)
	}
	for _, r := range d.RuleBindings {
		count.object(r.Object)
	}
	for _, r := range d.StaticNATs {
		count.object(r.Object)
		count.match(r.Match)
		count.add(
			len(r.Source),
			len(r.Destination),
			len(r.SourcePorts),
			len(r.DestinationPorts),
		)
	}
	for _, r := range d.DynamicNATs {
		count.object(r.Object)
		count.match(r.Match)
		count.add(len(r.Destination), len(r.SourcePorts), len(r.DestinationPorts))
	}
	for _, r := range d.NATPools {
		count.object(r.Object)
		count.add(len(r.Ranges))
	}
	return int(count)
}
