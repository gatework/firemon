package firemon

import "slices"

func sameMatch(a, b Match) bool {
	return a.AnySource == b.AnySource && a.AnyDestination == b.AnyDestination && a.AnyService == b.AnyService &&
		a.AnyFromZone == b.AnyFromZone && a.AnyToZone == b.AnyToZone && a.Schedule == b.Schedule && a.ZoneRelation == b.ZoneRelation &&
		slices.Equal(a.Sources, b.Sources) && slices.Equal(a.Destinations, b.Destinations) && slices.Equal(a.Services, b.Services) &&
		slices.Equal(a.FromZones, b.FromZones) && slices.Equal(a.ToZones, b.ToZones) && slices.Equal(a.Applications, b.Applications) &&
		slices.Equal(a.Users, b.Users) && slices.Equal(a.Unsupported, b.Unsupported)
}
