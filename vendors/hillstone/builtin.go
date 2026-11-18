package hillstone

import (
	_ "embed"
	"net/netip"

	"github.com/gatework/firemon"
)

// predefinedServices is the default StoneOS 5.5 service book. It holds the
// predefined names whose ports are protocol standards (IANA) or confirmed
// on devices (HTTP-EXT: tcp/80 and tcp/443); names whose ports are not
// known are left out so rules using them stay undecidable until
// Options.Services supplies the book observed on the device.
//
//go:embed predefined_services.json
var predefinedServices []byte

// predefinedApps maps application names to their default ports.
//
//go:embed predefined_apps.json
var predefinedApps []byte

// DefaultApplications returns the embedded application default-port book.
func DefaultApplications() firemon.ServiceBook {
	book, err := firemon.ParseServiceBook(predefinedApps)
	if err != nil {
		panic("hillstone: embedded application book: " + err.Error()) // covered by tests
	}
	return book
}

// DefaultServices returns the embedded default service book.
func DefaultServices() firemon.ServiceBook {
	book, err := firemon.ParseServiceBook(predefinedServices)
	if err != nil {
		panic("hillstone: embedded service book: " + err.Error()) // covered by tests
	}
	return book
}

// builtinAddresses returns the StoneOS predefined address objects that the
// configuration references without declaring.
func builtinAddresses(declared *catalog[addressDraft]) []firemon.Address {
	all := []firemon.Address{
		{Name: anyName, Predefined: true, Entries: []firemon.AddressEntry{
			firemon.PrefixEntry(netip.MustParsePrefix("0.0.0.0/0")), firemon.PrefixEntry(netip.MustParsePrefix("::/0")),
		}},
		{Name: "IPv6-any", Predefined: true, Entries: []firemon.AddressEntry{firemon.PrefixEntry(netip.MustParsePrefix("::/0"))}},
	}
	var out []firemon.Address
	for _, a := range all {
		if !declared.has(a.Name) {
			out = append(out, a)
		}
	}
	return out
}
