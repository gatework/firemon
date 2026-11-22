package paloalto

import (
	_ "embed"

	"github.com/gatework/firemon"
)

// predefinedServices is the PAN-OS default service book.
//
//go:embed predefined_services.json
var predefinedServices []byte

// predefinedApps maps application names to their default ports, as
// Applipedia lists them. Identification by standard ports (ADR 0017) takes
// each port to the applications with the fewest ports holding it, so an
// application with broad defaults (teamviewer on tcp/80,443,5938) claims
// only its own port (tcp/5938). Applications whose ports depend on the
// installation (sap) are absent: rules naming them stay possible matches
// on unclaimed ports.
//
//go:embed predefined_apps.json
var predefinedApps []byte

// DefaultApplications returns the embedded application default-port book.
func DefaultApplications() firemon.ServiceBook {
	book, err := firemon.ParseServiceBook(predefinedApps)
	if err != nil {
		panic("paloalto: embedded application book: " + err.Error()) // covered by tests
	}
	return book
}

// DefaultServices returns the embedded default service book.
func DefaultServices() firemon.ServiceBook {
	book, err := firemon.ParseServiceBook(predefinedServices)
	if err != nil {
		panic("paloalto: embedded service book: " + err.Error()) // covered by tests
	}
	return book
}
