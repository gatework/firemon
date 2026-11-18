package paloalto

import (
	_ "embed"

	"github.com/gatework/firemon"
)

// predefinedServices is the PAN-OS default service book.
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
