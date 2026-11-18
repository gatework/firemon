package paloalto

import (
	_ "embed"

	"github.com/gatework/firemon"
)

// predefinedServices is the PAN-OS default service book.
//
//go:embed predefined_services.json
var predefinedServices []byte

// DefaultServices returns the embedded default service book.
func DefaultServices() firemon.ServiceBook {
	book, err := firemon.ParseServiceBook(predefinedServices)
	if err != nil {
		panic("paloalto: embedded service book: " + err.Error()) // covered by tests
	}
	return book
}
