package audit_test

import (
	"fmt"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/audit"
)

func ExampleRun() {
	cfg := &firemon.Config{
		Vendor: firemon.VendorPaloAlto,
		Rules: []firemon.SecurityRule{
			{ID: "broad", Action: firemon.ActionPermit, Source: inline("10.0.0.0/8")},
			{ID: "narrow", Action: firemon.ActionPermit, Source: inline("10.1.0.0/16")},
		},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, f := range audit.Run(fw, audit.Options{Now: func() time.Time { return now }}).Findings {
		fmt.Println(f.Kind, f.Rule, f.By)
	}
	// Output: redundant narrow [broad]
}
