package cli

import (
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/intake"
	"github.com/gatework/firemon/traffic"
)

// trafficFlags describe the traffic a query or intent is about.
type trafficFlags struct {
	src, dst, service string
	fromZone, toZone  string
	vr                string
	at                string
}

func (t *trafficFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&t.src, "src", "", "source addresses: 10.0.0.1, 10.0.0.0/24, 10.0.0.1-10.0.0.9, any (comma separated)")
	f.StringVar(&t.dst, "dst", "", "destination addresses")
	f.StringVar(&t.service, "service", "", "services: tcp/443, udp/53, tcp/8000-8010, icmp, any (comma separated)")
	f.StringVar(&t.fromZone, "from-zone", "", "source zone (default: from routing)")
	f.StringVar(&t.toZone, "to-zone", "", "destination zone (default: from routing)")
	f.StringVar(&t.vr, "virtual-router", "", "routing context (default: the vendor default)")
	f.StringVar(&t.at, "at", "", "evaluate schedules at this RFC 3339 instant (default: now)")
}

// parsed is the validated traffic.
type parsed struct {
	src, dst traffic.AddressSet
	domains  []string
	apps     []string
	service  traffic.ServiceSet
	at       time.Time
}

// parse reads the traffic flags tolerantly (see intake); service names are
// read with the given book.
func (t *trafficFlags) parse(book firemon.ServiceBook) (parsed, error) {
	var p parsed
	if t.src == "" || t.dst == "" || t.service == "" {
		return p, &usageError{errors.New("--src, --dst and --service are required")}
	}
	in, err := intake.Parse(t.src, t.dst, t.service, intake.Options{Services: book})
	if err != nil {
		return p, &usageError{err}
	}
	p.src, p.dst, p.domains, p.apps, p.service = in.Src, in.Dst, in.DstDomains, in.Applications, in.Service
	if t.at != "" {
		if p.at, err = time.Parse(time.RFC3339, t.at); err != nil {
			return p, &usageError{err}
		}
	}
	return p, nil
}
