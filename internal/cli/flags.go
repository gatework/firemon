package cli

import (
	"errors"
	"time"

	"github.com/spf13/cobra"

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
	service  traffic.ServiceSet
	at       time.Time
}

func (t *trafficFlags) parse() (parsed, error) {
	var p parsed
	var err error
	if t.src == "" || t.dst == "" || t.service == "" {
		return p, &usageError{errors.New("--src, --dst and --service are required")}
	}
	if p.src, err = traffic.ParseAddressSet(t.src); err != nil {
		return p, &usageError{err}
	}
	if p.dst, err = traffic.ParseAddressSet(t.dst); err != nil {
		return p, &usageError{err}
	}
	if p.service, err = traffic.ParseServiceSet(t.service); err != nil {
		return p, &usageError{err}
	}
	if t.at != "" {
		if p.at, err = time.Parse(time.RFC3339, t.at); err != nil {
			return p, &usageError{err}
		}
	}
	return p, nil
}
