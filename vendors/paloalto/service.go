package paloalto

import (
	"context"

	"github.com/gatework/firemon/flow"
)

// serviceDraft keeps protocol and port fields together across native rows.
type serviceDraft struct {
	protocol string
	src, dst []flow.Interval
}

func (d *serviceDraft) field(ctx context.Context, fields []string) (bool, error) {
	if len(fields) != 3 || (fields[0] != "tcp" && fields[0] != "udp") {
		return false, nil
	}
	if d.protocol != "" && d.protocol != fields[0] {
		return false, nil
	}
	d.protocol = fields[0]
	switch fields[1] {
	case "override":
		// Inherit the application's timeout without altering the selector.
		return fields[2] == "no", nil
	case "port", "source-port":
		values, err := ports(ctx, fields[2])
		if err != nil {
			return false, ctx.Err()
		}
		if fields[1] == "port" {
			d.dst = values
		} else {
			d.src = values
		}
		return true, nil
	}
	return false, nil
}
