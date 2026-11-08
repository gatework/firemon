package hillstone

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/jsonio"
)

// ReadServices reads the normalized service-book format used by algosec-rb.
// ICMP uses destination_port for type and source_port for code. Definitions
// belong to the supplied capture; this function does not infer model applicability.
func ReadServices(ctx context.Context, reader io.Reader, limit int) ([]fm.ServiceRecord, error) {
	if reader == nil {
		return nil, config.ErrInvalid
	}
	raw, err := jsonio.Read(ctx, reader, config.DefaultMaxBytes)
	if err != nil {
		return nil, err
	}
	var document struct {
		Services map[string][]serviceTerm `json:"predefined_services"`
	}
	if err := jsonio.Decode(raw, &document); err != nil || len(document.Services) == 0 {
		return nil, fmt.Errorf("%w: invalid service book", config.ErrSource)
	}
	if limit <= 0 {
		limit = config.DefaultMaxServiceTerms
	}
	names := make([]string, 0, len(document.Services))
	for name := range document.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	var records []fm.ServiceRecord
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rows := document.Services[name]
		if strings.TrimSpace(name) == "" || strings.HasSuffix(name, "~") || len(rows) == 0 || len(rows) > limit {
			return nil, fmt.Errorf("%w: invalid or oversized service book", config.ErrSource)
		}
		limit -= len(rows)
		record := fm.ServiceRecord{Object: fm.Object{ID: fm.ID(name), Name: name}}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			term, ok := row.value()
			if !ok {
				return nil, fmt.Errorf("%w: invalid service book term", config.ErrSource)
			}
			record.Terms = append(record.Terms, term)
			if row.Timeout != nil {
				record.Unsupported = append(record.Unsupported, "predefined session timeout")
			}
		}
		records = append(records, record)
	}
	return records, ctx.Err()
}

type serviceTerm struct {
	Protocol    string  `json:"protocol"`
	Source      *string `json:"source_port"`
	Destination *string `json:"destination_port"`
	Timeout     *string `json:"timeout"`
	Term        *string `json:"term"`
	UUID        *string `json:"uuid"`
}

func (s serviceTerm) value() (fm.ServiceTerm, bool) {
	full := flow.Interval{Low: 0, High: 65535}
	octet := flow.Interval{Low: 0, High: 255}
	term := fm.ServiceTerm{SourcePort: full, DestinationPort: full, ICMPType: octet, ICMPCode: octet}
	var n uint64
	protocol := strings.ToLower(s.Protocol)
	switch protocol {
	case "any":
		term.Protocol = octet
	case "tcp":
		n = 6
	case "udp":
		n = 17
	case "sctp":
		n = 132
	case "icmp":
		n = 1
	default:
		var err error
		n, err = strconv.ParseUint(s.Protocol, 10, 8)
		if err != nil {
			return term, false
		}
	}
	if protocol != "any" {
		term.Protocol = flow.Interval{Low: uint16(n), High: uint16(n)}
	}
	src, ok := bookPort(s.Source)
	dst, ok2 := bookPort(s.Destination)
	if !ok || !ok2 {
		return term, false
	}
	ports := n == 6 || n == 17 || n == 132
	icmp := n == 1 || n == 58
	if !ports && !icmp && (src != full || dst != full) {
		return term, false
	}
	if icmp {
		if src == full {
			src = octet
		}
		if dst == full {
			dst = octet
		}
		if src.High > 255 || dst.High > 255 {
			return term, false
		}
		term.ICMPCode, term.ICMPType = src, dst
	} else {
		term.SourcePort, term.DestinationPort = src, dst
	}
	return term, true
}

func bookPort(value *string) (flow.Interval, bool) {
	if value == nil {
		return flow.Interval{Low: 0, High: 65535}, true
	}
	fields := strings.Split(*value, "-")
	return port(fields)
}
