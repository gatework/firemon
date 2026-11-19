package intake

import (
	"errors"
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// Errors reported when a field yields nothing usable.
var (
	ErrNoSource      = errors.New("intake: no usable source address")
	ErrNoDestination = errors.New("intake: no usable destination address or domain")
	ErrNoService     = errors.New("intake: no usable service or application")
	// ErrInvalidItem reports an item that could not be read: a request is
	// answered as written or not at all, never for part of it.
	ErrInvalidItem = errors.New("intake: an item cannot be read")
)

// Options tells Parse how to read names. The zero value reads only
// addresses, ports and protocols.
type Options struct {
	// Services resolves service names such as "https" or "ssh".
	Services firemon.ServiceBook
	// IsApplication reports whether a name is an application; such names
	// are matched against application-based rules.
	IsApplication func(name string) bool
}

// Request is the parsed operator input.
type Request struct {
	Src        traffic.AddressSet
	Dst        traffic.AddressSet
	DstDomains []string
	Service    traffic.ServiceSet
	// Applications holds application names; with no port service given,
	// Service is any and the applications decide.
	Applications []string
	Notes        []Note
}

// Parse reads the source, destination and service fields. It fails only
// when a field yields nothing usable; every skipped item is in the notes
// of the returned request, which is filled in even on error.
func Parse(src, dst, service string, opts Options) (Request, error) {
	s := parseAddresses(src, FieldSource)
	d := parseAddresses(dst, FieldDestination)
	v := parseServices(service, opts)
	req := Request{
		Src: s.set, Dst: d.set, DstDomains: slices.Compact(slices.Sorted(slices.Values(d.domains))),
		Service: v.set, Applications: slices.Compact(slices.Sorted(slices.Values(v.apps))),
		Notes: slices.Concat(s.notes, d.notes, v.notes),
	}
	if req.Service.IsEmpty() && len(req.Applications) > 0 {
		req.Service = traffic.AnyService()
	}
	var errs []error
	if slices.ContainsFunc(req.Notes, func(n Note) bool { return n.Code == CodeInvalid || n.Code == CodeUnknownApplication }) {
		errs = append(errs, ErrInvalidItem)
	}
	if req.Src.IsEmpty() {
		errs = append(errs, ErrNoSource)
	}
	if req.Dst.IsEmpty() && len(req.DstDomains) == 0 {
		errs = append(errs, ErrNoDestination)
	}
	if req.Service.IsEmpty() {
		errs = append(errs, ErrNoService)
	}
	return req, errors.Join(errs...)
}
