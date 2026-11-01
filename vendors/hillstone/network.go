package hillstone

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) zones(ctx context.Context, s *config.Builder) error {
	definitions, err := p.definitions(ctx, "zone")
	if err != nil {
		return err
	}
	for _, d := range definitions {
		if err := p.parseZone(ctx, s, d); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) parseZone(ctx context.Context, s *config.Builder, d definition) error {
	r := fm.ZoneRecord{Object: d.object()}
	tx := s.Begin()
	defer tx.Rollback()
	if err := d.walk(ctx, tx, &r.Object, func(w []string) bool {
		if len(w) == 2 && w[0] == "vrouter" {
			r.Scope = w[1]
			return true
		}
		return ancillary(w)
	}); err != nil {
		return err
	}
	tx.Emit(fm.Data{Zones: []fm.ZoneRecord{r}})
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.zoneVRF[r.ID] = r.Scope
	return nil
}

func prefix(words []string) (netip.Prefix, error) {
	if len(words) == 0 {
		return netip.Prefix{}, fmt.Errorf("missing prefix")
	}
	if strings.Contains(words[0], "/") {
		return netip.ParsePrefix(words[0])
	}
	a, err := netip.ParseAddr(words[0])
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := a.BitLen()
	if len(words) > 1 {
		mask, err := netip.ParseAddr(words[1])
		if err != nil || !mask.Is4() || !a.Is4() {
			return netip.Prefix{}, fmt.Errorf("invalid netmask")
		}
		b := mask.As4()
		ones, total := net.IPMask(b[:]).Size()
		if total != 32 {
			return netip.Prefix{}, fmt.Errorf("noncontiguous mask")
		}
		bits = ones
	}
	return netip.PrefixFrom(a, bits), nil
}
func (p *parser) interfaces(ctx context.Context, s *config.Builder) error {
	definitions, err := p.definitions(ctx, "interface")
	if err != nil {
		return err
	}
	for _, d := range definitions {
		if err := p.parseInterface(ctx, s, d); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) parseInterface(ctx context.Context, s *config.Builder, d definition) error {
	r := fm.InterfaceRecord{Object: d.object()}
	tx := s.Begin()
	defer tx.Rollback()
	if err := d.walk(ctx, tx, &r.Object, func(w []string) bool {
		if len(w) == 2 && w[0] == "zone" {
			r.Zone = fm.ID(w[1])
			return true
		}
		if len(w) >= 3 && (w[0] == "ip" || w[0] == "ipv6") && w[1] == "address" {
			fields := w[2:]
			if fields[len(fields)-1] == "secondary" {
				fields = fields[:len(fields)-1]
			}
			if len(fields) <= 2 {
				if v, err := prefix(fields); err == nil {
					r.Addresses = append(r.Addresses, v)
					return true
				}
			}
		}
		if len(w) == 1 && w[0] == "shutdown" {
			r.Disabled = true
			return true
		}
		return ancillary(w) || slices.Equal(w, []string{"ipv6", "enable"})
	}); err != nil {
		return err
	}
	if vrf := p.zoneVRF[r.Zone]; vrf != "" {
		r.Scope = vrf
	}
	delta := fm.Data{Interfaces: []fm.InterfaceRecord{r}}
	for i, prefix := range r.Addresses {
		if err := ctx.Err(); err != nil {
			return err
		}
		delta.Routes = append(delta.Routes, fm.RouteRecord{
			Object:      fm.Object{ID: fm.ID(fmt.Sprintf("connected:%s:%d", r.ID, i)), Scope: r.Scope},
			Destination: prefix.Masked(), Interface: r.ID, Direct: true,
		})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx.Emit(delta)
	return s.Commit(tx)
}

func (p *parser) routes(_ context.Context, s *config.Builder) error {
	for _, row := range p.lines {
		w := row.line.Words
		if len(w) < 4 || w[0] != "ip" || w[1] != "route" {
			continue
		}
		dest, err := prefix(w[2:3])
		if err != nil {
			continue
		}
		r := fm.RouteRecord{Object: fm.Object{Scope: row.scope, Spans: []fm.Span{row.line.Span}}, Destination: dest.Masked()}
		rest := w[3:]
		if addr, err := netip.ParseAddr(rest[0]); err == nil {
			r.NextHop = addr
			rest = rest[1:]
		} else {
			r.Interface = fm.ID(rest[0])
			rest = rest[1:]
			if len(rest) > 0 {
				if addr, err := netip.ParseAddr(rest[0]); err == nil {
					r.NextHop = addr
					rest = rest[1:]
				}
			}
		}
		if len(rest) > 0 {
			continue
		}
		tx := s.Begin()
		tx.Parse(row.line.Lines()...)
		r.ID = config.RouteID(r)
		tx.Emit(fm.Data{Routes: []fm.RouteRecord{r}})
		if err := s.Commit(tx); err != nil {
			return err
		}
	}
	return nil
}
