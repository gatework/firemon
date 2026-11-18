package traffic_test

import (
	"net/netip"
	"testing"

	"github.com/gatework/firemon/traffic"
)

// The point model enumerates a small universe exhaustively: 8 sources,
// 8 destinations, 2 protocols, 2 source ports and 4 destination ports.
const (
	modelAddrs = 8
	modelSrcP  = 2
	modelDstP  = 4
	modelSize  = modelAddrs * modelAddrs * 2 * modelSrcP * modelDstP
)

type point struct {
	src, dst   netip.Addr
	proto      traffic.Protocol
	sport, dpt uint16
}

func modelPoints() []point {
	var out []point
	for s := range modelAddrs {
		for d := range modelAddrs {
			for _, p := range []traffic.Protocol{traffic.ProtocolTCP, traffic.ProtocolUDP} {
				for sp := range modelSrcP {
					for dp := range modelDstP {
						out = append(out, point{
							src: netip.AddrFrom4([4]byte{10, 0, 0, byte(s)}), dst: netip.AddrFrom4([4]byte{10, 0, 1, byte(d)}),
							proto: p, sport: uint16(sp), dpt: uint16(dp),
						})
					}
				}
			}
		}
	}
	return out
}

func (p point) in(s traffic.Space) bool {
	pkt := traffic.NewService(p.proto, traffic.Port(p.sport), traffic.Port(p.dpt))
	return s.Src.Contains(p.src) && s.Dst.Contains(p.dst) && s.Service.ContainsSet(pkt)
}

func regionHas(r traffic.Region, p point) bool {
	hits := 0
	for _, s := range r.Spaces() {
		if p.in(s) {
			hits++
		}
	}
	return hits > 0
}

// spaceFrom decodes six bytes into a space inside the model universe.
func spaceFrom(b []byte) traffic.Space {
	addr := func(third byte, lo, hi byte) traffic.AddressSet {
		lo, hi = lo%modelAddrs, hi%modelAddrs
		return traffic.AddressRange(netip.AddrFrom4([4]byte{10, 0, third, min(lo, hi)}), netip.AddrFrom4([4]byte{10, 0, third, max(lo, hi)}))
	}
	proto := traffic.ProtocolTCP
	if b[4]&1 == 1 {
		proto = traffic.ProtocolUDP
	}
	svc := traffic.NewService(proto, traffic.Port(uint16(b[4]>>1)%modelSrcP), traffic.PortRange{Low: 0, High: uint16(b[5]) % modelDstP})
	if b[4]&0x80 != 0 {
		svc = traffic.AnyService()
	}
	return traffic.Space{Src: addr(0, b[0], b[1]), Dst: addr(1, b[2], b[3]), Service: svc}
}

func checkModel(t *testing.T, r traffic.Region, model *[modelSize]bool, points []point) {
	t.Helper()
	for i, p := range points {
		if got := regionHas(r, p); got != model[i] {
			t.Fatalf("point %+v: region has %v, model has %v (region %s)", p, got, model[i], r)
		}
	}
	spaces := r.Spaces()
	for i := range spaces {
		for j := i + 1; j < len(spaces); j++ {
			if spaces[i].Overlaps(spaces[j]) {
				t.Fatalf("spaces %d and %d overlap: %s / %s", i, j, spaces[i], spaces[j])
			}
		}
	}
}

func FuzzRegion(f *testing.F) {
	f.Add([]byte{0, 7, 0, 7, 0, 3, 1, 1, 2, 2, 3, 3, 1, 0})
	f.Add([]byte{0, 3, 2, 5, 0x81, 1, 2, 6, 0, 7, 0, 3, 0, 1})
	points := modelPoints()
	f.Fuzz(func(t *testing.T, ops []byte) {
		var r traffic.Region
		var model [modelSize]bool
		for len(ops) >= 7 {
			s, add := spaceFrom(ops[:6]), ops[6]&1 == 0
			ops = ops[7:]
			if add {
				r = r.Add(s)
			} else {
				r = r.Subtract(s)
			}
			for i, p := range points {
				if p.in(s) {
					model[i] = add
				}
			}
		}
		checkModel(t, r, &model, points)
	})
}

func TestRegion_SubtractToEmpty(t *testing.T) {
	t.Parallel()
	all := traffic.AnySpace()
	r := traffic.NewRegion(all)
	web := traffic.Space{Src: traffic.AnyAddress(), Dst: traffic.AnyAddress(), Service: traffic.PortService(traffic.ProtocolTCP, traffic.Port(80))}
	r = r.Subtract(web)
	if r.ContainsSpace(web) || !r.ContainsSpace(traffic.Space{Src: traffic.AnyAddress(), Dst: traffic.AnyAddress(), Service: traffic.ProtocolService(traffic.ProtocolUDP)}) {
		t.Fatalf("unexpected region %s", r)
	}
	if r = r.Subtract(all); !r.IsEmpty() {
		t.Fatalf("want empty, got %s", r)
	}
}
