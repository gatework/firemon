package firemon

import (
	"encoding/binary"
	"math/bits"
	"net/netip"

	"github.com/gatework/firemon/traffic"
)

// shiftSet maps every address of s, which must lie inside the single range
// of from, to the address at the same offset inside the single range of to.
func shiftSet(s, from, to traffic.AddressSet) traffic.AddressSet {
	fr, tr := from.Ranges(), to.Ranges()
	if len(fr) != 1 || len(tr) != 1 || s.IsEmpty() {
		return traffic.AddressSet{}
	}
	var out traffic.AddressSet
	for _, r := range s.Ranges() {
		lo := shiftAddr(r.From(), fr[0].From(), tr[0].From())
		hi := shiftAddr(r.To(), fr[0].From(), tr[0].From())
		out = out.Union(traffic.AddressRange(lo, hi))
	}
	return out
}

// shiftAddr returns a - base + target in 128-bit arithmetic, keeping the
// family of target.
func shiftAddr(a, base, target netip.Addr) netip.Addr {
	ah, al := split(a)
	bh, bl := split(base)
	th, tl := split(target)
	lo, borrow := bits.Sub64(al, bl, 0)
	hi, _ := bits.Sub64(ah, bh, borrow)
	lo, carry := bits.Add64(lo, tl, 0)
	hi, _ = bits.Add64(hi, th, carry)
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], hi)
	binary.BigEndian.PutUint64(b[8:], lo)
	out := netip.AddrFrom16(b)
	if target.Is4() {
		return out.Unmap()
	}
	return out
}

// sameSize reports whether two single-range sets hold the same number of
// addresses and are of the same family.
func sameSize(a, b traffic.AddressSet) bool {
	ar, br := a.Ranges(), b.Ranges()
	if len(ar) != 1 || len(br) != 1 || ar[0].From().Is4() != br[0].From().Is4() {
		return false
	}
	return shiftAddr(ar[0].To(), ar[0].From(), br[0].From()) == br[0].To()
}

func split(a netip.Addr) (hi, lo uint64) {
	b := a.As16()
	return binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
}
