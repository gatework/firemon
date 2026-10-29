package flow

import (
	"errors"
	"slices"
)

var ErrBudget = errors.New("traffic region budget exceeded")
var ErrRegion = errors.New("invalid traffic region")

type Interval struct{ Low, High uint16 }

func (i Interval) valid(max uint16) bool { return i.Low <= i.High && i.High <= max }
func (i Interval) intersection(j Interval) (Interval, bool) {
	x := Interval{max(i.Low, j.Low), min(i.High, j.High)}
	return x, x.Low <= x.High
}

// TrafficRegion preserves the association between source, destination and service dimensions.
// A wildcard is the full interval; protocol zero remains protocol zero.
type TrafficRegion struct {
	Source, Destination                                       AddressRange
	Protocol, SourcePort, DestinationPort, ICMPType, ICMPCode Interval
}

func (b TrafficRegion) Valid() bool {
	return b.Source.Valid() && b.Destination.Valid() && b.Source.First.BitLen() == b.Destination.First.BitLen() && b.Protocol.valid(255) && b.SourcePort.valid(65535) && b.DestinationPort.valid(65535) && b.ICMPType.valid(255) && b.ICMPCode.valid(255)
}
func (b TrafficRegion) Intersection(c TrafficRegion) (TrafficRegion, bool) {
	var r TrafficRegion
	var ok bool
	if r.Source, ok = b.Source.Intersection(c.Source); !ok {
		return TrafficRegion{}, false
	}
	if r.Destination, ok = b.Destination.Intersection(c.Destination); !ok {
		return TrafficRegion{}, false
	}
	bd, cd, rd := b.dimensions(), c.dimensions(), r.dimensions()
	for i := range bd {
		if *rd[i], ok = bd[i].intersection(*cd[i]); !ok {
			return TrafficRegion{}, false
		}
	}
	return r, true
}
func (b *TrafficRegion) dimensions() []*Interval {
	return []*Interval{&b.Protocol, &b.SourcePort, &b.DestinationPort, &b.ICMPType, &b.ICMPCode}
}

// subtract carves disjoint slabs around the intersection, never cross-products of projected axes.
func (b TrafficRegion) subtract(c TrafficRegion, pieces *[14]TrafficRegion) int {
	x, ok := b.Intersection(c)
	if !ok {
		pieces[0] = b
		return 1
	}
	count := 0
	emit := func(piece TrafficRegion) { pieces[count] = piece; count++ }
	core := b
	if core.Source.First.Compare(x.Source.First) < 0 {
		piece := core
		piece.Source.Last = x.Source.First.Prev()
		emit(piece)
		core.Source.First = x.Source.First
	}
	if x.Source.Last.Compare(core.Source.Last) < 0 {
		piece := core
		piece.Source.First = x.Source.Last.Next()
		emit(piece)
		core.Source.Last = x.Source.Last
	}
	if core.Destination.First.Compare(x.Destination.First) < 0 {
		piece := core
		piece.Destination.Last = x.Destination.First.Prev()
		emit(piece)
		core.Destination.First = x.Destination.First
	}
	if x.Destination.Last.Compare(core.Destination.Last) < 0 {
		piece := core
		piece.Destination.First = x.Destination.Last.Next()
		emit(piece)
		core.Destination.Last = x.Destination.Last
	}
	for i, target := range x.dimensions() {
		axis := core.dimensions()[i]
		if axis.Low < target.Low {
			piece := core
			piece.dimensions()[i].High = target.Low - 1
			emit(piece)
			axis.Low = target.Low
		}
		if target.High < axis.High {
			piece := core
			piece.dimensions()[i].Low = target.High + 1
			emit(piece)
			axis.High = target.High
		}
	}
	return count
}

// Traffic is an immutable disjoint union. Operations return no partial result on budget failure.
type Traffic struct{ boxes []TrafficRegion }

func NewTraffic(limit int, boxes ...TrafficRegion) (Traffic, error) {
	if limit < 1 || len(boxes) > limit {
		return Traffic{}, ErrBudget
	}
	var out Traffic
	for _, b := range boxes {
		if !b.Valid() {
			return Traffic{}, ErrRegion
		}
		pieces, err := (Traffic{boxes: []TrafficRegion{b}}).Difference(out, limit)
		if err != nil {
			return Traffic{}, err
		}
		if len(out.boxes)+len(pieces.boxes) > limit {
			return Traffic{}, ErrBudget
		}
		out.boxes = append(out.boxes, pieces.boxes...)
	}
	return out, nil
}

// RegionCount returns the disjoint region count without copying traffic.
func (s Traffic) RegionCount() int { return len(s.boxes) }

func (s Traffic) Regions() []TrafficRegion { return slices.Clone(s.boxes) }
func (s Traffic) Empty() bool              { return len(s.boxes) == 0 }
func (s Traffic) Union(t Traffic, limit int) (Traffic, error) {
	// Each operand is already disjoint. Normalize only the added coverage.
	if limit < 1 || len(s.boxes)+len(t.boxes) > limit {
		return Traffic{}, ErrBudget
	}
	out := s.Regions()
	for _, b := range t.boxes {
		// Charge each added declaration's intermediate regions as NewTraffic
		// does. Combining all additions first could change budget failures.
		extra, err := (Traffic{boxes: []TrafficRegion{b}}).Difference(s, limit)
		if err != nil {
			return Traffic{}, err
		}
		if len(out)+len(extra.boxes) > limit {
			return Traffic{}, ErrBudget
		}
		out = append(out, extra.boxes...)
	}
	return Traffic{boxes: out}, nil
}
func (s Traffic) Intersection(t Traffic, limit int) (Traffic, error) {
	if limit < 1 {
		return Traffic{}, ErrBudget
	}
	var out []TrafficRegion
	for _, a := range s.boxes {
		for _, b := range t.boxes {
			if x, ok := a.Intersection(b); ok {
				if len(out) >= limit {
					return Traffic{}, ErrBudget
				}
				out = append(out, x)
			}
		}
	}
	return Traffic{out}, nil
}
func (s Traffic) Difference(t Traffic, limit int) (Traffic, error) {
	if limit < 1 || len(s.boxes) > limit {
		return Traffic{}, ErrBudget
	}
	out := s.Regions()
	var next []TrafficRegion
	// At most two slabs per dimension; the bounded scratch stays on the stack.
	var pieces [14]TrafficRegion
	for _, b := range t.boxes {
		next = next[:0]
		for _, a := range out {
			count := a.subtract(b, &pieces)
			if len(next)+count > limit {
				return Traffic{}, ErrBudget
			}
			next = append(next, pieces[:count]...)
		}
		out, next = next, out
		if len(out) == 0 {
			return Traffic{}, nil
		}
	}
	return Traffic{out}, nil
}
func (s Traffic) Contains(t Traffic, limit int) (bool, error) {
	rest, err := t.Difference(s, limit)
	return err == nil && rest.Empty(), err
}
