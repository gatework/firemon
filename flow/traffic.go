package flow

import (
	"errors"
	"slices"
)

var ErrBudget = errors.New("traffic region budget exceeded")
var ErrBox = errors.New("invalid traffic region")

type Interval struct{ Low, High uint16 }

func (i Interval) valid(max uint16) bool { return i.Low <= i.High && i.High <= max }
func (i Interval) intersection(j Interval) (Interval, bool) {
	x := Interval{max(i.Low, j.Low), min(i.High, j.High)}
	return x, x.Low <= x.High
}

// Box preserves the association between source, destination and service dimensions.
// A wildcard is the full interval; protocol zero remains protocol zero.
type Box struct {
	Source, Destination                                       Range
	Protocol, SourcePort, DestinationPort, ICMPType, ICMPCode Interval
}

func (b Box) Valid() bool {
	return b.Source.Valid() && b.Destination.Valid() && b.Source.First.BitLen() == b.Destination.First.BitLen() && b.Protocol.valid(255) && b.SourcePort.valid(65535) && b.DestinationPort.valid(65535) && b.ICMPType.valid(255) && b.ICMPCode.valid(255)
}
func (b Box) Intersection(c Box) (Box, bool) {
	var r Box
	var ok bool
	if r.Source, ok = b.Source.Intersection(c.Source); !ok {
		return Box{}, false
	}
	if r.Destination, ok = b.Destination.Intersection(c.Destination); !ok {
		return Box{}, false
	}
	bd, cd, rd := b.dimensions(), c.dimensions(), r.dimensions()
	for i := range bd {
		if *rd[i], ok = bd[i].intersection(*cd[i]); !ok {
			return Box{}, false
		}
	}
	return r, true
}
func (b *Box) dimensions() []*Interval {
	return []*Interval{&b.Protocol, &b.SourcePort, &b.DestinationPort, &b.ICMPType, &b.ICMPCode}
}

// subtract carves disjoint slabs around the intersection, never cross-products of projected axes.
func (b Box) subtract(c Box) []Box {
	x, ok := b.Intersection(c)
	if !ok {
		return []Box{b}
	}
	var out []Box
	core := b
	if core.Source.First.Compare(x.Source.First) < 0 {
		piece := core
		piece.Source.Last = x.Source.First.Prev()
		out = append(out, piece)
		core.Source.First = x.Source.First
	}
	if x.Source.Last.Compare(core.Source.Last) < 0 {
		piece := core
		piece.Source.First = x.Source.Last.Next()
		out = append(out, piece)
		core.Source.Last = x.Source.Last
	}
	if core.Destination.First.Compare(x.Destination.First) < 0 {
		piece := core
		piece.Destination.Last = x.Destination.First.Prev()
		out = append(out, piece)
		core.Destination.First = x.Destination.First
	}
	if x.Destination.Last.Compare(core.Destination.Last) < 0 {
		piece := core
		piece.Destination.First = x.Destination.Last.Next()
		out = append(out, piece)
		core.Destination.Last = x.Destination.Last
	}
	for i, target := range x.dimensions() {
		axis := core.dimensions()[i]
		if axis.Low < target.Low {
			piece := core
			piece.dimensions()[i].High = target.Low - 1
			out = append(out, piece)
			axis.Low = target.Low
		}
		if target.High < axis.High {
			piece := core
			piece.dimensions()[i].Low = target.High + 1
			out = append(out, piece)
			axis.High = target.High
		}
	}
	return out
}

// Traffic is an immutable disjoint union. Operations return no partial result on budget failure.
type Traffic struct{ boxes []Box }

func NewTraffic(limit int, boxes ...Box) (Traffic, error) {
	if limit < 1 || len(boxes) > limit {
		return Traffic{}, ErrBudget
	}
	var out Traffic
	for _, b := range boxes {
		if !b.Valid() {
			return Traffic{}, ErrBox
		}
		pieces, err := (Traffic{boxes: []Box{b}}).Difference(out, limit)
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
func (s Traffic) Boxes() []Box { return slices.Clone(s.boxes) }
func (s Traffic) Empty() bool  { return len(s.boxes) == 0 }
func (s Traffic) Union(t Traffic, limit int) (Traffic, error) {
	return NewTraffic(limit, append(s.Boxes(), t.boxes...)...)
}
func (s Traffic) Intersection(t Traffic, limit int) (Traffic, error) {
	if limit < 1 {
		return Traffic{}, ErrBudget
	}
	var out []Box
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
	out := s.Boxes()
	for _, b := range t.boxes {
		var next []Box
		for _, a := range out {
			pieces := a.subtract(b)
			if len(next)+len(pieces) > limit {
				return Traffic{}, ErrBudget
			}
			next = append(next, pieces...)
		}
		out = next
	}
	return Traffic{out}, nil
}
func (s Traffic) Contains(t Traffic, limit int) (bool, error) {
	rest, err := t.Difference(s, limit)
	return err == nil && rest.Empty(), err
}
