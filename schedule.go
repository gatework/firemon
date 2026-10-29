package firemon

import (
	"iter"
	"time"
)

// Windows visits absolute windows by value in declaration order. It does not
// expose storage, and stops as soon as the consumer stops iteration.
func (s *Schedule) Windows() iter.Seq[TimeWindow] {
	return func(yield func(TimeWindow) bool) {
		for _, window := range s.record.Windows {
			if !yield(window) {
				return
			}
		}
	}
}

// HasRecurrence reports declarations whose recurring times need interpretation.
func (s *Schedule) HasRecurrence() bool { return len(s.record.Recurring) != 0 }

// ActiveAt reports activity in the schedule's half-open absolute windows.
// An unknown schedule remains possibly active; the second value is false.
func (s *Schedule) ActiveAt(at time.Time) (active, known bool) {
	if !s.knownAt(at) {
		return true, false
	}
	for _, window := range s.record.Windows {
		if !at.Before(window.Start) && at.Before(window.End) {
			return true, true
		}
	}
	return false, true
}

// ExpiredAt reports that every absolute window has ended. Unknown declarations
// and missing time evidence can never establish expiry.
func (s *Schedule) ExpiredAt(at time.Time) (expired, known bool) {
	if !s.knownAt(at) {
		return false, false
	}
	for _, window := range s.record.Windows {
		if window.End.After(at) {
			return false, true
		}
	}
	return true, true
}

func (s *Schedule) knownAt(at time.Time) bool {
	return s != nil && !at.IsZero() && !s.HasUnsupported() && len(s.record.Recurring) == 0 && len(s.record.Windows) > 0
}
