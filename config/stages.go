package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	fm "github.com/gatework/firemon"
)

type Stage struct {
	Name     string
	Requires []string
	Run      func(context.Context, *Session) error
}
type Session struct {
	cursor *Cursor
	data   fm.Data
}

func NewSession(c *Cursor, m fm.Metadata) (*Session, error) {
	if c == nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256([]byte(c.source.Text))
	m.SourceDigest = hex.EncodeToString(sum[:])
	return &Session{cursor: c, data: fm.Data{Metadata: m, Raw: c.source.Text}}, nil
}

func (s *Session) Cursor() *Cursor { return s.cursor }

func (s *Session) Commit(t *Transaction) error {
	if s == nil || s.cursor == nil {
		return ErrInvalid
	}
	if t == nil || t.cursor != s.cursor {
		return ErrClaim
	}
	return t.Commit(&s.data)
}
func (s *Session) Data() fm.Data {
	d := s.data.Clone()
	d.Evidence = s.cursor.Evidence()
	if !s.cursor.source.Complete {
		d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Code: "incomplete-source", Message: "capture completeness was not established"})
	}
	return d
}
func (s *Session) Run(ctx context.Context, stages []Stage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.cursor == nil {
		return ErrInvalid
	}
	done := make(map[string]bool)
	for _, stage := range stages {
		if stage.Name == "" || stage.Run == nil || done[stage.Name] {
			return fmt.Errorf("invalid stage %q", stage.Name)
		}
		for _, dep := range stage.Requires {
			if !done[dep] {
				return fmt.Errorf("stage %q requires earlier stage %q", stage.Name, dep)
			}
		}
		done[stage.Name] = true
	}
	for _, stage := range stages {
		if err := ctx.Err(); err != nil {
			return err
		}
		before := s.data
		wasTracking := s.cursor.tracking
		undoStart := len(s.cursor.undo)
		s.cursor.tracking = true
		point := s.cursor.Checkpoint()
		err := stage.Run(ctx, s)
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			s.data = before
			for i := len(s.cursor.undo) - 1; i >= undoStart; i-- {
				u := s.cursor.undo[i]
				s.cursor.evidence[u.index] = u.previous
			}
			s.cursor.undo = s.cursor.undo[:undoStart]
			s.cursor.tracking = wasTracking
			_ = s.cursor.Restore(point)
			return fmt.Errorf("stage %s: %w", stage.Name, err)
		}
		if !wasTracking {
			s.cursor.undo = nil
		}
		s.cursor.tracking = wasTracking
	}
	return nil
}
