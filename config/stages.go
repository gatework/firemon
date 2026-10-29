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
	Cursor *Cursor
	data   fm.Data
}

func NewSession(c *Cursor, m fm.Metadata) *Session {
	sum := sha256.Sum256([]byte(c.source.Text))
	m.SourceDigest = hex.EncodeToString(sum[:])
	return &Session{Cursor: c, data: fm.Data{Metadata: m, Raw: c.source.Text}}
}
func (s *Session) Commit(t *Transaction) error {
	if t.cursor != s.Cursor {
		return ErrClaim
	}
	return t.Commit(&s.data)
}
func (s *Session) Data() fm.Data {
	d := s.data.Clone()
	d.Evidence = s.Cursor.Evidence()
	if !s.Cursor.source.Complete {
		d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Code: "incomplete-source", Message: "capture completeness was not established"})
	}
	return d
}
func (s *Session) Run(ctx context.Context, stages []Stage) error {
	if err := ctx.Err(); err != nil {
		return err
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
		wasTracking := s.Cursor.tracking
		undoStart := len(s.Cursor.undo)
		s.Cursor.tracking = true
		point := s.Cursor.Checkpoint()
		err := stage.Run(ctx, s)
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			s.data = before
			for i := len(s.Cursor.undo) - 1; i >= undoStart; i-- {
				u := s.Cursor.undo[i]
				s.Cursor.evidence[u.index] = u.previous
			}
			s.Cursor.undo = s.Cursor.undo[:undoStart]
			s.Cursor.tracking = wasTracking
			_ = s.Cursor.Restore(point)
			return fmt.Errorf("stage %s: %w", stage.Name, err)
		}
		if !wasTracking {
			s.Cursor.undo = nil
		}
		s.Cursor.tracking = wasTracking
	}
	return nil
}
