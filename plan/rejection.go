package plan

import (
	"context"
	"errors"
	"fmt"

	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// RejectionStage identifies where a candidate was found unsuitable.
type RejectionStage string

const (
	DeclarationRejection    RejectionStage = "declaration"
	PreservationRejection   RejectionStage = "preservation"
	RepresentationRejection RejectionStage = "representation"
)

// RejectionError describes an expected candidate refusal, not an operational
// failure. Unwrap retains the existing cause for errors.Is. Callers can use
// errors.As for diagnostics, but a nested rejection does not authorize retry:
// it may belong to a failed renderer dependency rather than this candidate.
type RejectionError struct {
	Stage RejectionStage
	Err   error
}

func (e *RejectionError) Error() string {
	return fmt.Sprintf("plan: %s rejected: %v", e.Stage, e.Err)
}

func (e *RejectionError) Unwrap() error { return e.Err }

// representationRejected recognizes only the renderer's native refusal
// contract. A nested planning rejection belongs to that dependency, not us.
func representationRejected(err error) bool {
	var foreign *RejectionError
	return !computationFailed(err) && !errors.As(err, &foreign) && errors.Is(err, ErrRender)
}

func computationFailed(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, policy.ErrBudget) || errors.Is(err, flow.ErrBudget)
}
