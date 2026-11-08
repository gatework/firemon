package operations

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/internal/durablefile"
	"github.com/gatework/firemon/plan"
)

const maxSelectionBytes = 16 << 20

var ErrSelectionConflict = errors.New("batch selection identity conflicts with persisted selection")

// Selection explicitly names an approved candidate. Prepare is not write
// authorization: deploy.Engine still authorizes each exact operation separately.
type Selection struct {
	SourceRevision string `json:"source_revision,omitempty"`
	Device         string `json:"device"`
	Revision       string `json:"revision"`
	PlanDigest     string `json:"plan_digest"`
}

type PreparedBatch struct {
	ID         string         `json:"id"`
	Digest     string         `json:"digest"`
	Selections []Selection    `json:"selections"`
	Review     ReportDocument `json:"review"`
}

type ExecutionStatus string

const (
	ExecutionApplied   ExecutionStatus = "applied"
	ExecutionAborted   ExecutionStatus = "aborted"
	ExecutionUncertain ExecutionStatus = "uncertain"
	ExecutionFailed    ExecutionStatus = "failed"
	ExecutionCancelled ExecutionStatus = "cancelled"
	ExecutionUnstarted ExecutionStatus = "unstarted"
)

type DeviceExecution struct {
	Selection
	Operation string          `json:"operation"`
	Status    ExecutionStatus `json:"status"`
	Result    deploy.Result   `json:"result"`
	Code      string          `json:"code,omitempty"`
	Error     error           `json:"-"`
}
type BatchExecution struct {
	ID      string            `json:"id"`
	Digest  string            `json:"digest"`
	Review  ReportDocument    `json:"review"`
	Devices []DeviceExecution `json:"devices"`
}
type selectedPlan struct {
	Selection
	Operation string `json:"operation"`
	Checksum  string `json:"checksum"`
	Material  []byte `json:"material"`
}
type batchSelection struct {
	Version int            `json:"version"`
	ID      string         `json:"id"`
	Review  ReportDocument `json:"review"`
	Plans   []selectedPlan `json:"plans"`
}

// BatchExecutor persists immutable selections and composes independent engine
// calls in selection order. The engine journal owns all deployment state; this
// type never retries uncertain writes, rolls back peers or invents new IDs.
type BatchExecutor struct {
	root   string
	engine *deploy.Engine
	loader RevisionLoader
}

func NewBatchExecutor(root string, engine *deploy.Engine, loader RevisionLoader) (*BatchExecutor, error) {
	if strings.TrimSpace(root) == "" || engine == nil || dependency.Nil(loader) {
		return nil, ErrInvalid
	}
	path, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	return &BatchExecutor{root: path, engine: engine, loader: loader}, nil
}
func (e *BatchExecutor) validate(id string) error {
	if e == nil || e.root == "" || e.engine == nil || dependency.Nil(e.loader) || strings.TrimSpace(id) == "" || len(id) > 512 || !utf8.ValidString(id) {
		return ErrInvalid
	}
	return nil
}
func (e *BatchExecutor) path(id string) string {
	return filepath.Join(e.root, checksum([]byte(id))+".json")
}
func selectedOperation(id string, s Selection) string {
	// Length-prefixed original bytes avoid both separator and text-encoding aliases.
	var raw []byte
	for _, value := range []string{id, s.Device, s.Revision, s.SourceRevision, s.PlanDigest} {
		raw = binary.BigEndian.AppendUint64(raw, uint64(len(value)))
		raw = append(raw, value...)
	}
	return "batch-" + checksum(raw)
}

// Prepare verifies production reconstruction and durably stores the complete
// review plus only explicitly selected plans before any authorization or session.
// Reusing an ID with any different selection/review/material is a conflict.
func (e *BatchExecutor) Prepare(ctx context.Context, id string, report BatchReport, selections []Selection) (out PreparedBatch, err error) {
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err := e.validate(id); err != nil {
		return out, err
	}
	if report.Version != 1 || len(selections) < 1 || len(selections) > 100 || len(report.Devices) > 100 || len(report.Inputs) > 100 {
		return out, ErrInvalid
	}
	d := batchSelection{Version: 1, ID: id, Review: report.Document()}
	seen := make(map[string]bool, len(selections))
	remaining := maxSelectionBytes
	for _, s := range selections {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if s.Device == "" || len(s.Device) > 512 || !utf8.ValidString(s.Device) || !validChecksum(s.Revision) || s.SourceRevision != "" && !validChecksum(s.SourceRevision) || !validChecksum(s.PlanDigest) || seen[s.Device] {
			return out, ErrInvalid
		}
		seen[s.Device] = true
		var selected *DevicePlan
		for i := range report.Devices {
			device := &report.Devices[i]
			if device.Device == s.Device {
				if selected != nil {
					return out, ErrInvalid
				}
				selected = device
			}
		}
		if selected == nil || selected.Batch.Plan == nil || selected.Revision != s.Revision {
			return out, ErrInvalid
		}
		p := selected.Batch.Plan
		if p.Digest() != s.PlanDigest || p.Before().Metadata().Device != s.Device || p.Before().SemanticDigest() != selected.SemanticDigest {
			return out, ErrInvalid
		}
		var material bytes.Buffer
		sum, err := plan.EncodeReconstruction(ctx, &material, plan.SnapshotRevisions{Baseline: s.Revision, Source: s.SourceRevision}, p)
		if err != nil {
			return out, err
		}
		if material.Len() > remaining {
			return out, plan.ErrReconstruction
		}
		remaining -= material.Len()
		if _, _, err := RestorePlan(ctx, bytes.NewReader(material.Bytes()), sum, e.loader); err != nil {
			return out, err
		}
		d.Plans = append(d.Plans, selectedPlan{Selection: s, Operation: selectedOperation(id, s), Checksum: sum, Material: material.Bytes()})
	}
	raw, err := boundedJSON(ctx, d, maxSelectionBytes)
	if err != nil {
		return out, err
	}
	path := e.path(id)
	unlock, err := durablefile.Lock(ctx, path+".lock")
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	previous, err := readSelectionFile(ctx, path)
	if err == nil {
		if !bytes.Equal(previous, raw) {
			return out, ErrSelectionConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	} else {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if err := durablefile.Replace(path, raw); err != nil {
			return out, err
		}
	}
	out = PreparedBatch{ID: id, Digest: checksum(raw), Review: d.Review}
	for _, p := range d.Plans {
		out.Selections = append(out.Selections, p.Selection)
	}
	return out, nil
}

func readSelectionFile(ctx context.Context, path string) (raw []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return readBounded(ctx, f, maxSelectionBytes)
}
func (e *BatchExecutor) load(ctx context.Context, id, expected string) (batchSelection, error) {
	var d batchSelection
	if err := e.validate(id); err != nil {
		return d, err
	}
	if !validChecksum(expected) {
		return d, ErrSelectionConflict
	}
	raw, err := readSelectionFile(ctx, e.path(id))
	if err != nil {
		return d, err
	}
	if checksum(raw) != expected {
		return d, ErrSelectionConflict
	}
	if err := strictJSON(raw, &d); err != nil {
		return d, err
	}
	if d.Version != 1 || d.ID != id || len(d.Plans) < 1 || len(d.Plans) > 100 {
		return d, plan.ErrReconstruction
	}
	seen := make(map[string]bool, len(d.Plans))
	for _, p := range d.Plans {
		if p.Device == "" || len(p.Device) > 512 || seen[p.Device] || !validChecksum(p.Revision) || p.SourceRevision != "" && !validChecksum(p.SourceRevision) || !validChecksum(p.PlanDigest) || p.Operation != selectedOperation(id, p.Selection) || checksum(p.Material) != p.Checksum {
			return d, plan.ErrReconstruction
		}
		seen[p.Device] = true
	}
	return d, nil
}
func (e *BatchExecutor) Apply(ctx context.Context, id, expected string) (BatchExecution, error) {
	return e.run(ctx, id, expected, false)
}

// Recover delegates no-write recovery for the original selected operation IDs.
// An unstarted operation stays unstarted; recovery never starts it implicitly.
func (e *BatchExecutor) Recover(ctx context.Context, id, expected string) (BatchExecution, error) {
	return e.run(ctx, id, expected, true)
}
func (e *BatchExecutor) run(ctx context.Context, id, expected string, recover bool) (BatchExecution, error) {
	out := BatchExecution{ID: id, Digest: expected}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	d, err := e.load(ctx, id, expected)
	if err != nil {
		return out, err
	}
	out.Review = d.Review
	for _, selected := range d.Plans {
		r := DeviceExecution{Selection: selected.Selection, Operation: selected.Operation, Status: ExecutionUnstarted}
		if err := ctx.Err(); err != nil {
			r.Status, r.Code, r.Error = ExecutionCancelled, "cancelled_before_device", err
			out.Devices = append(out.Devices, r)
			continue
		}
		p, revision, err := RestorePlan(ctx, bytes.NewReader(selected.Material), selected.Checksum, e.loader)
		if err == nil && (revision != selected.Revision || p.Digest() != selected.PlanDigest || p.Before().Metadata().Device != selected.Device) {
			err = plan.ErrReconstruction
		}
		if err != nil {
			r.Status, r.Code, r.Error = ExecutionFailed, "reconstruction_failed", err
			out.Devices = append(out.Devices, r)
			continue
		}
		if recover {
			r.Result, err = e.engine.Recover(ctx, selected.Operation, p)
		} else {
			r.Result, err = e.engine.Apply(ctx, selected.Operation, selected.Revision, p)
		}
		r.Error = err
		switch {
		case r.Result.Terminal():
			r.Status = ExecutionApplied
			if r.Result.Phase == deploy.Aborted {
				r.Status = ExecutionAborted
			}
		case recover && errors.Is(err, deploy.ErrJournalNotFound):
			r.Status, r.Code = ExecutionUnstarted, "operation_not_started"
		case errors.Is(err, deploy.ErrUncertain) || errors.Is(err, deploy.ErrPending) || r.Result.Phase != 0:
			r.Status, r.Code = ExecutionUncertain, "recovery_required"
		default:
			r.Status, r.Code = ExecutionFailed, "device_operation_failed"
		}
		out.Devices = append(out.Devices, r)
	}
	// Per-device errors remain alongside successful peers. Cancellation is also
	// returned at batch level, with all outcomes collected so far intact.
	return out, ctx.Err()
}
