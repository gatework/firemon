package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

const maxAnalysisInput = 4 << 20
const maxAnalysisOutput = 16 << 20

type queryDoc struct {
	Traffic         []flow.TrafficRegion `json:"traffic"`
	Scope           string               `json:"scope,omitempty"`
	RuleSet         string               `json:"ruleset,omitempty"`
	FromZone        fm.ID                `json:"from_zone,omitempty"`
	ToZone          fm.ID                `json:"to_zone,omitempty"`
	EgressInterface fm.ID                `json:"egress_interface,omitempty"`
	At              time.Time            `json:"at"`
}

func (d queryDoc) request(limit int) (policy.Request, error) {
	if len(d.Traffic) == 0 || len(d.Traffic) > limit {
		return policy.Request{}, analysis.ErrInvalid
	}
	traffic, err := flow.NewTraffic(limit, d.Traffic...)
	return policy.Request{Traffic: traffic, Scope: d.Scope, RuleSet: d.RuleSet, FromZone: d.FromZone, ToZone: d.ToZone, EgressInterface: d.EgressInterface, At: d.At}, err
}

type inspectDoc struct {
	Version    int                 `json:"version"`
	Object     fm.AddressRef       `json:"object"`
	Addresses  []flow.AddressRange `json:"addresses,omitempty"`
	Evaluation *queryDoc           `json:"evaluation,omitempty"`
	Aliases    *struct {
		Request queryDoc         `json:"request"`
		VRF     string           `json:"vrf,omitempty"`
		View    policy.AliasView `json:"view"`
	} `json:"aliases,omitempty"`
}

func (d inspectDoc) request(limit int) (analysis.InspectionRequest, error) {
	if d.Version != 1 || len(d.Addresses) > limit {
		return analysis.InspectionRequest{}, analysis.ErrInvalid
	}
	addresses, err := flow.NewAddressSet(d.Addresses...)
	if err != nil {
		return analysis.InspectionRequest{}, err
	}
	q := analysis.InspectionRequest{Object: d.Object, Addresses: addresses}
	if d.Evaluation != nil {
		v, err := d.Evaluation.request(limit)
		if err != nil {
			return q, err
		}
		q.Evaluation = &v
	}
	if d.Aliases != nil {
		v, err := d.Aliases.Request.request(limit)
		if err != nil {
			return q, err
		}
		q.Aliases = &analysis.AliasInspection{Request: policy.PacketRequest{Request: v, VRF: d.Aliases.VRF}, View: d.Aliases.View}
	}
	return q, nil
}

type riskExprDoc struct {
	Predicate *struct {
		Dimension analysis.Dimension  `json:"dimension"`
		Relation  analysis.Relation   `json:"relation"`
		Addresses []flow.AddressRange `json:"addresses,omitempty"`
		Services  []fm.ServiceTerm    `json:"services,omitempty"`
	} `json:"predicate,omitempty"`
	All []riskExprDoc `json:"all,omitempty"`
	Any []riskExprDoc `json:"any,omitempty"`
}

func (d riskExprDoc) expression(depth int, nodes *int, limit int) (analysis.RiskExpression, error) {
	if depth >= 64 || *nodes <= 0 {
		return analysis.RiskExpression{}, policy.ErrBudget
	}
	*nodes -= 1
	out := analysis.RiskExpression{}
	if d.Predicate != nil {
		p := d.Predicate
		if len(p.Addresses) > limit || len(p.Services) > limit {
			return out, flow.ErrBudget
		}
		addresses, err := flow.NewAddressSet(p.Addresses...)
		if err != nil {
			return out, err
		}
		out.Predicate = &analysis.RiskPredicate{Dimension: p.Dimension, Relation: p.Relation, Addresses: addresses, Services: p.Services}
	}
	if len(d.All)+len(d.Any) > *nodes {
		return out, policy.ErrBudget
	}
	for _, child := range d.All {
		v, err := child.expression(depth+1, nodes, limit)
		if err != nil {
			return out, err
		}
		out.All = append(out.All, v)
	}
	for _, child := range d.Any {
		v, err := child.expression(depth+1, nodes, limit)
		if err != nil {
			return out, err
		}
		out.Any = append(out.Any, v)
	}
	return out, nil
}

type riskDoc struct {
	Version     int        `json:"version"`
	Contexts    []queryDoc `json:"contexts"`
	Definitions []struct {
		ID         string               `json:"id"`
		Version    string               `json:"version"`
		Mode       analysis.RiskMode    `json:"mode"`
		Relation   analysis.Relation    `json:"relation,omitempty"`
		Traffic    []flow.TrafficRegion `json:"traffic,omitempty"`
		Actions    []fm.Action          `json:"actions,omitempty"`
		Expression *riskExprDoc         `json:"expression,omitempty"`
	} `json:"definitions"`
}

func (d riskDoc) request(limits policy.Limits) ([]policy.Request, []analysis.RiskDefinition, error) {
	if d.Version != 1 || len(d.Contexts) == 0 || len(d.Definitions) == 0 {
		return nil, nil, analysis.ErrInvalid
	}
	if len(d.Contexts) > limits.MaxCombinations/len(d.Definitions) {
		return nil, nil, policy.ErrBudget
	}
	var contexts []policy.Request
	var definitions []analysis.RiskDefinition
	for _, c := range d.Contexts {
		q, err := c.request(limits.MaxRegions)
		if err != nil {
			return nil, nil, err
		}
		contexts = append(contexts, q)
	}
	nodes := limits.MaxCombinations
	for _, v := range d.Definitions {
		if len(v.Traffic) > limits.MaxRegions {
			return nil, nil, flow.ErrBudget
		}
		traffic, err := flow.NewTraffic(limits.MaxRegions, v.Traffic...)
		if err != nil {
			return nil, nil, err
		}
		def := analysis.RiskDefinition{ID: v.ID, Version: v.Version, Mode: v.Mode, Relation: v.Relation, Traffic: traffic, Actions: v.Actions}
		if v.Expression != nil {
			exp, err := v.Expression.expression(0, &nodes, limits.MaxRegions)
			if err != nil {
				return nil, nil, err
			}
			def.Expression = &exp
		}
		definitions = append(definitions, def)
	}
	return contexts, definitions, nil
}
func readJSON(ctx context.Context, path string, value any) (err error) {
	input, finish, err := openInput(ctx, path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, finish()) }()
	raw, err := io.ReadAll(io.LimitReader(input, maxAnalysisInput+1))
	if err != nil {
		return err
	}
	if len(raw) > maxAnalysisInput {
		return usage(errors.New("analysis request exceeds byte limit"))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return usage(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return usage(errors.New("trailing analysis JSON"))
	}
	return nil
}

// Encode privately before writing so a failed budget or serialization never
// leaves a truncated document that could be mistaken for a complete report.
func analysisOutput(out io.Writer, v any) error {
	var buf bytes.Buffer
	if err := output(&limitWriter{writer: &buf, remaining: maxAnalysisOutput}, v); err != nil {
		return err
	}
	return writeOutput(out, buf.Bytes())
}

type limitWriter struct {
	writer    io.Writer
	remaining int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, policy.ErrBudget
	}
	n, err := w.writer.Write(p)
	w.remaining -= n
	return n, err
}
