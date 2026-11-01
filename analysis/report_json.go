package analysis

import (
	"encoding/json"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

// MarshalJSON exposes exact paired traffic instead of flow.Traffic's private
// storage. Reports preserve three-valued risk; Unknown is never a clean result.
func (f RiskFinding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PolicyID      string               `json:"policy_id"`
		PolicyVersion string               `json:"policy_version"`
		GraphDigest   string               `json:"graph_digest"`
		Rule          fm.ID                `json:"rule"`
		Mode          RiskMode             `json:"mode"`
		Value         Truth                `json:"value"`
		Traffic       []flow.TrafficRegion `json:"traffic"`
	}{f.PolicyID, f.PolicyVersion, f.GraphDigest, f.Rule, f.Mode, f.Value, f.Traffic.Regions()})
}
func (c ConvergenceCandidate) MarshalJSON() ([]byte, error) {
	report := struct {
		Rules   []fm.ID             `json:"rules"`
		Kind    ConvergenceKind     `json:"kind"`
		Reason  string              `json:"reason"`
		Status  string              `json:"status"`
		Digest  string              `json:"plan_digest,omitempty"`
		Proof   *policy.Equivalence `json:"preservation,omitempty"`
		Changes []plan.Change       `json:"changes,omitempty"`
	}{Rules: c.Rules, Kind: c.Kind, Reason: c.Reason, Status: "unproven"}
	if c.Plan != nil && c.Rejection == nil {
		if proof, ok := c.Plan.Preservation(); ok {
			report.Status = "proven"
			report.Digest = c.Plan.Digest()
			report.Proof = &proof
			report.Changes = c.Plan.Changes()
		}
	}
	// Operational errors must be handled by the caller, never copied to reports.
	return json.Marshal(report)
}
