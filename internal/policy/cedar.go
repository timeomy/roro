package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// Annotation keys Roro understands on Cedar policies.
const (
	// AnnotationID names a policy: @id("deny-exec"). IDs appear in audit
	// events. Without it a policy is named "<file>:<index>".
	AnnotationID = "id"
	// AnnotationReason sets the reason code a forbid (or approval permit)
	// reports: @reason("exfil_tool_blocked").
	AnnotationReason = "reason"
	// AnnotationApproval marks a permit that only allows the call after a
	// human approves it: @approval. It is only valid on permit policies.
	AnnotationApproval = "approval"
)

var reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// policyMeta is what Roro reads from a policy's annotations.
type policyMeta struct {
	id       string
	reason   string
	approval bool
	forbid   bool
}

// CedarEngine evaluates Cedar policies.
//
// require_approval is encoded with an annotation. Policies are split into two
// sets at load time:
//
//   - unattended: every policy without @approval (permits and forbids)
//   - approval:   every @approval permit, plus all forbids
//
// A call is allowed if the unattended set allows it. If a forbid matched, it is
// denied. Otherwise, if the approval set allows it, a human must approve.
// Otherwise it is denied (no matching permit). Forbids therefore always win.
type CedarEngine struct {
	unattended *cedar.PolicySet
	approval   *cedar.PolicySet
	meta       map[cedar.PolicyID]policyMeta
	matchers   []string
}

// LoadCedar parses policy files. Any parse error, duplicate @id, invalid
// @reason, or @approval on a forbid policy is an error (fail closed).
func LoadCedar(files []string, matcherNames []string) (*CedarEngine, error) {
	e := &CedarEngine{
		unattended: cedar.NewPolicySet(),
		approval:   cedar.NewPolicySet(),
		meta:       map[cedar.PolicyID]policyMeta{},
		matchers:   append([]string(nil), matcherNames...),
	}
	total := 0
	for _, f := range files {
		n, err := e.loadFile(f)
		if err != nil {
			return nil, err
		}
		total += n
	}
	if total == 0 {
		return nil, errors.New("policy: no Cedar policies found; every call would be denied")
	}
	return e, nil
}

func (e *CedarEngine) loadFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("policy: %w", err)
	}
	list, err := cedar.NewPolicyListFromBytes(path, data)
	if err != nil {
		return 0, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	base := filepath.Base(path)
	for i, p := range list {
		meta, err := readMeta(p, fmt.Sprintf("%s:%d", base, i))
		if err != nil {
			return 0, fmt.Errorf("policy: %s policy #%d: %w", path, i, err)
		}
		id := cedar.PolicyID(meta.id)
		if _, dup := e.meta[id]; dup {
			return 0, fmt.Errorf("policy: duplicate policy id %q in %s", meta.id, path)
		}
		e.meta[id] = meta
		switch {
		case meta.forbid:
			e.unattended.Add(id, p)
			e.approval.Add(id, p)
		case meta.approval:
			e.approval.Add(id, p)
		default:
			e.unattended.Add(id, p)
		}
	}
	return len(list), nil
}

func readMeta(p *cedar.Policy, fallbackID string) (policyMeta, error) {
	ann := p.Annotations()
	m := policyMeta{id: fallbackID, forbid: p.Effect() == cedar.Forbid}
	if v, ok := ann[AnnotationID]; ok {
		if strings.TrimSpace(string(v)) == "" {
			return m, errors.New("@id must not be empty")
		}
		m.id = string(v)
	}
	if v, ok := ann[AnnotationReason]; ok {
		if !reasonPattern.MatchString(string(v)) {
			return m, fmt.Errorf("@reason(%q) must be a lowercase snake_case code", v)
		}
		m.reason = string(v)
	}
	if _, ok := ann[AnnotationApproval]; ok {
		if m.forbid {
			return m, errors.New("@approval is only valid on permit policies")
		}
		m.approval = true
	}
	return m, nil
}

// Decide implements Engine.
func (e *CedarEngine) Decide(r Request) Decision {
	req, entities, err := buildRequest(r, e.matchers)
	if err != nil {
		return Decision{Outcome: Deny, Reason: ReasonEvaluationError, Detail: err.Error()}
	}
	dec, diag := e.unattended.IsAuthorized(entities, req)
	if d, failed := e.forbidErrors(diag); failed {
		return d
	}
	ids := e.reasonIDs(diag)
	if dec == cedar.Allow {
		return Decision{Outcome: Allow, Reason: ReasonPermitted, PolicyIDs: ids}
	}
	if len(ids) > 0 { // determining policies of a deny are forbids
		return Decision{Outcome: Deny, Reason: e.firstReason(diag, ReasonForbidden), PolicyIDs: ids,
			Detail: "denied by policy " + strings.Join(ids, ", ")}
	}
	dec2, diag2 := e.approval.IsAuthorized(entities, req)
	if d, failed := e.forbidErrors(diag2); failed {
		return d
	}
	if dec2 == cedar.Allow {
		return Decision{Outcome: RequireApproval, Reason: e.firstReason(diag2, ReasonApprovalRequired),
			PolicyIDs: e.reasonIDs(diag2), Detail: "policy requires human approval"}
	}
	return Decision{Outcome: Deny, Reason: ReasonNoMatchingPermit, Detail: "no policy permits this call"}
}

// forbidErrors fails closed when a forbid policy could not be evaluated:
// an erroring forbid might otherwise have denied the call. Errors in permit
// policies only mean that permit does not apply, which is already safe.
func (e *CedarEngine) forbidErrors(diag cedar.Diagnostic) (Decision, bool) {
	var ids, msgs []string
	for _, de := range diag.Errors {
		if e.meta[de.PolicyID].forbid {
			ids = append(ids, e.meta[de.PolicyID].id)
			msgs = append(msgs, de.Message)
		}
	}
	if len(ids) == 0 {
		return Decision{}, false
	}
	return Decision{Outcome: Deny, Reason: ReasonEvaluationError, PolicyIDs: ids,
		Detail: "forbid policy failed to evaluate: " + strings.Join(msgs, "; ")}, true
}

func (e *CedarEngine) reasonIDs(diag cedar.Diagnostic) []string {
	ids := make([]string, 0, len(diag.Reasons))
	for _, r := range diag.Reasons {
		ids = append(ids, e.meta[r.PolicyID].id)
	}
	sort.Strings(ids)
	return ids
}

// firstReason returns the @reason of the determining policy with the lowest
// id, so the result is deterministic when several policies match.
func (e *CedarEngine) firstReason(diag cedar.Diagnostic, fallback string) string {
	best, bestID := "", ""
	for _, r := range diag.Reasons {
		m := e.meta[r.PolicyID]
		if m.reason != "" && (bestID == "" || m.id < bestID) {
			best, bestID = m.reason, m.id
		}
	}
	if best == "" {
		return fallback
	}
	return best
}

// PolicyCount reports how many policies were loaded.
func (e *CedarEngine) PolicyCount() int { return len(e.meta) }
