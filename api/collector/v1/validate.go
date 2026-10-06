// Contract rules that protobuf cannot express.
//
// These live in the contract module rather than in any consumer because the
// SDK, the plugin host and the conformance suite all have to apply exactly the
// same rules. Three implementations would drift, and the drift would surface
// as a plugin that passes conformance and fails in production.
//
// The rule this file exists for above all others: the zero value of every enum
// in this contract is invalid on the wire. proto3 and buf force a zero value
// to exist, so the schema cannot make "the author forgot" impossible. Where
// "we do not know" is an honest answer there is an explicit _UNKNOWN value,
// and it is never zero.
//
// See docs/adr/0006-collector-contract-shape.md.

package collectorv1

import (
	"fmt"
	"strings"
)

// Violation is one broken rule, addressed by protobuf field path so that a
// plugin author is told where to look rather than what we think they meant.
type Violation struct {
	// Field path, e.g. "node.key.type" or "edge.path.via[1]".
	Field string
	// Stable machine-readable rule name. Tests and error reports key on this,
	// not on Message, so wording can improve without breaking either.
	Rule string
	// One sentence for a human.
	Message string
}

func (v Violation) String() string { return v.Field + ": " + v.Rule + ": " + v.Message }

// rule names, used by callers and tests.
const (
	ruleEnumUnspecified = "enum-must-not-be-unspecified"
	ruleKeyRequired     = "key-required"
	ruleKeyFields       = "key-fields-required"
	ruleScopeKeySelf    = "scope-key-is-self-referential"
	ruleRecordRequired  = "record-required"
	ruleNodeName        = "node-name-required"
	ruleNodeSourceType  = "node-source-type-required"
	ruleIdentityFacts   = "identity-facts-iff-identity"
)

// unspecified builds the violation this whole file exists for.
func unspecified(at, enum string) Violation {
	return Violation{
		Field:   at,
		Rule:    ruleEnumUnspecified,
		Message: "the zero value of " + enum + " is invalid on the wire",
	}
}

// missingRecord reports a nil record, so a caller gets a violation rather than
// a panic on data that arrived over a wire.
func missingRecord(at string) []Violation {
	return []Violation{{
		Field:   at,
		Rule:    ruleRecordRequired,
		Message: at + " is required",
	}}
}

// ValidateKey checks one Key. `at` is the field path of the key itself, so
// that a violation points at "edge.from" rather than at "key".
func ValidateKey(k *Key, at string) []Violation {
	if k == nil {
		return []Violation{{
			Field:   at,
			Rule:    ruleKeyRequired,
			Message: "a key is required",
		}}
	}
	var vs []Violation
	if k.GetType() == NodeType_NODE_TYPE_UNSPECIFIED {
		return append(vs, unspecified(at+".type", "NodeType"))
	}
	if k.GetScope() == "" || k.GetId() == "" {
		vs = append(vs, Violation{
			Field:   at,
			Rule:    ruleKeyFields,
			Message: "scope and id are both required",
		})
		return vs
	}
	if k.GetType() == NodeType_NODE_TYPE_SCOPE && k.GetScope() != k.GetId() {
		vs = append(vs, Violation{
			Field:   at,
			Rule:    ruleScopeKeySelf,
			Message: fmt.Sprintf("a scope node must be keyed under itself: scope %q, id %q", k.GetScope(), k.GetId()),
		})
	}
	return vs
}

// ValidateNode checks one Node.
func ValidateNode(n *Node) []Violation {
	if n == nil {
		return missingRecord("node")
	}
	vs := ValidateKey(n.GetKey(), "node.key")

	if n.GetName() == "" {
		vs = append(vs, Violation{
			Field:   "node.name",
			Rule:    ruleNodeName,
			Message: "a display name is required",
		})
	}
	if n.GetSourceType() == "" {
		vs = append(vs, Violation{
			Field:   "node.source_type",
			Rule:    ruleNodeSourceType,
			Message: "the source's own type name is required; a reviewer UI renders it as the badge",
		})
	}
	if n.GetProvenance() == Provenance_PROVENANCE_UNSPECIFIED {
		vs = append(vs, unspecified("node.provenance", "Provenance"))
	}

	// Identity is the only node type with structured facts, and the rule is
	// exact in both directions: facts without an identity would be data nobody
	// can interpret, and an identity without them would silently lose the
	// human/service distinction that R11 exists for.
	isIdentity := n.GetKey().GetType() == NodeType_NODE_TYPE_IDENTITY
	if isIdentity != (n.GetIdentity() != nil) {
		vs = append(vs, Violation{
			Field:   "node.identity",
			Rule:    ruleIdentityFacts,
			Message: "identity facts are required if and only if the key type is NODE_TYPE_IDENTITY",
		})
		return vs
	}
	if f := n.GetIdentity(); f != nil {
		if f.GetKind() == IdentityKind_IDENTITY_KIND_UNSPECIFIED {
			vs = append(vs, unspecified("node.identity.kind", "IdentityKind"))
		}
		if f.GetStatus() == IdentityStatus_IDENTITY_STATUS_UNSPECIFIED {
			vs = append(vs, unspecified("node.identity.status", "IdentityStatus"))
		}
	}
	return vs
}

const (
	ruleEdgeEndpoints  = "edge-endpoint-types"
	ruleFidelityPath   = "fidelity-path-agreement"
	ruleStructuralEdge = "structural-edge-not-effective"
)

// edgeShape is the fixed endpoint typing for one EdgeType. Keeping it as data
// rather than as a switch means the table in collector.proto and the rule the
// host enforces are the same shape, and a reviewer can compare them by eye.
type edgeShape struct {
	from []NodeType
	to   []NodeType
	// structural edges state how the source is arranged. Nothing derives them,
	// so they are never EFFECTIVE.
	structural bool
}

var edgeShapes = map[EdgeType]edgeShape{
	EdgeType_EDGE_TYPE_MEMBER_OF: {
		from: []NodeType{NodeType_NODE_TYPE_IDENTITY}, to: []NodeType{NodeType_NODE_TYPE_GROUPING}, structural: true,
	},
	EdgeType_EDGE_TYPE_CHILD_OF: {
		from: []NodeType{NodeType_NODE_TYPE_GROUPING}, to: []NodeType{NodeType_NODE_TYPE_GROUPING}, structural: true,
	},
	EdgeType_EDGE_TYPE_HOLDS: {
		from: []NodeType{NodeType_NODE_TYPE_IDENTITY, NodeType_NODE_TYPE_GROUPING},
		to:   []NodeType{NodeType_NODE_TYPE_ENTITLEMENT},
	},
	EdgeType_EDGE_TYPE_INCLUDES: {
		from: []NodeType{NodeType_NODE_TYPE_ENTITLEMENT}, to: []NodeType{NodeType_NODE_TYPE_ENTITLEMENT}, structural: true,
	},
	// A scope target is how a source says "everything here". GitHub's
	// organization base permission and an AWS policy naming Resource "*" both
	// grant against a whole scope from one stated fact; expanding that into an
	// edge per resource would emit relationships the source never stated, and
	// would be quadratic in a large tenant.
	EdgeType_EDGE_TYPE_APPLIES_TO: {
		from: []NodeType{NodeType_NODE_TYPE_ENTITLEMENT},
		to:   []NodeType{NodeType_NODE_TYPE_RESOURCE, NodeType_NODE_TYPE_SCOPE}, structural: true,
	},
	EdgeType_EDGE_TYPE_ACTS_AS: {
		from: []NodeType{NodeType_NODE_TYPE_ENTITLEMENT}, to: []NodeType{NodeType_NODE_TYPE_IDENTITY}, structural: true,
	},
}

// ValidateEdge checks one Edge.
func ValidateEdge(e *Edge) []Violation {
	if e == nil {
		return missingRecord("edge")
	}
	var vs []Violation
	vs = append(vs, ValidateKey(e.GetFrom(), "edge.from")...)
	vs = append(vs, ValidateKey(e.GetTo(), "edge.to")...)
	for i, via := range e.GetPath().GetVia() {
		vs = append(vs, ValidateKey(via, fmt.Sprintf("edge.path.via[%d]", i))...)
	}

	if e.GetType() == EdgeType_EDGE_TYPE_UNSPECIFIED {
		return append(vs, unspecified("edge.type", "EdgeType"))
	}
	if e.GetFidelity() == Fidelity_FIDELITY_UNSPECIFIED {
		return append(vs, unspecified("edge.fidelity", "Fidelity"))
	}
	if len(vs) > 0 {
		// The endpoint and path rules below read the keys; do not compound a
		// broken key into a second, confusing complaint.
		return vs
	}

	shape, known := edgeShapes[e.GetType()]
	if !known {
		// A newer plugin's edge type. Tolerated: unknown non-zero enum values
		// are preserved, never rejected. Nothing more can be checked here.
		return vs
	}

	if !contains(shape.from, e.GetFrom().GetType()) || !contains(shape.to, e.GetTo().GetType()) {
		vs = append(vs, Violation{
			Field: "edge",
			Rule:  ruleEdgeEndpoints,
			Message: fmt.Sprintf("%v runs %v to %v, not %v to %v",
				e.GetType(), shape.from, shape.to, e.GetFrom().GetType(), e.GetTo().GetType()),
		})
	}

	if shape.structural && e.GetFidelity() == Fidelity_FIDELITY_EFFECTIVE {
		vs = append(vs, Violation{
			Field:   "edge.fidelity",
			Rule:    ruleStructuralEdge,
			Message: fmt.Sprintf("%v states how the source is arranged; nothing derives it, so it is never EFFECTIVE", e.GetType()),
		})
	}

	// DIRECT means the source said so, which leaves nothing to route through.
	// EFFECTIVE means the plugin derived it, which is meaningless without
	// saying from what. COARSE may be either: an unevaluated policy can be
	// held directly or reached through a group.
	hasPath := len(e.GetPath().GetVia()) > 0
	switch e.GetFidelity() {
	case Fidelity_FIDELITY_DIRECT:
		if hasPath {
			vs = append(vs, Violation{
				Field:   "edge.path",
				Rule:    ruleFidelityPath,
				Message: "a DIRECT edge is stated by the source and carries no path",
			})
		}
	case Fidelity_FIDELITY_EFFECTIVE:
		if !hasPath {
			vs = append(vs, Violation{
				Field:   "edge.path",
				Rule:    ruleFidelityPath,
				Message: "an EFFECTIVE edge was derived and must say through what",
			})
		}
	}
	return vs
}

func contains(types []NodeType, t NodeType) bool {
	for _, allowed := range types {
		if allowed == t {
			return true
		}
	}
	return false
}

const (
	ruleActivityResult     = "activity-result-required"
	ruleActivitySignal     = "activity-signal-required"
	ruleActivityObservedAt = "activity-observed-at-required"
	ruleActivityCoverage   = "activity-coverage-required"
	ruleActivityLag        = "activity-source-lag-required"
	ruleActivityLastSeen   = "activity-last-seen-required"
	ruleCoverageBounds     = "coverage-bounds-required"
	ruleCoverageOrdered    = "coverage-bounds-ordered"
	ruleUnavailableCode    = "unavailable-code-required"
)

// ValidateActivity checks one Activity.
//
// The shape here is the requirement: an activity claim is never a bare
// timestamp. A reviewer deciding whether an account is dormant needs to know
// how far back the source can see and how stale the reading is, and cannot
// tell "nobody logged in" from "we cannot see that far back" without both.
func ValidateActivity(a *Activity) []Violation {
	if a == nil {
		return missingRecord("activity")
	}
	vs := ValidateKey(a.GetSubject(), "activity.subject")

	if a.GetSignal() == "" {
		vs = append(vs, Violation{
			Field:   "activity.signal",
			Rule:    ruleActivitySignal,
			Message: "a signal name is required, and it must be one Describe declared",
		})
	}
	if a.GetObservedAt() == nil {
		vs = append(vs, Violation{
			Field:   "activity.observed_at",
			Rule:    ruleActivityObservedAt,
			Message: "when the plugin read the value is required",
		})
	}

	switch result := a.GetResult().(type) {
	case nil:
		// The whole point of the oneof: a record with no arm is a contract
		// violation, not an implied "never".
		return append(vs, Violation{
			Field:   "activity.result",
			Rule:    ruleActivityResult,
			Message: "exactly one of seen, not_seen or unavailable is required",
		})

	case *Activity_Seen:
		vs = append(vs, validateCoverage(a)...)
		if result.Seen.GetLastSeen() == nil {
			vs = append(vs, Violation{
				Field:   "activity.seen.last_seen",
				Rule:    ruleActivityLastSeen,
				Message: "a seen result must say when",
			})
		}
		if result.Seen.GetConfidence() == Confidence_CONFIDENCE_UNSPECIFIED {
			vs = append(vs, unspecified("activity.seen.confidence", "Confidence"))
		}
		vs = append(vs, checkSeenInWindow(a, result.Seen)...)

	case *Activity_NotSeen:
		vs = append(vs, validateCoverage(a)...)
		// An absence has a precision too: Access Advisor reporting "not
		// accessed" is not the same claim as a login log being empty.
		if result.NotSeen.GetConfidence() == Confidence_CONFIDENCE_UNSPECIFIED {
			vs = append(vs, unspecified("activity.not_seen.confidence", "Confidence"))
		}

	case *Activity_Unavailable:
		// Coverage and lag describe a window the source can answer within.
		// When it cannot answer at all there is no window to describe.
		if result.Unavailable.GetCode() == "" {
			vs = append(vs, Violation{
				Field:   "activity.unavailable.code",
				Rule:    ruleUnavailableCode,
				Message: "an unavailable result must carry a machine-readable code",
			})
		}
	}
	return vs
}

// checkSeenInWindow rejects a sighting the record's own coverage says the
// source could not have seen. A timestamp outside its window is either a wrong
// window, which overstates what we know, or a wrong timestamp.
func checkSeenInWindow(a *Activity, seen *Seen) []Violation {
	c, last := a.GetCoverage(), seen.GetLastSeen()
	if c == nil || c.GetSince() == nil || c.GetUntil() == nil || last == nil {
		return nil // already reported by validateCoverage
	}
	since, until := c.GetSince().AsTime(), c.GetUntil().AsTime()
	if since.After(until) {
		return nil // the window itself is already reported as invalid
	}
	t := last.AsTime()
	if t.Before(since) || t.After(until) {
		return []Violation{{
			Field:   "activity.seen.last_seen",
			Rule:    ruleLastSeenWindow,
			Message: "the sighting falls outside the window the record says the source can see",
		}}
	}
	return nil
}

// validateCoverage checks the fields that only mean something when the source
// can actually answer.
func validateCoverage(a *Activity) []Violation {
	var vs []Violation

	if a.GetSourceLag() == nil {
		// Zero is a meaningful value here — a Keycloak login event has no lag —
		// so an unset duration is an omission rather than a zero.
		vs = append(vs, Violation{
			Field:   "activity.source_lag",
			Rule:    ruleActivityLag,
			Message: "how stale the source admits the value may be is required; zero is a value, not an absence",
		})
	}

	c := a.GetCoverage()
	if c == nil {
		return append(vs, Violation{
			Field:   "activity.coverage",
			Rule:    ruleActivityCoverage,
			Message: "how far back the source can see is required",
		})
	}
	if c.GetSince() == nil || c.GetUntil() == nil {
		// An absent lower bound reads as "we see everything", which is the one
		// claim in this contract a reviewer could not detect as false.
		return append(vs, Violation{
			Field:   "activity.coverage",
			Rule:    ruleCoverageBounds,
			Message: "both bounds are required; an absent lower bound reads as seeing everything",
		})
	}
	if c.GetSince().AsTime().After(c.GetUntil().AsTime()) {
		vs = append(vs, Violation{
			Field:   "activity.coverage",
			Rule:    ruleCoverageOrdered,
			Message: "the coverage window starts after it ends",
		})
	}
	return vs
}

const (
	ruleCompletionCause   = "completion-cause-iff-incomplete"
	ruleCompletionCursor  = "completion-cursor-forbidden-when-complete"
	ruleCompletionCounts  = "completion-counts-required"
	ruleCompleteScopes    = "complete-requires-every-scope-accounted"
	ruleScopeOutcomeError = "scope-outcome-error-required"
	ruleScopeOutcomeKey   = "scope-outcome-key-type"
)

// ValidateCompletion checks the terminal event of a stream.
//
// The rules here are what stop a truncated population from being presented as
// a whole one. A complete verdict is a claim that every scope was accounted
// for, and it has to be contradicted by the record itself when it is not true.
func ValidateCompletion(c *Completion) []Violation {
	if c == nil {
		return missingRecord("completion")
	}
	var vs []Violation

	if c.GetVerdict() == Verdict_VERDICT_UNSPECIFIED {
		return append(vs, unspecified("completion.verdict", "Verdict"))
	}
	if c.GetCounts() == nil {
		vs = append(vs, Violation{
			Field:   "completion.counts",
			Rule:    ruleCompletionCounts,
			Message: "counts are required so the host can check them against what it received",
		})
	}

	complete := c.GetVerdict() == Verdict_VERDICT_COMPLETE
	hasCause := c.GetCause() != IncompleteCause_INCOMPLETE_CAUSE_UNSPECIFIED
	if complete == hasCause {
		vs = append(vs, Violation{
			Field:   "completion.cause",
			Rule:    ruleCompletionCause,
			Message: "a cause is required if and only if the verdict is INCOMPLETE",
		})
	}
	if complete && c.GetResumeCursor() != nil {
		vs = append(vs, Violation{
			Field:   "completion.resume_cursor",
			Rule:    ruleCompletionCursor,
			Message: "a complete collection has nothing to resume from",
		})
	}

	for i, s := range c.GetScopes() {
		at := fmt.Sprintf("completion.scopes[%d]", i)
		vs = append(vs, validateScopeOutcome(s, at, complete)...)
	}
	return vs
}

func validateScopeOutcome(s *ScopeOutcome, at string, complete bool) []Violation {
	if s == nil {
		return missingRecord(at)
	}
	vs := ValidateKey(s.GetScope(), at+".scope")
	if s.GetScope().GetType() != NodeType_NODE_TYPE_SCOPE && len(vs) == 0 {
		vs = append(vs, Violation{
			Field:   at + ".scope",
			Rule:    ruleScopeOutcomeKey,
			Message: "a scope outcome must name a NODE_TYPE_SCOPE key",
		})
	}

	switch s.GetStatus() {
	case ScopeStatus_SCOPE_STATUS_UNSPECIFIED:
		return append(vs, unspecified(at+".status", "ScopeStatus"))

	case ScopeStatus_SCOPE_STATUS_PARTIAL, ScopeStatus_SCOPE_STATUS_UNREACHABLE:
		if s.GetError() == nil {
			vs = append(vs, Violation{
				Field:   at + ".error",
				Rule:    ruleScopeOutcomeError,
				Message: "a scope that was not fully collected must say why",
			})
		} else {
			vs = append(vs, ValidateError(s.GetError(), at+".error")...)
		}
		if complete {
			// The verdict claims the population is whole while the record
			// says a scope is not. The record wins.
			vs = append(vs, Violation{
				Field:   at + ".status",
				Rule:    ruleCompleteScopes,
				Message: "a COMPLETE verdict requires every scope to be COLLECTED or SKIPPED",
			})
		}
	}
	return vs
}

// ValidateEvent checks one stream event, whichever arm it carries.
//
// An event with no recognised arm is tolerated rather than rejected: that is
// how a newer plugin's event kind reaches an older host without either side
// failing. Whether such an event may appear at all, and what must follow it,
// is a property of the stream rather than of the record.
func ValidateEvent(e *CollectResponse) []Violation {
	if e == nil {
		return missingRecord("event")
	}
	switch event := e.GetEvent().(type) {
	case *CollectResponse_Node:
		return ValidateNode(event.Node)
	case *CollectResponse_Edge:
		return ValidateEdge(event.Edge)
	case *CollectResponse_Activity:
		return ValidateActivity(event.Activity)
	case *CollectResponse_Completion:
		return ValidateCompletion(event.Completion)
	case *CollectResponse_Diagnostic:
		return ValidateDiagnostic(event.Diagnostic)
	default:
		return nil
	}
}

const (
	ruleErrorMessage      = "error-message-required"
	ruleDiagnosticCode    = "diagnostic-code-required"
	ruleDiagnosticMessage = "diagnostic-message-required"
	ruleDescribeKind      = "describe-kind-mismatch"
	ruleDescribeVersion   = "describe-protocol-version-mismatch"
	ruleDescribeName      = "describe-name-required"
	ruleDescribeCaps      = "describe-capabilities-required"
	ruleCoarseLimitation  = "coarse-requires-a-declared-limitation"
	ruleActivitySignals   = "activity-requires-a-declared-signal"
	ruleLimitationCode    = "limitation-code-required"
	ruleLimitationSummary = "limitation-summary-required"
	ruleScopeProbeError   = "scope-probe-error-required"
	ruleScopeProbeName    = "scope-probe-name-required"
	ruleRevokeError       = "revoke-failure-error-required"
	ruleConfigCode        = "config-issue-code-required"
	ruleConfigMessage     = "config-issue-message-required"
	ruleConfigPointer     = "config-issue-field-must-be-a-json-pointer"
	ruleLastSeenWindow    = "last-seen-outside-coverage"

	ruleProbeActivityRequired = "scope-probe-activity-required"
	ruleProbeNoteContradicts  = "scope-probe-note-contradicts-availability"
)

// Kind and ProtocolVersion are what this package is. A Describe that claims
// otherwise is talking about a different contract.
const (
	Kind            = "collector"
	ProtocolVersion = 1
)

// ValidateError checks an Error carries something a reader can act on.
//
// Several rules elsewhere say a plugin "must say why". That is worth nothing
// if an empty Error satisfies them.
func ValidateError(e *Error, at string) []Violation {
	if e == nil {
		return missingRecord(at)
	}
	var vs []Violation
	if e.GetCode() == ErrorCode_ERROR_CODE_UNSPECIFIED {
		vs = append(vs, unspecified(at+".code", "ErrorCode"))
	}
	if e.GetMessage() == "" {
		vs = append(vs, Violation{
			Field:   at + ".message",
			Rule:    ruleErrorMessage,
			Message: "an error must carry a human-readable message",
		})
	}
	return vs
}

// ValidateDiagnostic checks one Diagnostic. Diagnostics travel with the
// snapshot as evidence, so an empty one is a record that says nothing while
// looking like it says something.
func ValidateDiagnostic(d *Diagnostic) []Violation {
	if d == nil {
		return missingRecord("diagnostic")
	}
	var vs []Violation
	if d.GetSeverity() == Severity_SEVERITY_UNSPECIFIED {
		vs = append(vs, unspecified("diagnostic.severity", "Severity"))
	}
	if d.GetCode() == "" {
		vs = append(vs, Violation{
			Field: "diagnostic.code", Rule: ruleDiagnosticCode,
			Message: "a machine-readable code is required",
		})
	}
	if d.GetMessage() == "" {
		vs = append(vs, Violation{
			Field: "diagnostic.message", Rule: ruleDiagnosticMessage,
			Message: "a human-readable message is required",
		})
	}
	if d.GetScope() != nil {
		vs = append(vs, ValidateKey(d.GetScope(), "diagnostic.scope")...)
	}
	if d.GetSubject() != nil {
		vs = append(vs, ValidateKey(d.GetSubject(), "diagnostic.subject")...)
	}
	return vs
}

// ValidateDescribeResponse checks a plugin's self-description.
//
// The host degrades against what a plugin says it can do, so a description
// that is internally inconsistent is worse than one that claims little.
func ValidateDescribeResponse(d *DescribeResponse) []Violation {
	if d == nil {
		return missingRecord("describe")
	}
	var vs []Violation

	if d.GetKind() != Kind {
		vs = append(vs, Violation{
			Field: "describe.kind", Rule: ruleDescribeKind,
			Message: fmt.Sprintf("this contract is %q, not %q", Kind, d.GetKind()),
		})
	}
	if d.GetProtocolVersion() != ProtocolVersion {
		vs = append(vs, Violation{
			Field: "describe.protocol_version", Rule: ruleDescribeVersion,
			Message: fmt.Sprintf("this contract is version %d, not %d", ProtocolVersion, d.GetProtocolVersion()),
		})
	}
	if d.GetName() == "" {
		vs = append(vs, Violation{
			Field: "describe.name", Rule: ruleDescribeName,
			Message: "a plugin must name itself",
		})
	}

	for i, l := range d.GetLimitations() {
		at := fmt.Sprintf("describe.limitations[%d]", i)
		if l.GetCode() == "" {
			vs = append(vs, Violation{Field: at + ".code", Rule: ruleLimitationCode,
				Message: "a limitation needs a machine-readable code"})
		}
		if l.GetSummary() == "" {
			vs = append(vs, Violation{Field: at + ".summary", Rule: ruleLimitationSummary,
				Message: "a limitation needs a summary a reviewer can read"})
		}
	}

	caps := d.GetCapabilities()
	if caps == nil {
		return append(vs, Violation{
			Field: "describe.capabilities", Rule: ruleDescribeCaps,
			Message: "capabilities are required; the host degrades against them rather than assuming",
		})
	}

	coarse := false
	for i, f := range caps.GetFidelities() {
		if f == Fidelity_FIDELITY_UNSPECIFIED {
			vs = append(vs, unspecified(fmt.Sprintf("describe.capabilities.fidelities[%d]", i), "Fidelity"))
		}
		if f == Fidelity_FIDELITY_COARSE {
			coarse = true
		}
	}
	for i, t := range caps.GetNodeTypes() {
		if t == NodeType_NODE_TYPE_UNSPECIFIED {
			vs = append(vs, unspecified(fmt.Sprintf("describe.capabilities.node_types[%d]", i), "NodeType"))
		}
	}
	for i, t := range caps.GetEdgeTypes() {
		if t == EdgeType_EDGE_TYPE_UNSPECIFIED {
			vs = append(vs, unspecified(fmt.Sprintf("describe.capabilities.edge_types[%d]", i), "EdgeType"))
		}
	}

	// A coarse entitlement model is a limit on what the data means. It belongs
	// in the contract, not only in the plugin's README where a reader has to
	// go looking for it.
	if coarse && len(d.GetLimitations()) == 0 {
		vs = append(vs, Violation{
			Field: "describe.limitations", Rule: ruleCoarseLimitation,
			Message: "declaring FIDELITY_COARSE requires declaring what it means for this source",
		})
	}
	// "I have activity data" without naming a signal is not a claim a consumer
	// can render or a reviewer can weigh.
	if caps.GetActivity() && len(d.GetActivitySignals()) == 0 {
		vs = append(vs, Violation{
			Field: "describe.activity_signals", Rule: ruleActivitySignals,
			Message: "declaring activity requires declaring at least one signal",
		})
	}
	return vs
}

// ValidateTestConnectionResponse checks a reachability probe.
func ValidateTestConnectionResponse(r *TestConnectionResponse) []Violation {
	if r == nil {
		return missingRecord("test_connection")
	}
	var vs []Violation
	for i, p := range r.GetScopes() {
		at := fmt.Sprintf("test_connection.scopes[%d]", i)
		vs = append(vs, ValidateKey(p.GetScope(), at+".scope")...)
		if p.GetName() == "" {
			vs = append(vs, Violation{Field: at + ".name", Rule: ruleScopeProbeName,
				Message: "a scope needs a human name; the operator picks from this list"})
		}
		if !p.GetReachable() {
			if p.GetError() == nil {
				vs = append(vs, Violation{Field: at + ".error", Rule: ruleScopeProbeError,
					Message: "an unreachable scope must say why; the operator has to fix something"})
			} else {
				vs = append(vs, ValidateError(p.GetError(), at+".error")...)
			}
		}
	}
	for i, d := range r.GetDiagnostics() {
		for _, v := range ValidateDiagnostic(d) {
			v.Field = fmt.Sprintf("test_connection.diagnostics[%d]", i) + strings.TrimPrefix(v.Field, "diagnostic")
			vs = append(vs, v)
		}
	}
	return vs
}

// ValidateRevokeResponse checks a revocation result. Collectors answer
// REVOKE_OUTCOME_NOT_SUPPORTED; that the shape is checked now is what makes a
// later implementation not a contract change.
func ValidateRevokeResponse(r *RevokeResponse) []Violation {
	if r == nil {
		return missingRecord("revoke")
	}
	switch r.GetOutcome() {
	case RevokeOutcome_REVOKE_OUTCOME_UNSPECIFIED:
		return []Violation{unspecified("revoke.outcome", "RevokeOutcome")}
	case RevokeOutcome_REVOKE_OUTCOME_FAILED:
		if r.GetError() == nil {
			return []Violation{{
				Field: "revoke.error", Rule: ruleRevokeError,
				Message: "a failed revocation must say why; a write-back that silently did nothing is the worst outcome",
			}}
		}
		return ValidateError(r.GetError(), "revoke.error")
	}
	return nil
}

// ValidateConfigIssues checks the findings ValidateConfig returned.
func ValidateConfigIssues(issues []*ConfigIssue) []Violation {
	var vs []Violation
	for i, issue := range issues {
		at := fmt.Sprintf("config_issue[%d]", i)
		if issue.GetSeverity() == Severity_SEVERITY_UNSPECIFIED {
			vs = append(vs, unspecified(at+".severity", "Severity"))
		}
		if issue.GetCode() == "" {
			vs = append(vs, Violation{Field: at + ".code", Rule: ruleConfigCode,
				Message: "a machine-readable code is required"})
		}
		if issue.GetMessage() == "" {
			vs = append(vs, Violation{Field: at + ".message", Rule: ruleConfigMessage,
				Message: "a human-readable message is required"})
		}
		// The empty string addresses the whole document; anything else must be
		// a JSON Pointer, because that is what a CLI resolves against the
		// config it is holding.
		if f := issue.GetField(); f != "" && !strings.HasPrefix(f, "/") {
			vs = append(vs, Violation{Field: at + ".field", Rule: ruleConfigPointer,
				Message: fmt.Sprintf("%q is not an RFC 6901 JSON Pointer", f)})
		}
	}
	return vs
}

// ValidateProbeCapabilities checks probes against what the plugin said it can
// do. It is separate from ValidateTestConnectionResponse because it is not a
// record-level rule: it needs the Describe response as well, which only the
// host has.
//
// The rule it enforces is the one the contract states and nothing else could:
// a plugin that claims activity must say, per scope, whether that scope has
// it. Left unset, the enum reads as unavailable, and a pre-flight check tells
// an operator that a realm which works fine cannot answer.
func ValidateProbeCapabilities(scopes []*ScopeProbe, caps *Capabilities) []Violation {
	var vs []Violation
	for i, p := range scopes {
		at := fmt.Sprintf("test_connection.scopes[%d]", i)
		if caps.GetActivity() && p.GetReachable() &&
			p.GetActivity() == ActivityAvailability_ACTIVITY_AVAILABILITY_UNSPECIFIED {
			vs = append(vs, Violation{
				Field: at + ".activity",
				Rule:  ruleProbeActivityRequired,
				Message: "this collector declares activity, so each reachable scope must say " +
					"whether it has any; unset reads as unavailable",
			})
		}
		if p.GetActivity() == ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE && p.GetActivityNote() != "" {
			vs = append(vs, Violation{
				Field: at + ".activity_note",
				Rule:  ruleProbeNoteContradicts,
				Message: "a scope that has activity data must not also explain why it has none; " +
					"a reader cannot tell which half is true",
			})
		}
	}
	return vs
}
