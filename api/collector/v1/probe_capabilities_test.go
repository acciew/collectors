package collectorv1_test

import (
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

func caps(activity bool) *collectorv1.Capabilities {
	return &collectorv1.Capabilities{Activity: activity}
}

func probe(reachable bool, a collectorv1.ActivityAvailability) *collectorv1.ScopeProbe {
	return &collectorv1.ScopeProbe{
		Scope:     &collectorv1.Key{Scope: "r", Type: collectorv1.NodeType_NODE_TYPE_SCOPE, Id: "r"},
		Name:      "r",
		Reachable: reachable,
		Activity:  a,
	}
}

// The contract says activity is required on a probe when the plugin claims
// the capability. Nothing checked it, so a plugin could declare activity and
// then leave every probe unset, and the answer read as "unavailable" — the
// pre-flight check telling an operator their working realm cannot answer.
func TestAPluginClaimingActivityMustSayWhetherEachScopeHasIt(t *testing.T) {
	vs := collectorv1.ValidateProbeCapabilities(
		[]*collectorv1.ScopeProbe{probe(true, collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNSPECIFIED)},
		caps(true))
	if len(vs) != 1 {
		t.Fatalf("violations = %v, want exactly one", vs)
	}
	if !strings.Contains(vs[0].Field, "activity") {
		t.Errorf("the violation does not name the field: %+v", vs[0])
	}
}

func TestAPluginWithNoActivityCapabilityMayLeaveProbesUnset(t *testing.T) {
	vs := collectorv1.ValidateProbeCapabilities(
		[]*collectorv1.ScopeProbe{probe(true, collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNSPECIFIED)},
		caps(false))
	if len(vs) != 0 {
		t.Errorf("violations = %v, want none", vs)
	}
}

// An unreachable scope was never asked about activity, so demanding an answer
// would force a plugin to invent one.
func TestAnUnreachableScopeNeedNotAnswerAboutActivity(t *testing.T) {
	vs := collectorv1.ValidateProbeCapabilities(
		[]*collectorv1.ScopeProbe{probe(false, collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNSPECIFIED)},
		caps(true))
	if len(vs) != 0 {
		t.Errorf("violations = %v, want none", vs)
	}
}

// A note explaining why activity is missing, on a scope that says activity is
// present, is a contradiction: one of the two is wrong and a reader cannot
// tell which.
func TestANoteOnAnAvailableScopeIsAContradiction(t *testing.T) {
	p := probe(true, collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE)
	p.ActivityNote = "event storage is off"
	vs := collectorv1.ValidateProbeCapabilities([]*collectorv1.ScopeProbe{p}, caps(true))
	if len(vs) != 1 {
		t.Fatalf("violations = %v, want exactly one", vs)
	}
}

func TestAnAnsweredProbeIsFine(t *testing.T) {
	p := probe(true, collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNAVAILABLE)
	p.ActivityNote = "event storage is off for this realm"
	vs := collectorv1.ValidateProbeCapabilities([]*collectorv1.ScopeProbe{p}, caps(true))
	if len(vs) != 0 {
		t.Errorf("violations = %v, want none", vs)
	}
}
