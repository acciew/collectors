package collect_test

import (
	"errors"
	"testing"

	"go.acciew.io/collector/sdk/go/collector"
)

// The failures below are all the same failure: a collection that did not
// cover everything reporting that it did. They are the reason collect.All
// exists, and the first version of it reintroduced them one layer down.

// A realm that failed sat behind the cursor forever. The next run skipped it
// as "already covered", collected nothing, emitted no scope outcomes, and
// returned nil — which the host reads as a complete population of nobody.
func TestAResumeDoesNotSkipPastARealmThatFailed(t *testing.T) {
	boom := errors.New("keycloak said no")
	src := failingSource{fakeSource: realm(), failFor: "beta", err: boom}
	first := &capture{t: t}

	err := runAll(t, src, realmList("alpha", "beta", "gamma"),
		collector.CollectRequest{}, first)
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}

	// The second run is handed the cursor from the first, with Keycloak
	// healthy again.
	second := &capture{t: t}
	err = runAll(t, realm(), realmList("alpha", "beta", "gamma"),
		collector.CollectRequest{ResumeFrom: inc.ResumeFrom}, second)
	// Still incomplete: a resumed stream carries only the remainder.
	if resumed, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("the resumed run: %v", err)
	} else if resumed.Cause != collector.PartialStream {
		t.Errorf("cause = %v, want partial stream", resumed.Cause)
	}
	if got := second.scopeStatus()["beta"]; got != collector.Collected {
		t.Errorf("beta = %v after a resume; the realm that failed was never revisited", got)
	}
}

// A resume that covers nothing is not a complete collection of nothing. With
// no scope outcomes at all the host has no way to tell the two apart.
func TestAResumeThatCoversNothingSaysSoRatherThanReportingSuccess(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, realm(), realmList("alpha"),
		collector.CollectRequest{ResumeFrom: cursorFor("alpha")}, out)
	if err == nil {
		t.Fatal("a run that collected nothing returned success")
	}
}

// A realm that appears between two runs sorts wherever its name puts it. One
// sorting below the cursor would be skipped permanently.
func TestARealmThatAppearsAfterTheCursorIsStillCollected(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, realm(),
		realmList("alpha", "beta", "gamma"),
		collector.CollectRequest{ResumeFrom: cursorFor("alpha", "beta")}, out)
	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("All: %v", err)
	}
	if got := out.scopeStatus()["gamma"]; got != collector.Collected {
		t.Errorf("gamma = %v, want collected", got)
	}
}

// A collection where no realm completes emitted records and never a
// checkpoint. The SDK refuses to send a completion after that, so the host
// sees a truncated stream and loses the verdict and the data together. A
// single-realm Keycloak is the common deployment and hits this every time it
// fails partway.
func TestACollectionWhereEveryRealmFailsStillCheckpoints(t *testing.T) {
	boom := errors.New("keycloak said no")
	src := failingSource{fakeSource: realm(), failFor: "only", err: boom}
	out := &capture{t: t}

	err := runAll(t, src, realmList("only"),
		collector.CollectRequest{}, out)
	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if len(out.checkpoints) == 0 {
		t.Error("records were emitted with no checkpoint; the SDK will refuse to send the completion")
	}
}

// A budget stop that steps over a failed realm reported the budget as the
// cause and dropped the failure entirely.
func TestABudgetStopDoesNotSwallowARealmThatFailed(t *testing.T) {
	boom := errors.New("keycloak said no")
	src := failingSource{fakeSource: realm(), failFor: "alpha", err: boom}
	out := &capture{t: t}

	err := runAll(t, src, realmList("alpha", "beta"),
		collector.CollectRequest{MaxRecords: 1}, out)
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if inc.Err == nil {
		t.Error("the realm failure did not survive the budget stop")
	}
	if got := out.scopeStatus()["alpha"]; got != collector.Partial {
		t.Errorf("alpha = %v, want partial", got)
	}
}

// A cursor that no longer matches anything is the operator's realm list
// having changed, not a defect in the plugin. Reported as a plugin error it
// sends somebody to look in the wrong place.
func TestAStaleCursorIsNotReportedAsAPluginDefect(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, realm(), realmList("alpha"),
		collector.CollectRequest{ResumeFrom: []byte("{not json")}, out)

	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want an incomplete verdict rather than a bare error", err)
	}
	if inc.Cause == collector.SourceFailed && inc.Err == nil {
		t.Error("the reason did not survive")
	}
}
