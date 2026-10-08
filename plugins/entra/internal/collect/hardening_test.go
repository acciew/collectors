package collect_test

import (
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

// Whatever a tenant calls things, a message the collector writes is text, and
// text that is not valid UTF-8 cannot be sent: the host would get a transport
// error where it should get the verdict.
func TestNothingATenantNamesThingsCanMakeAnInvalidMessage(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	alphabet := []rune("abc XYZ 019 -_ éüñ 経理部 日本語 العربية Ελληνικά 😀🏢🔥 \u200d")
	names := []string{"a" + strings.Repeat("経理", 128)}
	for i := range 40 {
		n := 1 + rng.Intn(400)
		name := make([]rune, n)
		for j := range name {
			name[j] = alphabet[rng.Intn(len(alphabet))]
		}
		names = append(names, string(name))
		_ = i
	}

	for i, name := range names {
		d := directory()
		d.Groups[0].DisplayName = name
		d.Groups[0].Visibility = "HiddenMembership"
		d.Groups[0].Members[0].IDOnly = true
		w := newWorld(t, d)
		w.srv.Refuse("/v1.0/groups/"+engineering+"/members", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
		out, err := w.run("", collector.CollectRequest{})
		inc := incomplete(t, err)

		check := func(what, text string) {
			t.Helper()
			if !utf8.ValidString(text) {
				t.Fatalf("name %d: %s is not valid UTF-8: %q", i, what, text)
			}
		}
		check("the completion error", err.Error())
		check("the cursor", string(inc.ResumeFrom))
		sent := &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_SOURCE_ERROR, Message: err.Error()}
		if _, mErr := proto.Marshal(sent); mErr != nil {
			t.Fatalf("name %d: the completion error cannot be sent: %v", i, mErr)
		}
		for _, e := range out.events {
			if _, mErr := proto.Marshal(e); mErr != nil {
				t.Fatalf("name %d: an event cannot be sent: %v", i, mErr)
			}
		}
		for _, diag := range out.diags {
			check("a diagnostic", diag.GetMessage())
		}
	}
}

// A refused permission stays a refused permission when it is carried, so the
// host is told to grant it and not that the source failed.
func TestAProblemKeepsItsKindWhenItIsCarried(t *testing.T) {
	w := hiddenEngineering(t)
	_, err := w.run(noApplications, collector.CollectRequest{})
	first := incomplete(t, err)

	var faulty interface{ Fault() collector.Fault }
	if !errors.As(first.Err, &faulty) || faulty.Fault() != collector.FaultPermission {
		t.Errorf("the stream that found it says %v (%T), want a permission failure", first.Err, first.Err)
	}
	_, err = w.run(noApplications, collector.CollectRequest{ResumeFrom: first.ResumeFrom})
	second := incomplete(t, err)
	if !errors.As(second.Err, &faulty) || faulty.Fault() != collector.FaultPermission {
		t.Errorf("the stream that resumed from it says %v, want a permission failure too", second.Err)
	}
}

// A throttle on the probe is the stream being slowed down, not the tenant
// being unable to answer. Deciding "undetermined" on it would cost the whole
// collection its sign-in data for a glitch.
func TestAThrottledActivityProbeStopsTheStreamAndDecidesNothing(t *testing.T) {
	w := newWorld(t, signedIn())
	w.srv.Throttle("/v1.0/users", collect.ThrottleRetries+1, 1)
	out, err := w.run("", collector.CollectRequest{})

	inc := incomplete(t, err)
	if inc.Cause != collector.RateLimited {
		t.Fatalf("cause = %v, want rate limited", inc.Cause)
	}
	// What the stopped stream says of the scope is that it could not find out;
	// the zero value of the answer is "available", which it did not find.
	if s := out.scopes[0]; s.ActivityAvailable || !s.ActivityUndetermined {
		t.Errorf("scope = %+v, want activity undetermined for the stream the throttle stopped", s)
	}
	// Records were sent before the probe, so the stream already had a point to
	// resume from; the SDK refuses to complete one that did not.
	if len(out.checkpoints) == 0 {
		t.Error("the probe stopped a stream that had offered no checkpoint")
	}
	if out.diag("entra.activity.undetermined") != nil {
		t.Error("a throttle was reported as the tenant being unable to answer")
	}

	// Nothing had been read, so the resume is a whole collection.
	rest, err := w.run("", collector.CollectRequest{ResumeFrom: inc.ResumeFrom})
	if err != nil {
		t.Fatalf("the resume after the throttle: %v", err)
	}
	if rest.activities(alice)["successful_sign_in"].GetSeen() == nil || !rest.scopes[0].ActivityAvailable {
		t.Errorf("the resume after the throttle read no sign-in data: %+v", rest.scopes[0])
	}
}

// A loop of two pages looks different on every page, so a stream that reads
// one page each time and forgets could go round for ever.
func TestPagesThatGoRoundInACircleEndTheReadEvenWhenEveryStreamReadsOne(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Intercept("/v1.0/users", func(rw http.ResponseWriter, r *http.Request) bool {
		q := r.URL.Query()
		if r.URL.Path != "/v1.0/users" || q.Get("$top") == "1" {
			return false // the probe, and anything else
		}
		next := *r.URL
		nq := next.Query()
		switch q.Get("$skiptoken") {
		case "":
			nq.Set("$skiptoken", "b")
		case "b":
			nq.Set("$skiptoken", "c")
		default:
			nq.Set("$skiptoken", "b") // round again
		}
		next.RawQuery = nq.Encode()
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{"value": []any{}, "@odata.nextLink": w.srv.URL + next.RequestURI()})
		return true
	})

	var cursor []byte
	var last *collector.Incomplete
	for i := 0; i < 40; i++ {
		_, err := w.run(`{"service_principals":false,"app_roles":false,"pim":false}`,
			collector.CollectRequest{MaxRecords: 1, ResumeFrom: cursor})
		last = incomplete(t, err)
		if last.Cause != collector.BudgetExhausted {
			break
		}
		cursor = last.ResumeFrom
	}
	if last.Cause == collector.BudgetExhausted {
		t.Fatal("forty streams of one page each never noticed the pages went round")
	}
	if last.Err == nil || !strings.Contains(last.Err.Error(), "same page link") {
		t.Errorf("the chain ended %v: %v, want the repeated link named", last.Cause, last.Err)
	}
}

// A throttle on the read that settles whether a type of member can be read is a
// throttle like any other, and ends the stream when it will not pass, instead of
// being taken for a type that is fine.
func TestAThrottleOnThePermissionCheckThatNeverEndsStopsTheStream(t *testing.T) {
	d := directory()
	d.Groups[0].Members[0].IDOnly = true // alice, in Engineering
	w := newWorld(t, d)
	w.srv.Throttle("/v1.0/users/"+alice, 100, 1)
	out, err := w.run("", collector.CollectRequest{})

	if inc := incomplete(t, err); inc.Cause != collector.RateLimited {
		t.Fatalf("cause = %v, want rate limited", inc.Cause)
	}
	if out.scopes[0].Status == collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Error("a stream stopped by a throttle reported its scope collected")
	}
}
