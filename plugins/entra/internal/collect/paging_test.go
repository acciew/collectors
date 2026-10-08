package collect_test

import (
	"context"
	"errors"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

func TestAThrottleIsWaitedOutAndReportedAsProgress(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Throttle("/v1.0/groups", 2, 3)
	var waits []time.Duration
	out := &capture{t: t}
	r := collect.Run{
		Graph: w.client, Config: config(t, ""), Now: func() time.Time { return now },
		Wait: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil },
	}
	if err := r.Collect(context.Background(), collector.CollectRequest{}, out); err != nil {
		t.Fatalf("a throttle that passes ended the collection: %v", err)
	}
	if len(waits) != 2 || waits[0] != 3*time.Second {
		t.Errorf("waited %v, want the 3 seconds Graph asked for, twice", waits)
	}
	if len(out.progress) != 2 || out.progress[0].RetryAfter != 3*time.Second {
		t.Errorf("progress = %+v, want the wait reported so a caller can tell slow from stuck", out.progress)
	}
	out.assertContract()
}

func TestAThrottleThatWillNotEndStopsTheStreamAndSaysHowLongToWait(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Throttle("/v1.0/groups", collect.ThrottleRetries+1, 3)
	var waited time.Duration
	out := &capture{t: t}
	r := collect.Run{
		Graph: w.client, Config: config(t, ""), Now: func() time.Time { return now },
		Wait: func(_ context.Context, d time.Duration) error { waited += d; return nil },
	}
	err := r.Collect(context.Background(), collector.CollectRequest{}, out)

	inc := incomplete(t, err)
	if inc.Cause != collector.RateLimited {
		t.Fatalf("cause = %v, want rate limited", inc.Cause)
	}
	var retry interface{ CanRetry() (bool, time.Duration) }
	if !errors.As(inc.Err, &retry) {
		t.Fatalf("the failure does not say whether waiting helps: %v", inc.Err)
	}
	if can, after := retry.CanRetry(); !can || after != 3*time.Second {
		t.Errorf("CanRetry = %v, %v; want true and the 3 seconds", can, after)
	}
	if waited != time.Duration(collect.ThrottleRetries)*3*time.Second {
		t.Errorf("waited %v in all", waited)
	}
	// What was read is kept, and what the throttle stopped is not reported whole.
	if out.node("", "NODE_TYPE_IDENTITY", alice) == nil {
		t.Error("the users read before the throttle were lost")
	}
	if len(inc.ResumeFrom) != 0 {
		t.Errorf("a cursor of %d bytes offered; there is nothing to resume", len(inc.ResumeFrom))
	}
	if out.scopes[0].Status == collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Error("a stream the throttle stopped reported its scope collected")
	}
}

// A wait of an hour is not a wait: the host decides when to come back, and the
// collector holds nothing open meanwhile.
func TestARetryAfterTooLongToWaitForEndsTheStreamAtOnce(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Throttle("/v1.0/groups", 1, 3600)
	var waits int
	out := &capture{t: t}
	r := collect.Run{
		Graph: w.client, Config: config(t, ""), Now: func() time.Time { return now },
		Wait: func(context.Context, time.Duration) error { waits++; return nil },
	}
	err := r.Collect(context.Background(), collector.CollectRequest{}, out)

	inc := incomplete(t, err)
	if inc.Cause != collector.RateLimited || waits != 0 {
		t.Errorf("cause = %v after %d waits, want rate limited at once", inc.Cause, waits)
	}
	var retry interface{ CanRetry() (bool, time.Duration) }
	if _, after := func() (bool, time.Duration) {
		if errors.As(inc.Err, &retry) {
			return retry.CanRetry()
		}
		return false, 0
	}(); after != time.Hour {
		t.Errorf("RetryAfter = %v, want the hour Graph asked for", after)
	}
}

// Nothing sends a Progress for a collector: one that goes quiet for an hour
// reading the members of a thousand groups has to say so itself. A checkpoint
// is an event too, so between pages the stream is already heard from; it is
// inside a page that the silence can be long.
func TestALongReadSaysItIsStillWorkingInsideAPage(t *testing.T) {
	w := newWorld(t, directory())
	clock := now
	out := &capture{t: t}
	r := collect.Run{
		Graph: w.client, Config: config(t, ""),
		// Every reading of the clock is twenty seconds on, longer than the
		// heartbeat asked for.
		Now:  func() time.Time { clock = clock.Add(20 * time.Second); return clock },
		Wait: func(context.Context, time.Duration) error { return nil },
	}
	if err := r.Collect(context.Background(), collector.CollectRequest{Heartbeat: 15 * time.Second}, out); err != nil {
		t.Fatal(err)
	}
	groups := 0
	for _, p := range out.phases {
		if p == "group_members" {
			groups++
		}
	}
	// The members part announces itself once, and each of four groups reads its
	// members.
	if groups < 5 {
		t.Errorf("%d progress events during the groups, want the part to keep saying it is working", groups)
	}
}
