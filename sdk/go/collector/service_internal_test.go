package collector

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// "Wait" and "go and change something" are different instructions. A
// collector that knows which it is must be able to say so, or every failure
// reaches the operator as an undifferentiated source error and the CLI's
// "this may clear on its own" never appears for anything.
func TestACollectorsErrorKeepsWhatItKnowsAboutRetrying(t *testing.T) {
	for _, c := range []struct {
		name  string
		err   error
		code  collectorv1.ErrorCode
		retry bool
		after time.Duration
	}{
		{"a plain error", errors.New("something went wrong"),
			collectorv1.ErrorCode_ERROR_CODE_SOURCE_ERROR, false, 0},
		{"a permission", sourceErr{fault: FaultPermission},
			collectorv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, false, 0},
		{"a rejected credential", sourceErr{fault: FaultAuth},
			collectorv1.ErrorCode_ERROR_CODE_AUTHENTICATION_FAILED, false, 0},
		{"an unwell source", sourceErr{fault: FaultUnavailable, retry: true},
			collectorv1.ErrorCode_ERROR_CODE_SOURCE_UNAVAILABLE, true, 0},
		// The two questions are separate. A rate limit that named no delay is
		// still a rate limit, and an outage that named one is still an
		// outage: inferring the kind from the delay gets both wrong.
		{"a rate limit that named no wait", sourceErr{fault: FaultRateLimited, retry: true},
			collectorv1.ErrorCode_ERROR_CODE_RATE_LIMITED, true, 0},
		{"an outage that named a wait", sourceErr{
			fault: FaultUnavailable, retry: true, after: 30 * time.Second},
			collectorv1.ErrorCode_ERROR_CODE_SOURCE_UNAVAILABLE, true, 30 * time.Second},
		// A source can be unavailable and hopeless.
		{"an outage worth no retry", sourceErr{fault: FaultUnavailable},
			collectorv1.ErrorCode_ERROR_CODE_SOURCE_UNAVAILABLE, false, 0},
		// Wrapped, because a collector wraps its errors on the way out and
		// an interface check that only sees the outermost one is no check.
		{"wrapped", fmt.Errorf("reading realm acme: %w",
			sourceErr{fault: FaultUnavailable, retry: true}),
			collectorv1.ErrorCode_ERROR_CODE_SOURCE_UNAVAILABLE, true, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := asError(c.err)
			if got.GetCode() != c.code {
				t.Errorf("Code = %v, want %v", got.GetCode(), c.code)
			}
			if got.GetRetryable() != c.retry {
				t.Errorf("Retryable = %v, want %v", got.GetRetryable(), c.retry)
			}
			if got.GetRetryAfter().AsDuration() != c.after {
				t.Errorf("RetryAfter = %v, want %v", got.GetRetryAfter().AsDuration(), c.after)
			}
		})
	}
}

type sourceErr struct {
	fault Fault
	retry bool
	after time.Duration
}

func (e sourceErr) Error() string                   { return "source said no" }
func (e sourceErr) Fault() Fault                    { return e.fault }
func (e sourceErr) CanRetry() (bool, time.Duration) { return e.retry, e.after }

// The contract asks a collector to emit something at least this often so a
// caller can tell "slow" from "stuck". A collector that never sees the number
// cannot honour it, and the doc telling it to would be asking for the
// impossible.
func TestTheHeartbeatIntervalReachesTheCollector(t *testing.T) {
	var got CollectRequest
	svc := &service{impl: collectorFunc(func(_ context.Context, req CollectRequest, _ Stream) error {
		got = req
		return nil
	})}

	err := svc.Collect(&collectorv1.CollectRequest{
		Config:            []byte(`{}`),
		HeartbeatInterval: durationpb.New(45 * time.Second),
	}, &discardStream{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got.Heartbeat != 45*time.Second {
		t.Errorf("Heartbeat = %v, want 45s", got.Heartbeat)
	}
}

// collectorFunc is a Collector that is only its Collect method, for the tests
// that are about what the service hands it.
type collectorFunc func(context.Context, CollectRequest, Stream) error

func (f collectorFunc) Describe(context.Context) (*Description, error) {
	return &Description{Name: "fake", Version: "0.0.0"}, nil
}

func (f collectorFunc) ValidateConfig(context.Context, []byte) ([]Issue, error) { return nil, nil }

func (f collectorFunc) TestConnection(context.Context, []byte) ([]ScopeProbe, error) {
	return nil, nil
}

func (f collectorFunc) Collect(ctx context.Context, req CollectRequest, out Stream) error {
	return f(ctx, req, out)
}

// discardStream is the gRPC side, which these tests do not look at.
type discardStream struct {
	collectorv1.CollectorService_CollectServer
}

func (d *discardStream) Send(*collectorv1.CollectResponse) error { return nil }

func (d *discardStream) Context() context.Context { return context.Background() }

// A cursor this build cannot use and a configuration it cannot accept each
// have their own code in the contract. Reported as a source error they send
// an operator to look at a source that did nothing wrong.
func TestACursorAndAConfigFailureAreNotSourceErrors(t *testing.T) {
	for _, c := range []struct {
		fault Fault
		want  collectorv1.ErrorCode
	}{
		{FaultInvalidCursor, collectorv1.ErrorCode_ERROR_CODE_INVALID_CURSOR},
		{FaultConfig, collectorv1.ErrorCode_ERROR_CODE_INVALID_CONFIG},
	} {
		if got := asError(sourceErr{fault: c.fault}).GetCode(); got != c.want {
			t.Errorf("Fault %v -> %v, want %v", c.fault, got, c.want)
		}
	}
}

// The code and the cause are two statements of the same fact, and a collector
// that keeps them in step by hand eventually does not.
func TestTheCauseFollowsTheFault(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want collectorv1.IncompleteCause
	}{
		{"a plain error", errors.New("something"), SourceFailed},
		{"a config the collector cannot use", BadConfig(errors.New("bad")), InvalidConfig},
		{"a rate limit", sourceErr{fault: FaultRateLimited}, RateLimited},
		{"a cursor this build cannot read", BadCursor(errors.New("bad")), InvalidCursor},
		{"a permission", sourceErr{fault: FaultPermission}, SourceFailed},
		{"wrapped", fmt.Errorf("dialling: %w", BadConfig(errors.New("bad"))), InvalidConfig},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := CauseFor(c.err); got != c.want {
				t.Errorf("CauseFor = %v, want %v", got, c.want)
			}
		})
	}
}

// The two markers carry their message and their cause through a wrap.
func TestTheFaultMarkersKeepWhatTheyWere(t *testing.T) {
	inner := errors.New("the document has no base_url")
	for _, c := range []struct {
		marked error
		want   collectorv1.ErrorCode
	}{
		{BadConfig(inner), collectorv1.ErrorCode_ERROR_CODE_INVALID_CONFIG},
		{BadCursor(inner), collectorv1.ErrorCode_ERROR_CODE_INVALID_CURSOR},
	} {
		if got := asError(c.marked).GetCode(); got != c.want {
			t.Errorf("code = %v, want %v", got, c.want)
		}
		if !errors.Is(c.marked, inner) {
			t.Error("the marker lost the error it wrapped")
		}
		if c.marked.Error() != inner.Error() {
			t.Errorf("message = %q, want %q", c.marked.Error(), inner.Error())
		}
	}
}

// "The source records nothing for this scope" and "the read that would have
// told us never completed" are different things to put in front of an
// operator: one sends them to switch something on, the other to check a
// credential. The zero value says the first, so a scope that failed before
// anyone asked has to be able to say the second.
func TestAScopeCanSayItCouldNotFindOut(t *testing.T) {
	for _, c := range []struct {
		name   string
		result ScopeResult
		want   collectorv1.ActivityAvailability
	}{
		{"it answers", ScopeResult{ActivityAvailable: true},
			collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE},
		{"it records nothing", ScopeResult{},
			collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNAVAILABLE},
		{"nobody could ask", ScopeResult{ActivityUndetermined: true},
			collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNDETERMINED},
		// Undetermined wins: a collector that set both has not found out.
		{"both", ScopeResult{ActivityAvailable: true, ActivityUndetermined: true},
			collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNDETERMINED},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scopeAvailability(c.result); got != c.want {
				t.Errorf("availability = %v, want %v", got, c.want)
			}
		})
	}
}
