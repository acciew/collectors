package collector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// service adapts a Collector to the wire contract. It is the only place in
// the SDK that knows the contract's shape, which is what lets a plugin author
// work in the types above and never see a protobuf message they did not build
// with a constructor.
type service struct {
	collectorv1.UnimplementedCollectorServiceServer
	impl Collector
}

func (s *service) Describe(ctx context.Context, _ *collectorv1.DescribeRequest) (*collectorv1.DescribeResponse, error) {
	d, err := s.impl.Describe(ctx)
	if err != nil {
		return nil, err
	}
	out := &collectorv1.DescribeResponse{
		Kind:            collectorv1.Kind,
		ProtocolVersion: collectorv1.ProtocolVersion,
		Name:            d.Name,
		Version:         d.Version,
		Description:     d.Description,
		Capabilities: &collectorv1.Capabilities{
			Activity: d.Activity,
			// Collectors declare no revocation yet. The conformance suite
			// fails a plugin that says otherwise, and the SDK does not offer
			// a way to claim it.
			Revoke:     false,
			Fidelities: d.Fidelities,
			NodeTypes:  d.NodeTypes,
			EdgeTypes:  d.EdgeTypes,
		},
	}
	for _, l := range d.Limitations {
		out.Limitations = append(out.Limitations, &collectorv1.Limitation{
			Code: l.Code, Summary: l.Summary, DetailUrl: l.DetailURL,
		})
	}
	for _, sig := range d.Signals {
		out.ActivitySignals = append(out.ActivitySignals, &collectorv1.ActivitySignal{
			Name: sig.Name, Description: sig.Description,
			TypicalLag: durationpb.New(sig.TypicalLag),
		})
	}
	// Fail here rather than let the host reject it: the plugin author gets a
	// message naming the field, and their own tests catch it.
	if vs := collectorv1.ValidateDescribeResponse(out); len(vs) > 0 {
		return nil, fmt.Errorf("Describe is not a valid description: %s", vs[0])
	}
	return out, nil
}

func (s *service) ValidateConfig(ctx context.Context, req *collectorv1.ValidateConfigRequest) (*collectorv1.ValidateConfigResponse, error) {
	issues, err := s.impl.ValidateConfig(ctx, req.GetConfig())
	if err != nil {
		return nil, err
	}
	out := &collectorv1.ValidateConfigResponse{}
	for _, i := range issues {
		out.Issues = append(out.Issues, &collectorv1.ConfigIssue{
			Field: i.Field, Severity: i.Severity, Code: i.Code, Message: i.Message,
		})
	}
	if vs := collectorv1.ValidateConfigIssues(out.GetIssues()); len(vs) > 0 {
		return nil, fmt.Errorf("ValidateConfig returned a malformed issue: %s", vs[0])
	}
	return out, nil
}

func (s *service) TestConnection(ctx context.Context, req *collectorv1.TestConnectionRequest) (*collectorv1.TestConnectionResponse, error) {
	probes, err := s.impl.TestConnection(ctx, req.GetConfig())
	if err != nil {
		return nil, err
	}
	out := &collectorv1.TestConnectionResponse{}
	for _, p := range probes {
		probe := &collectorv1.ScopeProbe{
			Scope: p.Scope, Name: p.Name, Reachable: p.Reachable,
			Activity: probeAvailability(p), ActivityNote: p.ActivityNote,
		}
		if p.Err != nil {
			probe.Error = asError(p.Err)
		}
		out.Scopes = append(out.Scopes, probe)
	}
	if vs := collectorv1.ValidateTestConnectionResponse(out); len(vs) > 0 {
		return nil, fmt.Errorf("TestConnection returned a malformed probe: %s", vs[0])
	}
	return out, nil
}

// Revoke is declared and not implemented. Every collector answers the same way,
// so the SDK answers for it and nobody has to write it.
func (s *service) Revoke(context.Context, *collectorv1.RevokeRequest) (*collectorv1.RevokeResponse, error) {
	return &collectorv1.RevokeResponse{
		Outcome: collectorv1.RevokeOutcome_REVOKE_OUTCOME_NOT_SUPPORTED,
	}, nil
}

func (s *service) Collect(req *collectorv1.CollectRequest, srv collectorv1.CollectorService_CollectServer) error {
	out := &stream{srv: srv}
	err := s.impl.Collect(srv.Context(), CollectRequest{
		Config:      req.GetConfig(),
		Scopes:      req.GetScopes(),
		ResumeFrom:  req.GetResumeFrom().GetToken(),
		MaxRecords:  req.GetBudget().GetMaxRecords(),
		MaxDuration: req.GetBudget().GetMaxDuration().AsDuration(),
		Heartbeat:   req.GetHeartbeatInterval().AsDuration(),
	}, out)

	// The completion marker is the SDK's job, not the plugin author's. It has
	// to be exactly one, exactly last, and its counts have to match what was
	// actually sent -- three rules that are easy to get wrong by hand and
	// impossible to get wrong if nobody writes them by hand.
	return out.finish(err)
}

// stream is the Stream a collector writes into. It validates every record
// before it goes out and counts what it sent, so the completion marker cannot
// disagree with the stream.
type stream struct {
	srv collectorv1.CollectorService_CollectServer

	mu       sync.Mutex
	counts   collectorv1.Counters
	scopes   []*collectorv1.ScopeOutcome
	checkpts int
	records  int
	done     bool
}

func (s *stream) Node(n *collectorv1.Node) error {
	if vs := collectorv1.ValidateNode(n); len(vs) > 0 {
		return fmt.Errorf("invalid node: %s", vs[0])
	}
	s.mu.Lock()
	s.records++
	s.counts.CountNode(n)
	s.mu.Unlock()
	return s.send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Node{Node: n}})
}

func (s *stream) Edge(e *collectorv1.Edge) error {
	if vs := collectorv1.ValidateEdge(e); len(vs) > 0 {
		return fmt.Errorf("invalid edge: %s", vs[0])
	}
	s.mu.Lock()
	s.records++
	s.counts.Edges++
	s.mu.Unlock()
	return s.send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Edge{Edge: e}})
}

func (s *stream) Activity(a *collectorv1.Activity) error {
	if vs := collectorv1.ValidateActivity(a); len(vs) > 0 {
		return fmt.Errorf("invalid activity: %s", vs[0])
	}
	s.mu.Lock()
	s.records++
	s.counts.Activities++
	s.mu.Unlock()
	return s.send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Activity{Activity: a}})
}

func (s *stream) Checkpoint(cursor []byte) error {
	s.mu.Lock()
	s.checkpts++
	s.mu.Unlock()
	return s.send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Checkpoint{
		Checkpoint: &collectorv1.Checkpoint{Cursor: &collectorv1.Cursor{Token: cursor}},
	}})
}

func (s *stream) Progress(phase string, rl *RateLimit) error {
	p := &collectorv1.Progress{Phase: phase}
	s.mu.Lock()
	counts := s.counts
	s.mu.Unlock()
	p.Counts = counts.Proto()
	if rl != nil {
		p.RateLimit = &collectorv1.RateLimit{
			Remaining: rl.Remaining, Limit: rl.Limit,
			RetryAfter: durationpb.New(rl.RetryAfter),
		}
		if !rl.ResetsAt.IsZero() {
			p.RateLimit.ResetsAt = timestamppb.New(rl.ResetsAt)
		}
	}
	return s.send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Progress{Progress: p}})
}

func scopeAvailability(r ScopeResult) collectorv1.ActivityAvailability {
	if r.ActivityUndetermined {
		return collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNDETERMINED
	}
	return availability(r.ActivityAvailable)
}

func (s *stream) ScopeDone(r ScopeResult) error {
	outcome := &collectorv1.ScopeOutcome{
		Scope: r.Scope, Status: r.Status, Activity: scopeAvailability(r),
	}
	if r.Err != nil {
		outcome.Error = asError(r.Err)
	}
	s.mu.Lock()
	s.scopes = append(s.scopes, outcome)
	s.mu.Unlock()
	return nil
}

func (s *stream) Diagnostic(severity collectorv1.Severity, code, message string) error {
	d := &collectorv1.Diagnostic{Severity: severity, Code: code, Message: message}
	if vs := collectorv1.ValidateDiagnostic(d); len(vs) > 0 {
		return fmt.Errorf("invalid diagnostic: %s", vs[0])
	}
	return s.send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Diagnostic{Diagnostic: d}})
}

func (s *stream) send(e *collectorv1.CollectResponse) error {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return fmt.Errorf("the completion marker has already been sent; nothing may follow it")
	}
	s.mu.Unlock()
	return s.srv.Send(e)
}

// finish writes the one completion marker, derived from what was actually
// sent rather than from what the plugin believes it sent.
func (s *stream) finish(collectErr error) error {
	s.mu.Lock()
	counts, scopes, checkpts, records := s.counts, s.scopes, s.checkpts, s.records
	s.done = true
	s.mu.Unlock()

	done := &collectorv1.Completion{Counts: counts.Proto(), Scopes: scopes}

	inc, incomplete := AsIncomplete(collectErr)
	switch {
	case collectErr == nil:
		done.Verdict = collectorv1.Verdict_VERDICT_COMPLETE
	case incomplete:
		done.Verdict = collectorv1.Verdict_VERDICT_INCOMPLETE
		done.Cause = inc.Cause
		if len(inc.ResumeFrom) > 0 {
			done.ResumeCursor = &collectorv1.Cursor{Token: inc.ResumeFrom}
		}
		if inc.Err != nil {
			done.Error = asError(inc.Err)
		}
	default:
		// The collector failed in a way it did not describe. That is a defect
		// in the plugin, and saying so is more useful than guessing at a
		// source problem.
		done.Verdict = collectorv1.Verdict_VERDICT_INCOMPLETE
		done.Cause = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PLUGIN_ERROR
		done.Error = asError(collectErr)
	}

	// Resume is mandatory. A stream that sent records and offered no way back
	// in cannot be resumed, and the host will reject it -- so catch it here,
	// where the author can still see which of their code paths did it.
	if records > 0 && checkpts == 0 {
		return fmt.Errorf(
			"collector emitted %d records without a checkpoint: call Stream.Checkpoint at least once so the host can resume", records)
	}
	if vs := collectorv1.ValidateCompletion(done); len(vs) > 0 {
		return fmt.Errorf("completion is invalid: %s", vs[0])
	}
	return s.srv.Send(&collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Completion{Completion: done},
	})
}

func availability(ok bool) collectorv1.ActivityAvailability {
	if ok {
		return collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE
	}
	return collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNAVAILABLE
}

// Retryable is implemented by a collector's error that knows whether trying
// again unchanged could succeed.
//
// "Wait" and "go and change something" are different instructions, and only
// the collector can tell them apart. Without this every failure arrived as a
// plain source error, so a rate limit and a missing role read the same to the
// person deciding what to do next.
type Retryable interface {
	// CanRetry says whether the same call could succeed later, and how long
	// the source asked us to wait — zero when it did not say.
	CanRetry() (bool, time.Duration)
}

// Fault is what kind of failure a collector's error is.
//
// A wait and a permission are different instructions, and so are a rejected
// credential and an unwell source. Inferring them from whether a retry delay
// was named gets it wrong both ways: a rate limit that names no delay is not
// an outage, and an outage that names one is not a rate limit.
type Fault int

const (
	// FaultSource is anything not covered below.
	FaultSource Fault = iota
	// FaultAuth means the credentials were rejected outright.
	FaultAuth
	// FaultPermission means the credentials were accepted and lack a right.
	FaultPermission
	// FaultRateLimited means the source asked us to slow down.
	FaultRateLimited
	// FaultUnavailable means the source could not be reached or is unwell.
	FaultUnavailable
	// FaultInvalidCursor means a resume cursor could not be used. For a
	// collector that refuses an unreadable cursor rather than starting over,
	// which is the other branch the contract allows.
	FaultInvalidCursor
	// FaultConfig means the configuration document is invalid for this
	// operation.
	FaultConfig
)

// Faulty is implemented by a collector's error that knows which it is.
type Faulty interface {
	// Fault classifies this failure.
	Fault() Fault
}

func asError(err error) *collectorv1.Error {
	out := &collectorv1.Error{
		Code:    collectorv1.ErrorCode_ERROR_CODE_SOURCE_ERROR,
		Message: err.Error(),
	}
	var faulty Faulty
	if errors.As(err, &faulty) {
		switch faulty.Fault() {
		case FaultAuth:
			out.Code = collectorv1.ErrorCode_ERROR_CODE_AUTHENTICATION_FAILED
		case FaultPermission:
			out.Code = collectorv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED
		case FaultRateLimited:
			out.Code = collectorv1.ErrorCode_ERROR_CODE_RATE_LIMITED
		case FaultUnavailable:
			out.Code = collectorv1.ErrorCode_ERROR_CODE_SOURCE_UNAVAILABLE
		case FaultInvalidCursor:
			out.Code = collectorv1.ErrorCode_ERROR_CODE_INVALID_CURSOR
		case FaultConfig:
			out.Code = collectorv1.ErrorCode_ERROR_CODE_INVALID_CONFIG
		case FaultSource:
		}
	}
	// Separately, because whether waiting helps is not the same question as
	// what went wrong: a source can be unavailable and hopeless, or rate
	// limited and name no delay at all.
	var again Retryable
	if errors.As(err, &again) {
		if can, after := again.CanRetry(); can {
			out.Retryable = true
			if after > 0 {
				out.RetryAfter = durationpb.New(after)
			}
		}
	}
	return out
}

// probeAvailability keeps "the source says no" and "we could not find out"
// apart. Both mean no activity data today; only one of them is fixed by
// changing something in the source.
func probeAvailability(p ScopeProbe) collectorv1.ActivityAvailability {
	if p.ActivityUndetermined {
		return collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNDETERMINED
	}
	return availability(p.ActivityAvailable)
}

// BadConfig marks an error as a configuration failure.
//
// The source was never reached, so reporting it as a source error sends an
// operator to look at something that did nothing wrong. Pair it with
// Incomplete{Cause: InvalidConfig}: the code reaches the wire, the cause
// reaches the person.
func BadConfig(err error) error { return &faultError{err, FaultConfig} }

// BadCursor marks an error as a resume cursor this build cannot use.
//
// For a collector that refuses an unreadable cursor rather than starting over,
// which is the other branch the contract allows. Pass the marked error to
// CauseFor for the completion cause; do not reach for PartialStream, which
// says a continuation arrived carrying part of the population when a refusal
// collected nothing at all.
func BadCursor(err error) error { return &faultError{err, FaultInvalidCursor} }

// faultError is an error that knows which kind of failure it is.
type faultError struct {
	err   error
	fault Fault
}

func (e *faultError) Error() string { return e.err.Error() }

func (e *faultError) Unwrap() error { return e.err }

func (e *faultError) Fault() Fault { return e.fault }

// CauseFor is the completion cause an error deserves, given how the collector
// classified it.
//
// The code and the cause are two statements of the same fact, and a collector
// that keeps them in step by hand eventually does not: the code says invalid
// config while the cause says source error, and the host reads the cause.
// Everything unclassified is a source failure, which is the honest default
// for an error that reached us from a source.
func CauseFor(err error) collectorv1.IncompleteCause {
	var faulty Faulty
	if !errors.As(err, &faulty) {
		return SourceFailed
	}
	switch faulty.Fault() {
	case FaultConfig:
		return InvalidConfig
	case FaultRateLimited:
		return RateLimited
	case FaultInvalidCursor:
		return InvalidCursor
	case FaultSource, FaultAuth, FaultPermission, FaultUnavailable:
	}
	return SourceFailed
}
