package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// fakeServer stands in for the gRPC stream. Testing the adapter in process
// rather than through a subprocess is not a shortcut: the rules being checked
// here are the adapter's, and a subprocess would only add a way for the test
// to fail for reasons that have nothing to do with them.
type fakeServer struct {
	grpc.ServerStream
	sent []*collectorv1.CollectResponse
}

func (f *fakeServer) Send(e *collectorv1.CollectResponse) error {
	f.sent = append(f.sent, e)
	return nil
}
func (f *fakeServer) Context() context.Context { return context.Background() }

func (f *fakeServer) completion(t *testing.T) *collectorv1.Completion {
	t.Helper()
	if len(f.sent) == 0 {
		t.Fatal("nothing was sent")
	}
	last := f.sent[len(f.sent)-1].GetCompletion()
	if last == nil {
		t.Fatalf("the last event is not a completion: %T", f.sent[len(f.sent)-1].GetEvent())
	}
	return last
}

// fake is a collector whose Collect is whatever the test needs.
type fake struct {
	describe func() (*Description, error)
	collect  func(Stream) error
}

func (f *fake) Describe(context.Context) (*Description, error) {
	if f.describe != nil {
		return f.describe()
	}
	return &Description{
		Name: "fake", Version: "0.0.1", Description: "for tests",
		Fidelities: []collectorv1.Fidelity{Direct},
		NodeTypes:  []collectorv1.NodeType{collectorv1.NodeType_NODE_TYPE_IDENTITY},
		EdgeTypes:  []collectorv1.EdgeType{collectorv1.EdgeType_EDGE_TYPE_HOLDS},
	}, nil
}
func (f *fake) ValidateConfig(context.Context, []byte) ([]Issue, error) { return nil, nil }
func (f *fake) TestConnection(context.Context, []byte) ([]ScopeProbe, error) {
	return []ScopeProbe{{Scope: Scope("s", "s"), Name: "s", Reachable: true}}, nil
}
func (f *fake) Collect(_ context.Context, _ CollectRequest, out Stream) error {
	if f.collect != nil {
		return f.collect(out)
	}
	return nil
}

func run(t *testing.T, c Collector) (*fakeServer, error) {
	t.Helper()
	srv := &fakeServer{}
	err := (&service{impl: c}).Collect(&collectorv1.CollectRequest{}, srv)
	return srv, err
}

// The SDK writes the completion marker, not the plugin author. It has to be
// exactly one, exactly last, and its counts have to match what was sent --
// three rules that are easy to get wrong by hand and impossible to get wrong
// if nobody writes them by hand.
func TestTheCompletionIsDerivedFromWhatWasActuallySent(t *testing.T) {
	srv, err := run(t, &fake{collect: func(out Stream) error {
		if err := out.Node(Identity(IdentityKey("s", "u1"), "alice", "user", Human, Active)); err != nil {
			return err
		}
		if err := out.Node(Entitlement(EntitlementKey("s", "r1"), "admin", "role")); err != nil {
			return err
		}
		if err := out.Edge(Holds(IdentityKey("s", "u1"), EntitlementKey("s", "r1"), Direct)); err != nil {
			return err
		}
		if err := out.ScopeDone(ScopeResult{Scope: Scope("s", "s"), Status: Collected}); err != nil {
			return err
		}
		return out.Checkpoint([]byte("done"))
	}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	done := srv.completion(t)
	if done.GetVerdict() != collectorv1.Verdict_VERDICT_COMPLETE {
		t.Errorf("verdict = %v", done.GetVerdict())
	}
	counts := done.GetCounts()
	if counts.GetIdentities() != 1 || counts.GetEntitlements() != 1 || counts.GetEdges() != 1 {
		t.Errorf("counts = %+v", counts)
	}
	if done.GetCause() != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_UNSPECIFIED {
		t.Error("a complete collection carries no cause")
	}
}

func TestAnIncompleteCollectionCarriesItsCauseAndCursor(t *testing.T) {
	srv, err := run(t, &fake{collect: func(out Stream) error {
		if err := out.Node(Identity(IdentityKey("s", "u1"), "alice", "user", Human, Active)); err != nil {
			return err
		}
		if err := out.Checkpoint([]byte("page-2")); err != nil {
			return err
		}
		return &Incomplete{Cause: RateLimited, ResumeFrom: []byte("page-2"),
			Err: errors.New("secondary rate limit")}
	}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	done := srv.completion(t)
	if done.GetVerdict() != collectorv1.Verdict_VERDICT_INCOMPLETE {
		t.Errorf("verdict = %v", done.GetVerdict())
	}
	if done.GetCause() != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_RATE_LIMITED {
		t.Errorf("cause = %v", done.GetCause())
	}
	if string(done.GetResumeCursor().GetToken()) != "page-2" {
		t.Errorf("cursor = %q", done.GetResumeCursor().GetToken())
	}
	if !strings.Contains(done.GetError().GetMessage(), "secondary rate limit") {
		t.Errorf("the underlying reason should survive: %q", done.GetError().GetMessage())
	}
}

// A collector that fails in a way it did not describe has a defect. Saying so
// is more useful than guessing that the source was at fault.
func TestAnUndescribedFailureIsReportedAsAPluginError(t *testing.T) {
	srv, err := run(t, &fake{collect: func(out Stream) error {
		if err := out.Node(Identity(IdentityKey("s", "u1"), "alice", "user", Human, Active)); err != nil {
			return err
		}
		if err := out.Checkpoint([]byte("x")); err != nil {
			return err
		}
		return errors.New("nil map or something")
	}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	done := srv.completion(t)
	if done.GetCause() != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PLUGIN_ERROR {
		t.Errorf("cause = %v, want plugin_error", done.GetCause())
	}
}

// Resume is mandatory, and the SDK catches it here -- where the author can
// still see which of their code paths did it -- rather than letting the host
// reject the whole collection later.
func TestEmittingRecordsWithoutACheckpointFailsWithAnActionableMessage(t *testing.T) {
	_, err := run(t, &fake{collect: func(out Stream) error {
		return out.Node(Identity(IdentityKey("s", "u1"), "alice", "user", Human, Active))
	}})
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"checkpoint", "resume"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// A malformed record comes back to the author at the call site, with the
// field named, rather than as a collection the host rejects later.
func TestAnInvalidRecordFailsAtTheCallSite(t *testing.T) {
	var got error
	_, _ = run(t, &fake{collect: func(out Stream) error {
		bad := Identity(IdentityKey("s", "u1"), "", "user", Human, Active) // no name
		got = out.Node(bad)
		return got
	}})
	if got == nil {
		t.Fatal("want an error from Node")
	}
	if !strings.Contains(got.Error(), "node.name") {
		t.Errorf("error = %q, want it to name the field", got)
	}
}

func TestNothingMayFollowTheCompletion(t *testing.T) {
	srv := &fakeServer{}
	s := &stream{srv: srv}
	if err := s.finish(nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Node(Identity(IdentityKey("s", "u1"), "alice", "user", Human, Active)); err == nil {
		t.Error("a record after the completion must be refused")
	}
}

func TestDescribeIsCheckedBeforeItLeavesThePlugin(t *testing.T) {
	svc := &service{impl: &fake{}}

	d, err := svc.Describe(context.Background(), &collectorv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if d.GetKind() != collectorv1.Kind || d.GetCapabilities().GetRevoke() {
		t.Errorf("kind = %q, revoke = %v", d.GetKind(), d.GetCapabilities().GetRevoke())
	}

	// Declaring coarse entitlements without saying what that means for this
	// source is the case the contract most wants caught, and it is caught on
	// the plugin's side of the wire.
	svc = &service{impl: &fake{describe: func() (*Description, error) {
		return &Description{
			Name: "fake", Version: "0.0.1",
			Fidelities: []collectorv1.Fidelity{Coarse},
		}, nil
	}}}
	if _, err := svc.Describe(context.Background(), &collectorv1.DescribeRequest{}); err == nil {
		t.Error("declaring COARSE without a limitation should be refused")
	}
}

func TestRevokeIsDeclaredAndAnsweredForYou(t *testing.T) {
	resp, err := (&service{impl: &fake{}}).Revoke(context.Background(), &collectorv1.RevokeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetOutcome() != collectorv1.RevokeOutcome_REVOKE_OUTCOME_NOT_SUPPORTED {
		t.Errorf("outcome = %v", resp.GetOutcome())
	}
}

func TestTestConnectionAndValidateConfigCrossIntact(t *testing.T) {
	svc := &service{impl: &fake{}}

	probes, err := svc.TestConnection(context.Background(), &collectorv1.TestConnectionRequest{})
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if len(probes.GetScopes()) != 1 || !probes.GetScopes()[0].GetReachable() {
		t.Errorf("scopes = %+v", probes.GetScopes())
	}

	issues, err := svc.ValidateConfig(context.Background(), &collectorv1.ValidateConfigRequest{})
	if err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	if len(issues.GetIssues()) != 0 {
		t.Errorf("issues = %+v", issues.GetIssues())
	}
}

func TestProgressAndDiagnosticReachTheStream(t *testing.T) {
	srv := &fakeServer{}
	s := &stream{srv: srv}

	remaining := int64(4200)
	if err := s.Progress("users", &RateLimit{Remaining: &remaining}); err != nil {
		t.Fatal(err)
	}
	if err := s.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
		"fake.partial", "event storage is on but LOGIN is not enabled"); err != nil {
		t.Fatal(err)
	}
	if err := s.Diagnostic(collectorv1.Severity_SEVERITY_UNSPECIFIED, "", ""); err == nil {
		t.Error("an empty diagnostic says nothing and must be refused")
	}
	if len(srv.sent) != 2 {
		t.Fatalf("sent %d events, want 2", len(srv.sent))
	}
	if srv.sent[0].GetProgress().GetRateLimit().GetRemaining() != 4200 {
		t.Errorf("rate limit did not survive: %+v", srv.sent[0].GetProgress())
	}
}

func TestActivityRecordsReachTheStreamAndAreCounted(t *testing.T) {
	srv, err := run(t, &fake{collect: func(out Stream) error {
		now := time.Unix(1e9, 0).UTC()
		w := Window(now.Add(-30*24*time.Hour), now)
		if err := out.Activity(Seen(IdentityKey("s", "u1"), "login", now, w, 0, now, Exact)); err != nil {
			return err
		}
		if err := out.Activity(Unavailable(IdentityKey("s", "svc"), "login", now,
			"s.disabled", "event storage is off")); err != nil {
			return err
		}
		// A malformed one must not reach the wire.
		if err := out.Activity(&collectorv1.Activity{}); err == nil {
			t.Error("an activity with no subject and no result must be refused")
		}
		return out.Checkpoint([]byte("done"))
	}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := srv.completion(t).GetCounts().GetActivities(); got != 2 {
		t.Errorf("activities counted = %d, want 2", got)
	}
}

func TestResourceNodesAreBuildable(t *testing.T) {
	n := Resource(ResourceKey("s", "repo-1"), "acme/api", "repository")
	if vs := collectorv1.ValidateNode(n); len(vs) != 0 {
		t.Errorf("%v", vs)
	}
}

func TestIncompleteReadsAsAnErrorAndKeepsItsCause(t *testing.T) {
	underlying := errors.New("429 from the source")
	inc := &Incomplete{Cause: RateLimited, Err: underlying}

	if !strings.Contains(inc.Error(), "429") {
		t.Errorf("Error() = %q, want the underlying reason", inc)
	}
	if !errors.Is(inc, underlying) {
		t.Error("the underlying error should stay reachable through errors.Is")
	}
	bare := &Incomplete{Cause: BudgetExhausted}
	if strings.Contains(bare.Error(), "<nil>") {
		t.Errorf("Error() = %q; an Incomplete with no cause detail should still read cleanly", bare)
	}
	if _, ok := AsIncomplete(underlying); ok {
		t.Error("a plain error is not an Incomplete")
	}
}

// The handshake answers before the host knows what the binary is. It reports
// what contracts this binary speaks, and takes the plugin's identity from the
// collector itself so there is one source of truth for it.
func TestTheHandshakeReportsIdentityAndOfferings(t *testing.T) {
	resp, err := (&handshakeService{impl: &fake{}}).Hello(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetPluginName() != "fake" || resp.GetPluginVersion() != "0.0.1" {
		t.Errorf("identity = %q/%q", resp.GetPluginName(), resp.GetPluginVersion())
	}
	if len(resp.GetOfferings()) != 1 {
		t.Fatalf("offerings = %+v", resp.GetOfferings())
	}
	o := resp.GetOfferings()[0]
	if o.GetKind() != collectorv1.Kind || o.GetProtocolVersion() != collectorv1.ProtocolVersion {
		t.Errorf("offering = %s/%d", o.GetKind(), o.GetProtocolVersion())
	}

	// A collector that cannot describe itself still handshakes: the host
	// needs to learn what it speaks even when the plugin is unhealthy.
	broken := &handshakeService{impl: &fake{describe: func() (*Description, error) {
		return nil, errors.New("cannot reach my own config")
	}}}
	resp, err = broken.Hello(context.Background(), nil)
	if err != nil {
		t.Fatalf("the handshake must not depend on Describe succeeding: %v", err)
	}
	if len(resp.GetOfferings()) != 1 {
		t.Error("the offerings are a property of the binary, not of its health")
	}
}

func TestBothServicesRegisterOnThePluginsServer(t *testing.T) {
	s := grpc.NewServer()
	if err := (&collectorPlugin{impl: &fake{}}).GRPCServer(nil, s); err != nil {
		t.Errorf("registering the collector: %v", err)
	}
	if err := (&handshakePlugin{impl: &fake{}}).GRPCServer(nil, s); err != nil {
		t.Errorf("registering the handshake: %v", err)
	}
	if len(s.GetServiceInfo()) != 2 {
		t.Errorf("registered %d services, want both", len(s.GetServiceInfo()))
	}
}
