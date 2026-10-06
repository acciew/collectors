package collect_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/awsiam/internal/collect"
	"go.acciew.io/collector/plugins/awsiam/internal/iam"
	"go.acciew.io/collector/sdk/go/collector"
)

var now = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

// fakeSource is an account shaped like the real one these facts were verified
// against: a handful of users, far more roles than users, a root account that
// the authorization details do not return, trust policies naming all three
// principal kinds, and a policy attached through a group.
type fakeSource struct {
	snap   iam.Snapshot
	report iam.CredentialReport
	err    error
	// reportErr fails the credential report while leaving everything else
	// readable, which is what a missing permission looks like.
	reportErr error
	// snapshots counts how many times the account's authorization details
	// were read, which is the most expensive call in the collection.
	snapshots int
}

func (f *fakeSource) Snapshot(context.Context) (iam.Snapshot, error) {
	f.snapshots++
	return f.snap, f.err
}
func (f *fakeSource) CredentialReport(context.Context) (iam.CredentialReport, error) {
	if f.reportErr != nil {
		// As the real client answers: nothing, and the reason.
		return iam.CredentialReport{}, f.reportErr
	}
	return f.report, nil
}

func account() *fakeSource {
	return &fakeSource{
		snap: iam.Snapshot{
			Account: iam.Account{ID: "111122223333", Alias: "acme-prod"},
			Policies: []iam.Policy{
				{Arn: "arn:aws:iam::aws:policy/ReadOnlyAccess", Name: "ReadOnlyAccess", AWSManaged: true},
				{Arn: "arn:aws:iam::111122223333:policy/Deploy", Name: "Deploy"},
			},
			Groups: []iam.Group{{
				ID: "AGPAEXAMPLE1", Name: "engineers",
				Arn:              "arn:aws:iam::111122223333:group/engineers",
				AttachedPolicies: []iam.PolicyRef{{Arn: "arn:aws:iam::111122223333:policy/Deploy", Name: "Deploy"}},
			}},
			Users: []iam.User{
				{
					ID: "AIDAEXAMPLE1", Name: "alice",
					Arn:              "arn:aws:iam::111122223333:user/alice",
					Groups:           []string{"engineers"},
					AttachedPolicies: []iam.PolicyRef{{Arn: "arn:aws:iam::aws:policy/ReadOnlyAccess"}},
					InlinePolicies:   []string{"AliceExtra"},
				},
				// The account root is deliberately absent, exactly as
				// GetAccountAuthorizationDetails leaves it. It reaches the
				// collection from the credential report below.
			},
			Roles: []iam.Role{
				{
					ID: "AROAEXAMPLE1", Name: "DeployRole",
					Arn:              "arn:aws:iam::111122223333:role/DeployRole",
					AttachedPolicies: []iam.PolicyRef{{Arn: "arn:aws:iam::111122223333:policy/Deploy"}},
					LastUsed:         now.Add(-48 * time.Hour), LastUsedRegion: "us-west-2",
					Trust: []iam.Principal{
						{Kind: "AWS", Value: "arn:aws:iam::111122223333:user/alice"},
						{Kind: "Service", Value: "ec2.amazonaws.com", External: true},
					},
				},
				{
					ID: "AROAEXAMPLE2", Name: "AuditRole",
					Arn: "arn:aws:iam::111122223333:role/AuditRole",
					// No LastUsed: AWS has no record, which is not the same
					// as the role never having been assumed.
					Trust: []iam.Principal{
						{Kind: "AWS", Value: "arn:aws:iam::444455556666:role/Auditor", External: true},
						{Kind: "Federated", Value: "arn:aws:iam::111122223333:oidc-provider/oidc.eks", External: true},
					},
				},
			},
		},
		report: iam.CredentialReport{
			GeneratedAt: now.Add(-30 * time.Minute),
			Rows: []iam.Credentials{
				{
					User: "alice", PasswordEnabled: true,
					PasswordLastUsed: now.Add(-72 * time.Hour),
					Keys: []iam.AccessKey{
						{Number: 1, Active: true, LastUsed: now.Add(-time.Hour)},
						{Number: 2, Active: true, Unknown: true},
					},
				},
				// As a real report answers for the root account, which is
				// the only place it appears at all.
				{User: "<root_account>", Arn: "arn:aws:iam::111122223333:root",
					PasswordEnabled: true, PasswordUnknown: true},
			},
		},
	}
}

type capture struct {
	t           *testing.T
	events      []*collectorv1.CollectResponse
	diags       []string
	scopes      []collector.ScopeResult
	checkpoints [][]byte
}

func (c *capture) Node(n *collectorv1.Node) error {
	if vs := collectorv1.ValidateNode(n); len(vs) > 0 {
		c.t.Errorf("invalid node %q: %s", n.GetName(), vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Node{Node: n}})
	return nil
}

func (c *capture) Edge(e *collectorv1.Edge) error {
	if vs := collectorv1.ValidateEdge(e); len(vs) > 0 {
		c.t.Errorf("invalid edge: %s", vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Edge{Edge: e}})
	return nil
}

func (c *capture) Activity(a *collectorv1.Activity) error {
	if vs := collectorv1.ValidateActivity(a); len(vs) > 0 {
		c.t.Errorf("invalid activity for %q: %s", a.GetSubject().GetId(), vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Activity{Activity: a}})
	return nil
}

func (c *capture) Checkpoint(cursor []byte) error {
	c.checkpoints = append(c.checkpoints, cursor)
	return nil
}
func (c *capture) Progress(string, *collector.RateLimit) error { return nil }
func (c *capture) ScopeDone(r collector.ScopeResult) error {
	c.scopes = append(c.scopes, r)
	return nil
}
func (c *capture) Diagnostic(_ collectorv1.Severity, code, msg string) error {
	c.diags = append(c.diags, code+": "+msg)
	return nil
}

func collectAccount(t *testing.T, src collect.Source) *capture {
	t.Helper()
	out := &capture{t: t}
	if err := collect.Account(context.Background(), src, now, out); err != nil {
		t.Fatalf("Account: %v", err)
	}
	return out
}

func (c *capture) nodes() map[string]*collectorv1.Node {
	out := map[string]*collectorv1.Node{}
	for _, e := range c.events {
		if n := e.GetNode(); n != nil {
			out[n.GetKey().GetId()] = n
		}
	}
	return out
}

func (c *capture) grants(subject string) map[string]*collectorv1.Edge {
	out := map[string]*collectorv1.Edge{}
	for _, e := range c.events {
		edge := e.GetEdge()
		if edge.GetType() == collectorv1.EdgeType_EDGE_TYPE_HOLDS &&
			edge.GetFrom().GetId() == subject {
			out[edge.GetTo().GetId()] = edge
		}
	}
	return out
}

func (c *capture) activityFor(subject, signal string) *collectorv1.Activity {
	for _, e := range c.events {
		a := e.GetActivity()
		if a.GetSubject().GetId() == subject && a.GetSignal() == signal {
			return a
		}
	}
	return nil
}

// Every AWS grant is COARSE: an entitlement here is a policy document this
// collector did not evaluate. Rendering one beside a resolved Keycloak role
// as though they were the same strength of claim is the defect ADR-0003
// exists to prevent.
func TestEveryGrantIsCoarse(t *testing.T) {
	out := collectAccount(t, account())
	var checked int
	for _, e := range out.events {
		edge := e.GetEdge()
		if edge.GetType() != collectorv1.EdgeType_EDGE_TYPE_HOLDS {
			continue
		}
		checked++
		if edge.GetFidelity() != collectorv1.Fidelity_FIDELITY_COARSE {
			t.Errorf("%s -> %s is %v, want coarse",
				edge.GetFrom().GetId(), edge.GetTo().GetId(), edge.GetFidelity())
		}
	}
	if checked == 0 {
		t.Fatal("no grants were emitted, so this proves nothing")
	}
}

// The account root is not returned by the authorization-details call, and it
// can do everything. A collector reading only that call reports an account
// without its most privileged principal — so it is taken from the credential
// report, which is the only place it appears.
func TestTheAccountRootIsCollected(t *testing.T) {
	src := account()
	for _, u := range src.snap.Users {
		if u.Root {
			t.Fatal("the fixture hands the collector a root user; the point is that " +
				"AWS does not, and this test would then prove nothing")
		}
	}
	nodes := collectAccount(t, src).nodes()
	root, ok := nodes["root"]
	if !ok {
		t.Fatal("the account root was not collected")
	}
	if root.GetContext()["root_user"] != "true" {
		t.Errorf("the root user is not marked as one: %v", root.GetContext())
	}
	if root.GetSourceType() != "account_root_user" {
		t.Errorf("source type = %q", root.GetSourceType())
	}
}

// A role is a principal and an entitlement at once: it holds policies, and
// "may assume it" is a permission somebody holds. One object, two nodes,
// joined so a consumer can tell they are the same thing.
func TestARoleIsBothAPrincipalAndAnEntitlement(t *testing.T) {
	out := collectAccount(t, account())
	nodes := out.nodes()

	if _, ok := nodes["AROAEXAMPLE1"]; !ok {
		t.Error("the role is not a principal")
	}
	if _, ok := nodes["assume:AROAEXAMPLE1"]; !ok {
		t.Error("the role is not an entitlement")
	}
	var linked bool
	for _, e := range out.events {
		edge := e.GetEdge()
		if edge.GetType() == collectorv1.EdgeType_EDGE_TYPE_ACTS_AS &&
			edge.GetFrom().GetId() == "assume:AROAEXAMPLE1" &&
			edge.GetTo().GetId() == "AROAEXAMPLE1" {
			linked = true
		}
	}
	if !linked {
		t.Error("nothing says that holding the entitlement lets you act as the role")
	}
	// And the role holds its own policies, as a principal.
	if _, held := out.grants("AROAEXAMPLE1")["arn:aws:iam::111122223333:policy/Deploy"]; !held {
		t.Error("the role does not hold the policy attached to it")
	}
}

// A role is not a person and never was. Left to a name heuristic, every
// consumer would re-derive it differently.
func TestARoleIsNotAPerson(t *testing.T) {
	node := collectAccount(t, account()).nodes()["AROAEXAMPLE1"]
	if node.GetIdentity().GetKind() == collectorv1.IdentityKind_IDENTITY_KIND_HUMAN {
		t.Error("a role was collected as a person")
	}
}

// What a group holds reaches its members, and the route is the membership —
// which is what a reviewer would end.
func TestWhatAGroupHoldsReachesItsMembersThroughTheMembership(t *testing.T) {
	out := collectAccount(t, account())
	grant, held := out.grants("AIDAEXAMPLE1")["arn:aws:iam::111122223333:policy/Deploy"]
	if !held {
		t.Fatalf("alice does not hold the group's policy: %v", keys(out.grants("AIDAEXAMPLE1")))
	}
	via := grant.GetPath().GetVia()
	if len(via) != 1 || via[0].GetId() != "AGPAEXAMPLE1" {
		t.Errorf("route = %v, want the group membership", via)
	}
}

// "Anybody in account 444455556666 may assume this role" is precisely the
// finding a reviewer wants. Dropping it because the subject is not local
// would hide it.
func TestAPrincipalOutsideTheAccountIsNamedRatherThanDropped(t *testing.T) {
	out := collectAccount(t, account())
	nodes := out.nodes()

	var external *collectorv1.Node
	for id, n := range nodes {
		if strings.HasPrefix(id, "external:AWS:") {
			external = n
		}
	}
	if external == nil {
		t.Fatalf("the external principal was dropped: %v", keys2(nodes))
	}
	// Named to us, never enumerated. The difference is what stops "we did
	// not look" reading as "we looked and this is all there is".
	if external.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Errorf("provenance = %v, want referenced", external.GetProvenance())
	}
	if external.GetContext()["outside_account"] != "true" {
		t.Errorf("context = %v", external.GetContext())
	}
	if _, held := out.grants(external.GetKey().GetId())["assume:AROAEXAMPLE2"]; !held {
		t.Error("the external principal does not hold the role it is trusted to assume")
	}
}

// A federated principal stands for people who live in another source. Nothing
// in the contract yet lets an AWS role and the identity provider's users be
// recognised as related, and this collector must not pretend otherwise.
func TestAFederatedPrincipalIsNotClaimedToBeAPerson(t *testing.T) {
	nodes := collectAccount(t, account()).nodes()
	for id, n := range nodes {
		if !strings.HasPrefix(id, "external:Federated:") {
			continue
		}
		if n.GetIdentity().GetKind() == collectorv1.IdentityKind_IDENTITY_KIND_HUMAN {
			t.Error("a federation provider was collected as a person")
		}
		return
	}
	t.Error("the federated principal was not collected")
}

func keys(m map[string]*collectorv1.Edge) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keys2(m map[string]*collectorv1.Node) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The strongest test available: the whole collection through the same stream
// checker the host and the conformance suite use. It proves, among other
// things, that every hop of every derived grant is an edge this collector
// actually stated.
func TestTheEmittedStreamSatisfiesTheContract(t *testing.T) {
	out := collectAccount(t, account())

	checker := collectorv1.NewStreamChecker()
	var violations []collectorv1.Violation
	for _, e := range out.events {
		violations = append(violations, checker.Event(e)...)
	}
	violations = append(violations, checker.Close()...)

	for _, v := range violations {
		if strings.Contains(v.Rule, "completion") || strings.Contains(v.Rule, "checkpoint") {
			continue
		}
		t.Errorf("%s", v)
	}
}

// Two runs of one collection emit the same records in the same order, or
// every snapshot diff is churn rather than change.
func TestTheEmissionOrderIsTheSameEveryRun(t *testing.T) {
	var first []string
	for range 8 {
		var got []string
		for _, e := range collectAccount(t, account()).events {
			switch {
			case e.GetNode() != nil:
				got = append(got, "n:"+e.GetNode().GetKey().GetId())
			case e.GetEdge() != nil:
				got = append(got, "e:"+e.GetEdge().GetFrom().GetId()+">"+e.GetEdge().GetTo().GetId())
			case e.GetActivity() != nil:
				got = append(got, "a:"+e.GetActivity().GetSubject().GetId()+":"+e.GetActivity().GetSignal())
			}
		}
		if first == nil {
			first = got
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("run lengths differ: %d then %d", len(first), len(got))
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("record %d differs between runs: %s then %s", i, first[i], got[i])
			}
		}
	}
}

// An entitlement whose document names "*" covers everything in the account.
// Expanding that into an edge per resource would invent relationships and,
// for a policy naming every resource, would be unbounded.
func TestAPolicyAppliesToTheAccountRatherThanToInventedResources(t *testing.T) {
	out := collectAccount(t, account())
	var applies int
	for _, e := range out.events {
		edge := e.GetEdge()
		if edge.GetType() != collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO {
			continue
		}
		applies++
		if edge.GetTo().GetType() != collectorv1.NodeType_NODE_TYPE_SCOPE {
			t.Errorf("%s applies to %v, want the account scope",
				edge.GetFrom().GetId(), edge.GetTo().GetType())
		}
	}
	if applies == 0 {
		t.Error("no entitlement said what it applies to")
	}
}

// An inline policy exists only on the principal it is attached to and has no
// ARN, so its key is composed from the principal's stable id and the name.
// Two principals with a policy of the same name are two entitlements.
func TestAnInlinePolicyBelongsToItsPrincipal(t *testing.T) {
	src := account()
	src.snap.Roles[0].InlinePolicies = []string{"AliceExtra"}
	nodes := collectAccount(t, src).nodes()

	user, ok := nodes["inline:AIDAEXAMPLE1:AliceExtra"]
	if !ok {
		t.Fatalf("the user's inline policy is missing: %v", keys2(nodes))
	}
	if _, ok := nodes["inline:AROAEXAMPLE1:AliceExtra"]; !ok {
		t.Error("two principals with a policy of the same name collapsed into one entitlement")
	}
	if user.GetContext()["inline_on"] != "alice" {
		t.Errorf("context = %v, want the principal it belongs to", user.GetContext())
	}
}

// A group holds its own policies, so a reviewer can ask what the group has
// rather than only what its members have.
func TestAGroupHoldsItsOwnPolicies(t *testing.T) {
	out := collectAccount(t, account())
	if _, held := out.grants("AGPAEXAMPLE1")["arn:aws:iam::111122223333:policy/Deploy"]; !held {
		t.Errorf("the group does not hold its own policy: %v", keys(out.grants("AGPAEXAMPLE1")))
	}
}

// An AWS-managed policy is not one somebody in this account wrote, and a
// reviewer reading a list of attachments needs to tell them apart.
func TestAnAWSManagedPolicyIsMarkedAsOne(t *testing.T) {
	nodes := collectAccount(t, account()).nodes()
	aws := nodes["arn:aws:iam::aws:policy/ReadOnlyAccess"]
	if aws.GetContext()["aws_managed"] != "true" {
		t.Errorf("context = %v, want it marked AWS-managed", aws.GetContext())
	}
	own := nodes["arn:aws:iam::111122223333:policy/Deploy"]
	if own.GetContext()["aws_managed"] != "false" {
		t.Errorf("context = %v, want it marked as the account's own", own.GetContext())
	}
}

// A policy attached to a principal that the account's policy list does not
// include is still an entitlement they hold.
func TestAPolicyOnlySeenThroughAnAttachmentIsStillCollected(t *testing.T) {
	src := account()
	src.snap.Policies = nil // as a truncated or filtered listing would leave it
	nodes := collectAccount(t, src).nodes()
	if _, ok := nodes["arn:aws:iam::aws:policy/ReadOnlyAccess"]; !ok {
		t.Error("a policy reached only through an attachment was dropped")
	}
}

// refusing fails on the nth write, so that every error path is walked.
//
// A collector that swallows a stream error carries on emitting into a broken
// stream, and the host is handed a partial collection with a complete
// verdict. This walks every emission point and checks the error comes back.
type refusing struct {
	capture
	failAt int
	writes int
	err    error
}

func (r *refusing) tick() error {
	r.writes++
	if r.writes == r.failAt {
		return r.err
	}
	return nil
}

func (r *refusing) Node(n *collectorv1.Node) error {
	if err := r.tick(); err != nil {
		return err
	}
	return r.capture.Node(n)
}

func (r *refusing) Edge(e *collectorv1.Edge) error {
	if err := r.tick(); err != nil {
		return err
	}
	return r.capture.Edge(e)
}

func (r *refusing) Activity(a *collectorv1.Activity) error {
	if err := r.tick(); err != nil {
		return err
	}
	return r.capture.Activity(a)
}

func TestAStreamFailureAtAnyPointComesBack(t *testing.T) {
	boom := errors.New("the host went away")

	// How many records a whole collection emits, so every one can be failed.
	total := len(collectAccount(t, account()).events)
	if total < 20 {
		t.Fatalf("the fixture emits only %d records; this test would prove little", total)
	}

	for at := 1; at <= total; at++ {
		out := &refusing{capture: capture{t: t}, failAt: at, err: boom}
		err := collect.Account(context.Background(), account(), now, out)
		if !errors.Is(err, boom) {
			t.Fatalf("failing write %d of %d was swallowed: err = %v", at, total, err)
		}
	}
}

// An account whose credential report has no root row — which should not
// happen, but a collector must not invent a principal that AWS did not
// mention either.
func TestNoRootRowMeansNoInventedRootUser(t *testing.T) {
	src := account()
	var kept []iam.Credentials
	for _, r := range src.report.Rows {
		if r.User != "<root_account>" {
			kept = append(kept, r)
		}
	}
	src.report.Rows = kept

	if _, ok := collectAccount(t, src).nodes()["root"]; ok {
		t.Error("a root user was invented from a report that did not mention one")
	}
}

// A user in the account and not in the report is not a user who has never
// used anything: AWS generates the report on a schedule, so somebody created
// since the last one is simply not in it yet.
func TestAUserMissingFromTheReportIsNotReportedAsNeverActive(t *testing.T) {
	src := account()
	src.report.Rows = nil

	a := collectAccount(t, src).activityFor("AIDAEXAMPLE1", "console_password")
	if a == nil {
		t.Fatal("nothing was said about a user missing from the report")
	}
	if a.GetNotSeen() != nil {
		t.Error("a user absent from the report was reported as never having signed in")
	}
	if a.GetUnavailable() == nil {
		t.Errorf("result = %v, want unavailable", a.GetResult())
	}
}

// "May assume this role" and "may assume this role from the office network
// with MFA" are different access, and only one of them is what the
// unqualified sentence means. Every GitHub Actions role uses the conditional
// shape.
func TestAConditionalTrustGrantSaysThatItIsConditional(t *testing.T) {
	src := account()
	src.snap.Roles[0].Trust = []iam.Principal{
		{Kind: "AWS", Value: "arn:aws:iam::111122223333:user/alice", Conditional: true},
	}
	out := collectAccount(t, src)

	grant, held := out.grants("AIDAEXAMPLE1")["assume:AROAEXAMPLE1"]
	if !held {
		t.Fatal("the trust grant is missing")
	}
	if !strings.Contains(grant.GetSourceType(), "condition") {
		t.Errorf("granted as %q, which does not say the assumption is conditional",
			grant.GetSourceType())
	}
}

// AWS does not say whether an IAM user is a person, and in most accounts a
// large share are deployment and integration identities. Guessing from the
// name is what every consumer would do instead, differently each time.
func TestAnIAMUsersKindIsNotGuessed(t *testing.T) {
	node := collectAccount(t, account()).nodes()["AIDAEXAMPLE1"]
	if node.GetIdentity().GetKind() == collectorv1.IdentityKind_IDENTITY_KIND_HUMAN {
		t.Error("an IAM user was claimed to be a person; AWS does not say, and " +
			"jenkins-deploy is an IAM user too")
	}
}

// AWS has no enabled flag on a user. What it has is credentials: somebody
// with no console password and no active key cannot authenticate, and that is
// the closest thing to disabled the source states.
func TestAUserWithNothingToSignInWithIsNotActive(t *testing.T) {
	src := account()
	src.report.Rows[0].PasswordEnabled = false
	src.report.Rows[0].Keys = []iam.AccessKey{{Number: 1, Active: false}}

	node := collectAccount(t, src).nodes()["AIDAEXAMPLE1"]
	if node.GetIdentity().GetStatus() == collectorv1.IdentityStatus_IDENTITY_STATUS_ACTIVE {
		t.Error("a user with no password and no active key was reported as active")
	}
}

// And without a report there is nothing to base it on, which is not the same
// as being disabled.
func TestAUserWithNoCredentialInformationHasAnUnknownStatus(t *testing.T) {
	src := account()
	src.report.Rows = nil

	node := collectAccount(t, src).nodes()["AIDAEXAMPLE1"]
	if got := node.GetIdentity().GetStatus(); got != collectorv1.IdentityStatus_IDENTITY_STATUS_UNKNOWN {
		t.Errorf("status = %v, want unknown: nothing was read about their credentials", got)
	}
}

// A group a user says they are in that the account listing did not return is
// access this collection does not show, and silence about it is the one thing
// a reviewer cannot act on.
func TestAGroupMissingFromTheListingIsReported(t *testing.T) {
	src := account()
	src.snap.Users[0].Groups = append(src.snap.Users[0].Groups, "ghosts")

	out := collectAccount(t, src)
	var warned bool
	for _, d := range out.diags {
		if strings.Contains(d, "aws.group.not-in-listing") && strings.Contains(d, "ghosts") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("a group that could not be resolved was dropped silently: %v", out.diags)
	}
}

// The commonest trust policy in AWS names the account's own root. Now that
// the root user is collected, that principal joins up with it rather than
// becoming a second, external node standing for the same thing.
func TestATrustPolicyNamingThisAccountsRootJoinsTheRootWeCollected(t *testing.T) {
	src := account()
	src.snap.Roles[0].Trust = []iam.Principal{
		{Kind: "AWS", Value: "arn:aws:iam::111122223333:root", External: false},
	}
	out := collectAccount(t, src)

	if _, held := out.grants("root")["assume:AROAEXAMPLE1"]; !held {
		t.Errorf("the account root does not hold the role its own trust policy names: %v",
			keys(out.grants("root")))
	}
	for id := range out.nodes() {
		if strings.Contains(id, "external:AWS:arn:aws:iam::111122223333:root") {
			t.Error("a second node was invented for a principal already collected")
		}
	}
}

// A principal genuinely outside the account is marked as one, and a principal
// inside it that we could not resolve is not.
func TestOutsideTheAccountIsWhatTheTrustPolicySaidNotAGuess(t *testing.T) {
	src := account()
	src.snap.Roles[0].Trust = []iam.Principal{
		// In this account, but naming something the listing did not return.
		{Kind: "AWS", Value: "arn:aws:iam::111122223333:role/Gone", External: false},
		{Kind: "AWS", Value: "arn:aws:iam::444455556666:role/Auditor", External: true},
	}
	nodes := collectAccount(t, src).nodes()

	local := nodes["external:AWS:arn:aws:iam::111122223333:role/Gone"]
	if local.GetContext()["outside_account"] != "false" {
		t.Errorf("a principal in this account was marked as outside it: %v", local.GetContext())
	}
	foreign := nodes["external:AWS:arn:aws:iam::444455556666:role/Auditor"]
	if foreign.GetContext()["outside_account"] != "true" {
		t.Errorf("a principal in another account was not marked as outside: %v",
			foreign.GetContext())
	}
}
