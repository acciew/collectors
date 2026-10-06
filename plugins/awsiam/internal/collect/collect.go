// Package collect turns an AWS account's IAM into the access graph.
//
// The shape is decided by one fact, recorded in ADR-0003: AWS does not
// enumerate effective permissions and cannot be made to. An entitlement here
// is an attached policy or an assumable role — a container of permissions
// nobody evaluated — and every grant is marked COARSE so that a reviewer is
// never shown one beside a resolved Keycloak role as though they were the
// same strength of claim.
//
// Three further facts, each verified against a real account, shape the rest.
//
// Roles are the largest identity class by a long way: on a real account
// they outnumbered users by a wide margin. An AWS review is mostly a review of roles, and a collector that
// treats them as an afterthought is reviewing the wrong population.
//
// A role is a principal *and* an entitlement. "May assume role X" is a
// permission somebody holds, and the role itself holds policies. One object,
// two nodes, joined by an ACTS_AS edge.
//
// The account root user is not returned by the authorization-details call at
// all. It is the most privileged principal in the account, and a collector
// that reads only that call reports an account without it.
package collect

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/awsiam/internal/iam"
	"go.acciew.io/collector/sdk/go/collector"
)

// Source is what a collection reads.
type Source interface {
	// Snapshot is the authorization details: users, groups, roles, policies
	// and their attachments, in one paginated call.
	Snapshot(ctx context.Context) (iam.Snapshot, error)
	// CredentialReport is the only per-user activity AWS offers.
	CredentialReport(ctx context.Context) (iam.CredentialReport, error)
}

// Account collects one AWS account into the stream.
func Account(ctx context.Context, src Source, now time.Time, out collector.Stream) error {
	snap, err := src.Snapshot(ctx)
	if err != nil {
		return err
	}
	return AccountFrom(ctx, src, snap, now, out)
}

// AccountFrom collects an account from a snapshot already read.
//
// The caller has one: it needed the account id before it could decide whether
// this is the account that was asked for. Reading it a second time would
// double the most expensive call in the collection — many pages and
// several minutes on a real account — and the two reads could disagree.
func AccountFrom(ctx context.Context, src Source, snap iam.Snapshot, now time.Time,
	out collector.Stream) error {
	// The credential report is read before anything is emitted, because the
	// root user comes out of it and has to be in the population rather than
	// appended to it.
	//
	// It can fail on a permission that has nothing to do with the rest of
	// the collection, and roles carry their own last-used, so a failure here
	// costs the user signal and not the role signal.
	report, reportErr := src.CredentialReport(ctx)
	if reportErr != nil {
		if err := out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
			"aws.credential_report.unreadable",
			"the credential report could not be read, so nothing is known about any user's "+
				"console password or access keys. Roles are unaffected: their last-used "+
				"arrives with the collection itself. The reason: "+reportErr.Error()); err != nil {
			return err
		}
	}
	snap.Users = append(snap.Users, rootUser(snap.Account, report)...)
	scope := snap.Account.ID

	name := snap.Account.ID
	if snap.Account.Alias != "" {
		name = snap.Account.Alias
	}
	if err := out.Node(collector.WithContext(
		collector.ScopeNode(collector.Scope(scope, scope), name, "account"),
		map[string]string{"account_id": snap.Account.ID, "alias": snap.Account.Alias},
	)); err != nil {
		return err
	}

	g := &graph{scope: scope, emitted: map[string]bool{}, byArn: map[string]string{}}
	if err := emitPolicies(snap, out, g); err != nil {
		return err
	}
	if err := emitGroups(snap, out, g); err != nil {
		return err
	}
	byUser := map[string]iam.Credentials{}
	for _, row := range report.Rows {
		byUser[row.User] = row
	}
	if err := emitUsers(snap, byUser, out, g); err != nil {
		return err
	}
	if err := emitRoles(snap, out, g); err != nil {
		return err
	}
	if err := emitTrust(snap, out, g); err != nil {
		return err
	}
	return emitActivity(snap, report, reportErr != nil, now, out)
}

// rootUser is the account root, which GetAccountAuthorizationDetails does not
// return.
//
// It can do everything in the account and it is nowhere in the authorization
// details — verified against a real account, where the credential report listed
// one more principal than that call did, and the extra was this. A collector
// that reads only the authorization details reports an account without its
// most privileged principal.
//
// It has no unique id of the AIDA kind, so the key is the word: there is
// exactly one per account and the account is the scope.
func rootUser(account iam.Account, report iam.CredentialReport) []iam.User {
	for _, row := range report.Rows {
		if row.User != rootUserName {
			continue
		}
		arn := row.Arn
		if arn == "" {
			arn = "arn:aws:iam::" + account.ID + ":root"
		}
		return []iam.User{{ID: "root", Name: rootUserName, Arn: arn, Root: true}}
	}
	return nil
}

// rootUserName is what the credential report calls the account root.
const rootUserName = "<root_account>"

type graph struct {
	scope   string
	emitted map[string]bool
	// byArn resolves an ARN to the key of the principal it names, so a trust
	// policy pointing at a principal in this account joins up with it.
	byArn map[string]string
}

// emitPolicies records every managed policy as an entitlement.
//
// An entitlement here is a container of permissions this collector did not
// and cannot evaluate. That is what COARSE means on every grant below, and
// why ADR-0003 exists.
func emitPolicies(snap iam.Snapshot, out collector.Stream, g *graph) error {
	for _, p := range snap.Policies {
		if err := g.policy(p.Arn, p.Name, map[string]string{
			"aws_managed": fmt.Sprint(p.AWSManaged),
			"policy_id":   p.ID,
		}, out); err != nil {
			return err
		}
	}
	return nil
}

// policy emits a managed policy entitlement once, keyed by ARN.
//
// A managed policy ARN is stable: unlike a user or a role, a policy cannot be
// renamed in place. It is also the only identifier a principal's attachment
// list carries, so keying on anything else would mean a lookup that can fail.
func (g *graph) policy(arn, name string, attrs map[string]string, out collector.Stream) error {
	if g.emitted[arn] {
		return nil
	}
	if attrs == nil {
		attrs = map[string]string{}
	}
	attrs["arn"] = arn
	attrs["account"] = g.scope
	if name == "" {
		name = policyName(arn)
	}
	if err := out.Node(collector.WithContext(
		collector.Entitlement(collector.EntitlementKey(g.scope, arn), name, "managed_policy"),
		attrs)); err != nil {
		return err
	}
	// A policy names the resources it covers inside a document nobody here
	// evaluates, so the honest statement is that it applies to the account.
	// Expanding it per resource would invent relationships and, for a policy
	// naming "*", would be unbounded.
	if err := out.Edge(collector.AppliesTo(
		collector.EntitlementKey(g.scope, arn), collector.Scope(g.scope, g.scope))); err != nil {
		return err
	}
	g.emitted[arn] = true
	return nil
}

// inlineID is the key for a policy that exists only on one principal. It has
// no ARN of its own, so the key is composed from the principal's stable id
// and the policy name.
func inlineID(principalID, name string) string {
	return "inline:" + principalID + ":" + name
}

func (g *graph) inline(principalID, principalName, policy string, out collector.Stream) error {
	id := inlineID(principalID, policy)
	if g.emitted[id] {
		return nil
	}
	if err := out.Node(collector.WithContext(
		collector.Entitlement(collector.EntitlementKey(g.scope, id), policy, "inline_policy"),
		map[string]string{
			"account":   g.scope,
			"inline_on": principalName,
		})); err != nil {
		return err
	}
	if err := out.Edge(collector.AppliesTo(
		collector.EntitlementKey(g.scope, id), collector.Scope(g.scope, g.scope))); err != nil {
		return err
	}
	g.emitted[id] = true
	return nil
}

// holds emits a grant. Every one is COARSE: the entitlement is a policy
// document this collector did not evaluate, and saying otherwise would put it
// beside a resolved role as though the two claims were equally strong.
func (g *graph) holds(subject *collectorv1.Key, entitlement string, how string,
	out collector.Stream, via ...*collectorv1.Key) error {
	fidelity := collector.Coarse
	return out.Edge(collector.HowGranted(
		collector.Holds(subject, collector.EntitlementKey(g.scope, entitlement), fidelity, via...),
		how))
}

func policyName(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i+1 < len(arn) {
		return arn[i+1:]
	}
	return arn
}

// isThrottling reports whether AWS asked us to slow down, which is a
// different instruction to an operator than anything else that can go wrong.
//
// Answered by the SDK's own classification rather than by looking for words
// in a message: a role named ThrottleReader would otherwise turn an
// access-denied into "wait an hour", and the operator would wait for
// something that will never clear.
func isThrottling(err error) bool { return iam.Throttled(err) }
