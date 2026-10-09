// Command awsiam is the AWS IAM collector.
//
// Built exactly as a third party would build it: its own module, depending on
// the SDK and the contract and never on the core. It reads IAM and never
// writes.
package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/awsiam/internal/collect"
	"go.acciew.io/collector/plugins/awsiam/internal/iam"
	"go.acciew.io/collector/sdk/go/collector"
)

// version is stamped at build time; the default is what a local build reports.
var version = "0.2.0-dev"

func main() { collector.Serve(&awsiam{}) }

type awsiam struct{}

func (a *awsiam) Describe(context.Context) (*collector.Description, error) {
	return &collector.Description{
		Name:    "awsiam",
		Version: version,
		Description: "Collects users, groups, roles and policy attachments from an AWS " +
			"account's IAM.",
		Activity: true,
		Fidelities: []collectorv1.Fidelity{
			// Every grant, without exception. An entitlement here is a
			// policy document this collector did not evaluate, and AWS
			// cannot be made to enumerate what a principal can actually do.
			collector.Coarse,
		},
		NodeTypes: []collectorv1.NodeType{
			collectorv1.NodeType_NODE_TYPE_SCOPE,
			collectorv1.NodeType_NODE_TYPE_IDENTITY,
			collectorv1.NodeType_NODE_TYPE_GROUPING,
			collectorv1.NodeType_NODE_TYPE_ENTITLEMENT,
		},
		EdgeTypes: []collectorv1.EdgeType{
			collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF,
			collectorv1.EdgeType_EDGE_TYPE_HOLDS,
			collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO,
			collectorv1.EdgeType_EDGE_TYPE_ACTS_AS,
		},
		Signals: []collector.Signal{
			{
				Name: collect.SignalConsolePassword,
				Description: "When a user last signed in to the console, from the credential " +
					"report. AWS answers \"no information\" for a password never used or last " +
					"used before it began recording in 2014, and those are different facts.",
			},
			{
				Name: collect.SignalAccessKey,
				Description: "When an access key was last used, per key, from the credential " +
					"report. A user's keys and their console password are separate answers: " +
					"merging them loses which credential to take away.",
			},
			{
				Name: collect.SignalRoleLastUsed,
				Description: "When a role was last assumed. It arrives with the collection " +
					"itself, which matters because roles are the largest identity class in a " +
					"real account by a long way. AWS reports a role's last use for the trailing 400 days only, " +
					"and a role last assumed before then is indistinguishable from one never assumed.",
			},
		},
		Limitations: []collector.Limitation{
			{
				Code: "aws.entitlements-are-coarse",
				Summary: "An entitlement here is an attached policy or an assumable role — a " +
					"container of permissions nobody evaluated — not a computed permission. " +
					"An AWS principal's effective access is the outcome of evaluating identity " +
					"policies, resource policies, permission boundaries, service control " +
					"policies and session policies against a specific action on a specific " +
					"resource, and there is no list to fetch. Every grant is marked coarse so " +
					"that it is never shown beside a resolved role as the same strength of " +
					"claim.",
			},
			{
				Code: "aws.assumption-needs-both-sides",
				Summary: "Who may assume a role is taken from the role's trust policy, because " +
					"that arrives with data already fetched. Assumption in fact requires both " +
					"the trust policy naming the principal and the principal holding " +
					"sts:AssumeRole, so this over-reports rather than under-reports: somebody " +
					"named in a trust policy who lacks the caller-side permission cannot " +
					"actually assume the role.",
			},
			{
				Code: "aws.federated-principals-are-elsewhere",
				Summary: "A trust policy naming a SAML or OIDC provider means the people who " +
					"can assume that role live in an identity provider this collector cannot " +
					"see. Nothing in the contract yet lets an AWS role and those users be " +
					"recognised as related, and this collector does not pretend otherwise: the " +
					"provider is recorded as a principal referenced rather than enumerated.",
			},
			{
				Code: "aws.identity-center-not-collected",
				Summary: "IAM Identity Center — permission sets assigned across accounts — is a " +
					"different API surface with a different model, and is where a large " +
					"organisation's human access actually lives. This collects IAM only.",
			},
			{
				Code: "aws.one-account-per-collection",
				Summary: "One set of credentials reaches one account. Reading another means " +
					"assuming a role into it, which is a different configuration and therefore " +
					"a different collection. AWS Organizations is not used to enumerate " +
					"accounts.",
			},
			{
				Code: "aws.activity-began-when-aws-started-recording",
				Summary: "AWS began recording password use in October 2014, and reports a role's last " +
					"use for the trailing 400 days only. Beyond those limits it has nothing to say " +
					"about anybody, which is why every coverage window starts there and why a " +
					"credential AWS has no record of is reported as unanswerable rather than as unused.",
			},
		},
	}, nil
}

func (a *awsiam) ValidateConfig(_ context.Context, raw []byte) ([]collector.Issue, error) {
	_, issues := collect.Validate(raw)
	return issues, nil
}

func (a *awsiam) TestConnection(ctx context.Context, raw []byte) ([]collector.ScopeProbe, error) {
	client, err := dial(ctx, raw)
	if err != nil {
		return nil, err
	}
	account, err := client.Account(ctx)
	if err != nil {
		// Not knowing which account the credentials are in is not a scope
		// that failed; it is not knowing what to probe.
		return nil, err
	}
	probe := collector.ScopeProbe{
		Scope:     collector.Scope(account.ID, account.ID),
		Name:      accountName(account),
		Reachable: true,
	}
	// One page of the authorization details and one look at the credential
	// report: enough to prove both permissions the collection needs, and not
	// the minutes a full read would take.
	canRead, activityErr, err := client.Probe(ctx)
	switch {
	case err != nil:
		probe.Reachable, probe.Err = false, err
	case activityErr != nil:
		// Roles still carry their own last-used, so this is not "no activity
		// at all" — it is no activity for the users, which is worth knowing
		// before waiting on a collection.
		probe.ActivityAvailable = false
		probe.ActivityNote = "the credential report cannot be read, so nothing will be known " +
			"about any user's console password or access keys; roles are unaffected because " +
			"their last-used arrives with the collection itself. " + activityErr.Error()
	default:
		probe.ActivityAvailable = canRead
	}
	return []collector.ScopeProbe{probe}, nil
}

func (a *awsiam) Collect(ctx context.Context, req collector.CollectRequest, out collector.Stream) error {
	// A raw error here is reported as a plugin error — a defect in this
	// code — and expired credentials or an unreachable IAM are neither.
	client, err := dial(ctx, req.Config)
	if err != nil {
		return &collector.Incomplete{Cause: collector.CauseFor(err), Err: err}
	}
	return collect.All(ctx, client, time.Now().UTC(), req, out)
}

func accountName(a iam.Account) string {
	if a.Alias != "" {
		return a.Alias + " (" + a.ID + ")"
	}
	return a.ID
}

// dial resolves the configuration and prepares a client.
//
// There is no credential in the document to resolve. AWS credentials are
// temporary by design and come from the SDK's own chain — environment, shared
// config, an instance or pod role — which is what rotates without us and what
// an operator already knows how to configure.
func dial(ctx context.Context, raw []byte) (*iam.Client, error) {
	cfg, issues := collect.Validate(raw)
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			// Marked where it happens, so the cause and the code cannot drift
			// apart later.
			return nil, collector.BadConfig(
				fmt.Errorf("configuration: %s: %s", i.Field, i.Message))
		}
	}
	client, err := iam.Dial(ctx, iam.Config{
		Region: cfg.Region, Profile: cfg.Profile,
		RoleARN: cfg.RoleARN, ExternalID: cfg.ExternalID,
	})
	// Assembling a client reads files and environment on this machine and
	// calls AWS for none of it, so those failures are the deployment's.
	// Everything after this is the SDK talking to AWS.
	var local *iam.ConfigError
	if errors.As(err, &local) {
		return nil, collector.BadConfig(err)
	}
	return client, err
}
