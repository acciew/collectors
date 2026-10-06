package iam_test

import (
	"context"
	"os"
	"testing"

	"go.acciew.io/collector/plugins/awsiam/internal/iam"
)

// The claims this collector rests on, against a real account.
//
// Skipped without credentials, so it costs CI nothing. Run it with whatever
// the AWS SDK's own chain resolves — an ordinary `aws configure` profile is
// enough, and the permissions needed are read-only:
//
//	ACCIEW_AWS_LIVE=1 go test ./internal/iam/ -run Live -v
//
// The facts below were confirmed against a real account through direct API
// calls while this collector was written. This test is what keeps them true.
func TestLiveTheClaimsThisCollectorRestsOn(t *testing.T) {
	if os.Getenv("ACCIEW_AWS_LIVE") == "" {
		t.Skip("set ACCIEW_AWS_LIVE=1, with AWS credentials resolvable, to check " +
			"against a real account")
	}
	ctx := context.Background()
	client, err := iam.Dial(ctx, iam.Config{Region: os.Getenv("AWS_REGION")})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	snap, err := client.Snapshot(ctx)
	if err != nil {
		t.Fatalf("reading the account's authorization details: %v", err)
	}
	t.Logf("%d users, %d groups, %d roles, %d managed policies",
		len(snap.Users), len(snap.Groups), len(snap.Roles), len(snap.Policies))

	// Roles are the largest identity class in a real account, which is why
	// the role signal is the one that decides whether an AWS review is worth
	// anything. Observed to outnumber users by a wide margin.
	if len(snap.Roles) > 0 && len(snap.Roles) <= len(snap.Users) {
		t.Logf("this account has more users than roles, which is unusual; "+
			"users %d, roles %d", len(snap.Users), len(snap.Roles))
	}

	// Role last-used arrives with the same call, and is empty for a role AWS
	// has no record of rather than for one never assumed.
	var withRecord int
	for _, r := range snap.Roles {
		if !r.LastUsed.IsZero() {
			withRecord++
		}
		if r.ID == "" || r.Arn == "" {
			t.Errorf("a role has no stable identity: %+v", r)
		}
	}
	t.Logf("%d of %d roles have a last-used record", withRecord, len(snap.Roles))

	// Every trust principal kind should parse. A collector that handles only
	// one shape drops every role trusted by more than one principal.
	kinds := map[string]int{}
	for _, r := range snap.Roles {
		for _, p := range r.Trust {
			kinds[p.Kind]++
		}
	}
	t.Logf("trust principal kinds: %v", kinds)
	if len(snap.Roles) > 0 && len(kinds) == 0 {
		t.Error("no role named anybody in its trust policy, which cannot be right")
	}

	report, err := client.CredentialReport(ctx)
	if err != nil {
		t.Fatalf("reading the credential report: %v", err)
	}
	if report.GeneratedAt.IsZero() {
		t.Error("the report does not say when it was made, so its staleness is unknowable")
	}
	// The root account is in the report and not in the authorization
	// details, which is why the collector reads both.
	var root bool
	for _, row := range report.Rows {
		if row.User == "<root_account>" {
			root = true
			if !row.PasswordUnknown && row.PasswordLastUsed.IsZero() {
				t.Error("the root account's password answer was read as a definite negative")
			}
		}
	}
	if !root {
		t.Error("the credential report has no root account row; it is the most privileged " +
			"principal in the account and the authorization details do not return it")
	}
	t.Logf("credential report: %d rows, generated %s", len(report.Rows), report.GeneratedAt)
}
