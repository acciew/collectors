package iam

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
)

// A trust policy is the only place AWS says who may assume a role, and its
// Principal field has three shapes. A collector that handles only the
// map-of-one-string case silently drops every role trusted by more than one
// principal — which is most of the interesting ones.
func TestTrustPoliciesAreReadInEveryShapeAWSUses(t *testing.T) {
	const roleArn = "arn:aws:iam::111122223333:role/Example"

	for _, c := range []struct {
		name     string
		document string
		want     []Principal
	}{
		{
			"a service, which is how a workload assumes a role",
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}]}`,
			[]Principal{{Kind: "Service", Value: "ec2.amazonaws.com", External: true}},
		},
		{
			"a principal in this account",
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"}}]}`,
			[]Principal{{Kind: "AWS", Value: "arn:aws:iam::111122223333:user/alice"}},
		},
		{
			"a principal in another account, which is the finding a reviewer wants",
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::444455556666:role/Auditor"}}]}`,
			[]Principal{{Kind: "AWS", Value: "arn:aws:iam::444455556666:role/Auditor", External: true}},
		},
		{
			"a list, which a collector reading only strings would drop",
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":[
				"arn:aws:iam::111122223333:user/alice",
				"arn:aws:iam::111122223333:user/bob"]}}]}`,
			[]Principal{
				{Kind: "AWS", Value: "arn:aws:iam::111122223333:user/alice"},
				{Kind: "AWS", Value: "arn:aws:iam::111122223333:user/bob"},
			},
		},
		{
			"a federation provider, where the actual people are somewhere else",
			`{"Statement":[{"Effect":"Allow","Principal":{"Federated":
				"arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"}}]}`,
			[]Principal{{Kind: "Federated",
				Value:    "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE",
				External: true}},
		},
		{
			"anybody at all",
			`{"Statement":[{"Effect":"Allow","Principal":"*"}]}`,
			[]Principal{{Kind: "*", Value: "*", External: true}},
		},
	} {
		got := trustPrincipals(c.document, roleArn)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %+v, want %+v", c.name, got[i], c.want[i])
			}
		}
	}
}

// A Deny statement is not a grant. Reading one as a grant reports access that
// is explicitly refused.
func TestADenyStatementIsNotAGrant(t *testing.T) {
	got := trustPrincipals(
		`{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::999:root"}}]}`,
		"arn:aws:iam::111122223333:role/Example")
	if len(got) != 0 {
		t.Errorf("a Deny was read as a grant: %+v", got)
	}
}

// AWS returns the document URL-encoded.
func TestAnEncodedDocumentIsDecodedFirst(t *testing.T) {
	raw := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"}}]}`
	got := trustPrincipals(url.QueryEscape(raw), "arn:aws:iam::111122223333:role/Example")
	if len(got) != 1 || got[0].Value != "lambda.amazonaws.com" {
		t.Errorf("got %+v", got)
	}
}

// The same principal named twice is one principal.
func TestARepeatedPrincipalIsNotTwoGrants(t *testing.T) {
	got := trustPrincipals(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"}},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"}}]}`,
		"arn:aws:iam::111122223333:role/Example")
	if len(got) != 1 {
		t.Errorf("got %d principals, want 1: %+v", len(got), got)
	}
}

func TestAnUnreadableDocumentYieldsNothingRatherThanPanicking(t *testing.T) {
	for _, doc := range []string{"", "not json", "{}", `{"Statement":"nonsense"}`} {
		if got := trustPrincipals(doc, "arn:aws:iam::1:role/X"); len(got) != 0 {
			t.Errorf("%q yielded %+v", doc, got)
		}
	}
}

// The sentinels. AWS says "no_information" for a credential that has never
// been used *or* was last used before it began recording, and "N/A" for a key
// in the same position. Read as a zero time a caller might treat as "never",
// either one retires an account that is in use.
func TestTheReportsSentinelsAreUnknownRatherThanNever(t *testing.T) {
	for _, v := range []string{"no_information", "N/A", "not_supported", "", "  "} {
		at, unknown := readWhen(v)
		if !unknown {
			t.Errorf("%q was read as a definite answer", v)
		}
		if !at.IsZero() {
			t.Errorf("%q produced a time: %v", v, at)
		}
	}
}

func TestARealTimestampIsRead(t *testing.T) {
	at, unknown := readWhen("2026-08-11T19:35:51Z")
	if unknown {
		t.Fatal("a real timestamp was read as unknown")
	}
	if !at.Equal(time.Date(2026, 8, 11, 19, 35, 51, 0, time.UTC)) {
		t.Errorf("parsed %v", at)
	}
}

// A timestamp in a shape AWS has never used is unknown, not epoch zero.
func TestAnUnparseableTimestampIsUnknownRatherThanTheBeginningOfTime(t *testing.T) {
	if _, unknown := readWhen("11/08/2026"); !unknown {
		t.Error("an unreadable date was read as a definite answer")
	}
}

// Reading the report row by row: the two credential types are independent
// facts about one user.
func TestACredentialRowKeepsThePasswordAndTheKeysApart(t *testing.T) {
	header := map[string]int{}
	names := []string{
		"user", "arn", "password_enabled", "password_last_used", "mfa_active",
		"access_key_1_active", "access_key_1_last_used_date",
		"access_key_2_active", "access_key_2_last_used_date",
	}
	for i, n := range names {
		header[n] = i
	}
	got := readCredentials(header, []string{
		"alice", "arn:aws:iam::1:user/alice", "true", "2026-08-11T19:35:51Z", "true",
		"true", "2026-09-07T16:16:00Z",
		"true", "N/A",
	})
	if !got.PasswordEnabled || got.PasswordUnknown {
		t.Errorf("password: %+v", got)
	}
	if len(got.Keys) != 2 {
		t.Fatalf("keys = %+v", got.Keys)
	}
	if got.Keys[0].Unknown || got.Keys[0].LastUsed.IsZero() {
		t.Errorf("the used key was read as unknown: %+v", got.Keys[0])
	}
	if !got.Keys[1].Unknown {
		t.Errorf("the unused key was read as a definite answer: %+v", got.Keys[1])
	}
}

// The root account is the row that matters most and the one AWS says least
// about.
func TestTheRootAccountRowIsReadWithoutInventingAnswers(t *testing.T) {
	header := map[string]int{"user": 0, "password_enabled": 1, "password_last_used": 2}
	got := readCredentials(header, []string{"<root_account>", "true", "no_information"})
	if !got.PasswordUnknown {
		t.Error("the root account's password was given a definite answer")
	}
}

// A trust statement with a Condition allows the assumption only when the
// condition holds — a source IP, an MFA claim, a matching OIDC subject. This
// collector does not evaluate conditions, so a grant that says "may assume"
// without saying "when" overstates what the principal can do.
func TestAConditionalTrustEntryIsMarkedAsOne(t *testing.T) {
	got := trustPrincipals(`{"Statement":[{
		"Effect":"Allow",
		"Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
		"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/app:ref:refs/heads/main"}}
	}]}`, "arn:aws:iam::1:role/Deploy")

	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if !got[0].Conditional {
		t.Error("a conditional trust entry was recorded as an unconditional grant; " +
			"this is the shape every GitHub Actions role uses, and it does not mean " +
			"that anybody with that provider may assume the role")
	}
}

func TestAnUnconditionalTrustEntryIsNotMarked(t *testing.T) {
	got := trustPrincipals(
		`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}]}`,
		"arn:aws:iam::1:role/X")
	if got[0].Conditional {
		t.Error("an unconditional grant was marked conditional")
	}
}

// A Deny beats an Allow in IAM. A principal named in both holds nothing, and
// reporting the Allow alone shows access that is explicitly refused.
func TestADenyTakesAwayWhatAnAllowGave(t *testing.T) {
	got := trustPrincipals(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:user/alice","arn:aws:iam::1:user/bob"]}},
		{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::1:user/alice"}}]}`,
		"arn:aws:iam::1:role/X")

	if len(got) != 1 || got[0].Value != "arn:aws:iam::1:user/bob" {
		t.Errorf("got %+v, want only bob: alice is explicitly denied", got)
	}
}

// NotPrincipal names who may *not* assume the role, which grants it to
// everybody else. Dropped silently, that hides a grant far wider than any it
// could have named.
func TestNotPrincipalIsReportedAsTheWideGrantItIs(t *testing.T) {
	got := trustPrincipals(
		`{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::1:user/alice"}}]}`,
		"arn:aws:iam::1:role/X")

	if len(got) != 1 {
		t.Fatalf("got %+v, want the inverted grant reported", got)
	}
	if got[0].Kind != "*" {
		t.Errorf("kind = %q, want the wildcard it effectively is", got[0].Kind)
	}
	if !strings.Contains(got[0].Value, "alice") {
		t.Errorf("value = %q, want the exclusion visible", got[0].Value)
	}
}

// A trust policy may name an account by its bare twelve-digit id rather than
// by ARN, and it is the same account.
func TestAnAccountTrustingItselfByBareIdIsNotExternal(t *testing.T) {
	got := trustPrincipals(
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"111122223333"}}]}`,
		"arn:aws:iam::111122223333:role/X")
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].External {
		t.Error("an account trusting itself by bare id was reported as a foreign account")
	}
}

// The commonest trust policy in AWS names this account's own root.
func TestAnAccountTrustingItsOwnRootIsNotExternal(t *testing.T) {
	got := trustPrincipals(
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"}}]}`,
		"arn:aws:iam::111122223333:role/X")
	if got[0].External {
		t.Error("an account trusting its own root was reported as a foreign account")
	}
}

// Principals come back in a fixed order, because the result reaches a stream
// that is read in order and a map is not an order.
func TestPrincipalsComeBackInAStableOrder(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{
		"Service":["s3.amazonaws.com","ec2.amazonaws.com"],
		"AWS":"arn:aws:iam::1:user/alice"}}]}`
	var first []string
	for range 20 {
		var got []string
		for _, p := range trustPrincipals(doc, "arn:aws:iam::1:role/X") {
			got = append(got, p.Kind+":"+p.Value)
		}
		if first == nil {
			first = got
			continue
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("order is not stable: %v then %v", first, got)
			}
		}
	}
}

// Whether AWS asked us to slow down is the SDK's own answer, not a guess from
// the words in a message. Guessed, a role called ThrottleReader turns an
// access-denied into "wait an hour", and the operator waits for something
// that will never clear.
func TestThrottlingIsRecognisedByCodeNotByWording(t *testing.T) {
	throttled := &smithy.GenericAPIError{Code: "Throttling", Message: "Rate exceeded"}
	if !Throttled(throttled) {
		t.Error("a throttling error was not recognised")
	}

	denied := &smithy.GenericAPIError{
		Code:    "AccessDenied",
		Message: "User is not authorized to perform iam:GetRole on ThrottleReader",
	}
	if Throttled(denied) {
		t.Error("an access-denied naming a role called ThrottleReader was read as throttling; " +
			"the operator would be told to wait for something that never clears")
	}

	if Throttled(nil) || Throttled(errors.New("throttling, probably")) {
		t.Error("something that is not an API error was read as throttling")
	}
}
