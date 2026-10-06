package iam

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// Client reads IAM. It never writes.
//
// This is the one file that knows the AWS SDK exists. Everything above it
// works in the narrow types in this package, so the mapping can be tested
// without a network and the SDK's surface stays where it can be reasoned
// about. The SDK is used rather than hand-rolled because request signing and
// the credential chain are exactly the things not to reimplement.
type Client struct {
	iam *awsiam.Client
	sts *sts.Client
}

// Config is what the client needs. Everything about credentials is left to
// the AWS SDK's own chain — environment, shared config, instance role, an
// assumed role in a profile — because that is what an operator already knows
// how to configure and what rotates without us.
type Config struct {
	// Region for the API calls. IAM is global, but the SDK needs one.
	Region string
	// Profile from the shared config file. Empty means the default chain.
	Profile string
	// RoleARN to assume before reading, for the cross-account case.
	RoleARN string
	// ExternalID accompanies the assumption when the trusted account
	// requires one.
	ExternalID string
}

// Dial prepares a client.
//
// It resolves no credentials: the chain it builds runs lazily and reaches out
// at the first API call. The one exception is defaults_mode=auto, which asks
// the instance metadata service which region this is, at load time — see the
// error handling below, which is where that matters.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	loaded, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		// The one exception, and the reason this is not a bare universal.
		// Under defaults_mode=auto the SDK asks the instance metadata service
		// which region this is, at load time, and swallows the answer's
		// failure unless the context ended first — so a cancelled or
		// timed-out collection arrives here too, and calling that a bad
		// document would be this rule inverted.
		if ctx.Err() != nil {
			// The context first, because that is what happened: the probe's
			// own message says the metadata service was unreachable, which
			// is not the reason this call gave up.
			return nil, fmt.Errorf("aws: loading the AWS configuration: %w (the call that gave "+
				"up said: %s)", ctx.Err(), err.Error())
		}
		// Everything else is local, or near enough. This parses the shared
		// config and credentials files and the environment and builds a
		// provider chain; every provider that would reach out — SSO,
		// credential_process, web identity, the instance role — resolves
		// lazily on first use and surfaces at the first API call instead.
		//
		// Near enough because of one case: a container credentials URI is
		// resolved here, and a name that will not resolve arrives as a load
		// failure. Calling that the document's is right anyway — the SDK
		// requires such a host to be loopback, so it is a name this machine
		// was supposed to know.
		//
		// Blanket rather than a list of SDK error types, because the list is
		// what went wrong before: eight local failures fell through it and
		// were reported as AWS misbehaving. Another load-time failure that is
		// genuinely the network's belongs above as a named exception rather
		// than as a return to guessing.
		//
		// The message names all three places the value could have come from:
		// an operator told to check the document for something that came from
		// the environment greps for what is not there.
		return nil, &ConfigError{fmt.Errorf(
			"aws: loading the AWS configuration from this machine "+
				"(the collector's own profile field, the AWS_* environment, or the shared "+
				"config and credentials files): %w", err)}
	}
	if loaded.Region == "" {
		// IAM is global and the SDK still insists on one.
		loaded.Region = "us-east-1"
	}
	if cfg.RoleARN != "" {
		loaded.Credentials = aws.NewCredentialsCache(assumer{
			sts: sts.NewFromConfig(loaded), arn: cfg.RoleARN, externalID: cfg.ExternalID,
		})
	}
	return &Client{iam: awsiam.NewFromConfig(loaded), sts: sts.NewFromConfig(loaded)}, nil
}

// Account is which account these credentials are in.
func (c *Client) Account(ctx context.Context) (Account, error) {
	who, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Account{}, fmt.Errorf("aws: asking who we are: %w", err)
	}
	out := Account{ID: aws.ToString(who.Account)}
	// The alias is what people call the account; there is at most one. Not
	// being allowed to read it is not a reason to fail the collection, but a
	// failure that is merely transient would make the account's name flip
	// between runs — churn on the very node a reviewer identifies it by — so
	// a refusal is distinguished from a throttle.
	aliases, err := c.iam.ListAccountAliases(ctx, &awsiam.ListAccountAliasesInput{})
	switch {
	case err == nil && len(aliases.AccountAliases) > 0:
		out.Alias = aliases.AccountAliases[0]
	case Throttled(err):
		return Account{}, fmt.Errorf("aws: reading the account alias: %w", err)
	}
	return out, nil
}

// Probe checks the permissions a collection needs without doing one.
//
// One page of the authorization details proves the call the whole collection
// rests on, and asking for the credential report proves the other. Reading
// the account in full to answer "will this work" would take the minutes the
// collection takes, which is not a pre-flight check.
func (c *Client) Probe(ctx context.Context) (canRead bool, activity error, err error) {
	one := int32(1)
	if _, err := c.iam.GetAccountAuthorizationDetails(ctx,
		&awsiam.GetAccountAuthorizationDetailsInput{MaxItems: &one}); err != nil {
		return false, nil, fmt.Errorf("aws: reading the account's authorization details: %w", err)
	}
	// The report is a separate permission, and a token can have one without
	// the other. Answered separately so the check can say which is missing.
	if _, err := c.iam.GetCredentialReport(ctx, &awsiam.GetCredentialReportInput{}); err != nil {
		var notReady *iamtypes.CredentialReportNotReadyException
		var notPresent *iamtypes.CredentialReportNotPresentException
		if !errors.As(err, &notReady) && !errors.As(err, &notPresent) {
			return true, err, nil
		}
		// Not made yet is not the same as not allowed: the collection asks
		// for one and waits.
	}
	return true, nil, nil
}

// Snapshot reads the whole authorization picture.
//
// One paginated API returns users, groups, roles, policies and every
// attachment between them. Verified against a real account: a few
// users and groups and a few hundred roles and policies came back over many
// pages, so this
// is neither a single request nor a fast one.
func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	account, err := c.Account(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{Account: account}

	pages := awsiam.NewGetAccountAuthorizationDetailsPaginator(c.iam,
		&awsiam.GetAccountAuthorizationDetailsInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return Snapshot{}, fmt.Errorf("aws: reading the account's authorization details: %w", err)
		}
		for _, u := range page.UserDetailList {
			out.Users = append(out.Users, convertUser(u))
		}
		for _, g := range page.GroupDetailList {
			out.Groups = append(out.Groups, convertGroup(g))
		}
		for _, r := range page.RoleDetailList {
			out.Roles = append(out.Roles, convertRole(r))
		}
		for _, p := range page.Policies {
			out.Policies = append(out.Policies, convertPolicy(p))
		}
	}
	out.ReadAt = time.Now().UTC()
	return out, nil
}

func convertUser(u iamtypes.UserDetail) User {
	out := User{
		ID: aws.ToString(u.UserId), Name: aws.ToString(u.UserName),
		Arn: aws.ToString(u.Arn), Path: aws.ToString(u.Path),
		Groups: u.GroupList, Tags: tagsOf(u.Tags),
	}
	if u.CreateDate != nil {
		out.CreatedAt = *u.CreateDate
	}
	out.AttachedPolicies = attachedOf(u.AttachedManagedPolicies)
	for _, p := range u.UserPolicyList {
		out.InlinePolicies = append(out.InlinePolicies, aws.ToString(p.PolicyName))
	}
	return out
}

func convertGroup(g iamtypes.GroupDetail) Group {
	out := Group{
		ID: aws.ToString(g.GroupId), Name: aws.ToString(g.GroupName),
		Arn: aws.ToString(g.Arn), Path: aws.ToString(g.Path),
	}
	if g.CreateDate != nil {
		out.CreatedAt = *g.CreateDate
	}
	out.AttachedPolicies = attachedOf(g.AttachedManagedPolicies)
	for _, p := range g.GroupPolicyList {
		out.InlinePolicies = append(out.InlinePolicies, aws.ToString(p.PolicyName))
	}
	return out
}

func convertRole(r iamtypes.RoleDetail) Role {
	out := Role{
		ID: aws.ToString(r.RoleId), Name: aws.ToString(r.RoleName),
		Arn: aws.ToString(r.Arn), Path: aws.ToString(r.Path),
		Tags: tagsOf(r.Tags),
	}
	if r.CreateDate != nil {
		out.CreatedAt = *r.CreateDate
	}
	// Arrives with the same call as everything else, which is why roles are
	// the one identity class this collector can say anything about cheaply.
	if r.RoleLastUsed != nil {
		if r.RoleLastUsed.LastUsedDate != nil {
			out.LastUsed = *r.RoleLastUsed.LastUsedDate
		}
		out.LastUsedRegion = aws.ToString(r.RoleLastUsed.Region)
	}
	out.AttachedPolicies = attachedOf(r.AttachedManagedPolicies)
	for _, p := range r.RolePolicyList {
		out.InlinePolicies = append(out.InlinePolicies, aws.ToString(p.PolicyName))
	}
	for _, p := range r.InstanceProfileList {
		out.Profiles = append(out.Profiles, aws.ToString(p.InstanceProfileName))
	}
	out.Trust = trustPrincipals(aws.ToString(r.AssumeRolePolicyDocument), out.Arn)
	return out
}

func convertPolicy(p iamtypes.ManagedPolicyDetail) Policy {
	return Policy{
		Arn: aws.ToString(p.Arn), Name: aws.ToString(p.PolicyName),
		ID:              aws.ToString(p.PolicyId),
		AWSManaged:      strings.HasPrefix(aws.ToString(p.Arn), "arn:aws:iam::aws:"),
		AttachmentCount: aws.ToInt32(p.AttachmentCount),
	}
}

func attachedOf(ps []iamtypes.AttachedPolicy) []PolicyRef {
	out := make([]PolicyRef, 0, len(ps))
	for _, p := range ps {
		out = append(out, PolicyRef{Arn: aws.ToString(p.PolicyArn), Name: aws.ToString(p.PolicyName)})
	}
	return out
}

func tagsOf(ts []iamtypes.Tag) map[string]string {
	if len(ts) == 0 {
		return nil
	}
	out := make(map[string]string, len(ts))
	for _, t := range ts {
		out[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return out
}

// trustPrincipals reads who may assume a role out of its trust policy.
//
// The document arrives URL-encoded and its Principal field is one of several
// shapes: a bare "*", a map of kind to one value, or a map of kind to a list.
// A collector that handles only the map-of-string case silently drops every
// role trusted by more than one principal.
func trustPrincipals(document, roleArn string) []Principal {
	if document == "" {
		return nil
	}
	decoded, err := url.QueryUnescape(document)
	if err != nil {
		decoded = document
	}
	var doc struct {
		Statement []struct {
			Effect       string          `json:"Effect"`
			Principal    json.RawMessage `json:"Principal"`
			NotPrincipal json.RawMessage `json:"NotPrincipal"`
			Condition    json.RawMessage `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil
	}

	var out []Principal
	seen := map[string]bool{}
	// Everything an explicit Deny takes away. A Deny beats an Allow in IAM,
	// so a principal named in both holds nothing, and reporting the Allow
	// alone would show access that is refused.
	denied := map[string]bool{}
	// NotPrincipal inverts the set: everybody except those named. It cannot
	// be enumerated, and reporting nothing for it would hide a grant to
	// everybody. Reported as the wildcard it effectively is, with the
	// exclusions in the value so a reader can see them.
	var inverted []string
	add := func(kind, value string, conditional bool) {
		key := kind + "\x00" + value
		if value == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Principal{
			Kind: kind, Value: value,
			External:    isExternal(kind, value, roleArn),
			Conditional: conditional,
		})
	}

	for _, st := range doc.Statement {
		allow := strings.EqualFold(st.Effect, "Allow")

		// A statement naming who may *not* assume the role grants it to
		// everybody else. Dropping it silently hides a grant far wider than
		// any it could have named.
		if len(st.NotPrincipal) > 0 && string(st.NotPrincipal) != "null" && allow {
			inverted = append(inverted, string(st.NotPrincipal))
			continue
		}
		if !allow {
			// Collected rather than skipped, so the Allow it contradicts can
			// be taken away below.
			for _, p := range principalsIn(st.Principal) {
				denied[p.kind+"\x00"+p.value] = true
			}
			continue
		}
		// A statement with a Condition allows the assumption only when the
		// condition holds, and this collector does not evaluate conditions.
		conditional := len(st.Condition) > 0 && string(st.Condition) != "null"

		for _, p := range principalsIn(st.Principal) {
			add(p.kind, p.value, conditional)
		}
	}

	if len(inverted) > 0 {
		add("*", "everybody except "+strings.Join(inverted, ", "), false)
	}

	// A Deny removes what an Allow gave.
	kept := out[:0]
	for _, p := range out {
		if !denied[p.Kind+"\x00"+p.Value] {
			kept = append(kept, p)
		}
	}
	return kept
}

// entry is one principal as a policy document writes it.
type entry struct{ kind, value string }

// principalsIn reads a Principal block, which AWS writes in three shapes: a
// bare "*", a map of kind to one value, and a map of kind to a list. A reader
// that handles only the middle one drops every role trusted by more than one
// principal.
func principalsIn(raw json.RawMessage) []entry {
	if len(raw) == 0 {
		return nil
	}
	var bare string
	if json.Unmarshal(raw, &bare) == nil {
		return []entry{{kind: "*", value: bare}}
	}
	var byKind map[string]json.RawMessage
	if json.Unmarshal(raw, &byKind) != nil {
		return nil
	}
	var out []entry
	for kind, value := range byKind {
		var one string
		if json.Unmarshal(value, &one) == nil {
			out = append(out, entry{kind: kind, value: one})
			continue
		}
		var many []string
		if json.Unmarshal(value, &many) == nil {
			for _, v := range many {
				out = append(out, entry{kind: kind, value: v})
			}
		}
	}
	// Map iteration is not an order and the result reaches a stream that is
	// read in order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].kind != out[j].kind {
			return out[i].kind < out[j].kind
		}
		return out[i].value < out[j].value
	})
	return out
}

// isExternal reports whether a trust principal is outside the account being
// collected. A service, a federation provider and a wildcard always are.
func isExternal(kind, value, roleArn string) bool {
	if kind != "AWS" {
		return true
	}
	if value == "*" {
		return true
	}
	account := accountOf(roleArn)
	if account == "" {
		return true
	}
	// A trust policy may name a principal by ARN or an account by its bare
	// twelve-digit id, and the second form is common. Read only as an ARN,
	// an account trusting itself looks like a foreign account.
	return principalAccount(value) != account
}

// principalAccount is the account a trust principal belongs to, whether it
// was written as an ARN or as a bare account id.
func principalAccount(value string) string {
	if strings.HasPrefix(value, "arn:") {
		return accountOf(value)
	}
	if len(value) == 12 && isDigits(value) {
		return value
	}
	return ""
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func accountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

// CredentialReport is the only per-user activity AWS offers.
//
// It is generated asynchronously and cached, so this asks for one, waits for
// it if it is being made, and reports when AWS says it was produced — which
// is how stale every answer in it may be.
func (c *Client) CredentialReport(ctx context.Context) (CredentialReport, error) {
	if _, err := c.iam.GenerateCredentialReport(ctx, &awsiam.GenerateCredentialReportInput{}); err != nil {
		return CredentialReport{}, fmt.Errorf("aws: asking for a credential report: %w", err)
	}
	var report *awsiam.GetCredentialReportOutput
	for attempt := range 12 {
		var err error
		report, err = c.iam.GetCredentialReport(ctx, &awsiam.GetCredentialReportInput{})
		if err == nil {
			break
		}
		var notReady *iamtypes.CredentialReportNotReadyException
		if !errors.As(err, &notReady) {
			return CredentialReport{}, fmt.Errorf("aws: reading the credential report: %w", err)
		}
		select {
		case <-ctx.Done():
			return CredentialReport{}, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Second):
		}
	}
	if report == nil {
		return CredentialReport{}, errors.New("aws: the credential report was not ready in time")
	}

	out := CredentialReport{}
	if report.GeneratedTime == nil {
		// Without it there is no way to say how stale the answers are, and
		// an activity record whose freshness is unknowable is one this
		// product will not produce.
		return CredentialReport{}, errors.New("aws: the credential report does not say when " +
			"it was generated, so how stale its answers are cannot be established")
	}
	out.GeneratedAt = *report.GeneratedTime
	rows, err := csv.NewReader(strings.NewReader(string(report.Content))).ReadAll()
	if err != nil {
		return CredentialReport{}, fmt.Errorf("aws: the credential report is not readable: %w", err)
	}
	if len(rows) < 2 {
		return CredentialReport{}, errors.New("aws: the credential report has no rows; " +
			"every account has at least a root user")
	}
	header := map[string]int{}
	for i, name := range rows[0] {
		header[name] = i
	}
	for _, row := range rows[1:] {
		out.Rows = append(out.Rows, readCredentials(header, row))
	}
	return out, nil
}

func readCredentials(header map[string]int, row []string) Credentials {
	at := func(name string) string {
		i, ok := header[name]
		if !ok || i >= len(row) {
			return ""
		}
		return row[i]
	}
	c := Credentials{
		User:            at("user"),
		Arn:             at("arn"),
		PasswordEnabled: at("password_enabled") == "true",
		MFAActive:       at("mfa_active") == "true",
	}
	c.PasswordLastUsed, c.PasswordUnknown = readWhen(at("password_last_used"))

	for n := 1; n <= 2; n++ {
		suffix := strconv.Itoa(n)
		if at("access_key_"+suffix+"_active") == "" {
			continue
		}
		key := AccessKey{
			Number:  n,
			Active:  at("access_key_"+suffix+"_active") == "true",
			Region:  at("access_key_" + suffix + "_last_used_region"),
			Service: at("access_key_" + suffix + "_last_used_service"),
		}
		key.LastUsed, key.Unknown = readWhen(at("access_key_" + suffix + "_last_used_date"))
		c.Keys = append(c.Keys, key)
	}
	return c
}

// readWhen reads one of the report's timestamps.
//
// The sentinels are the whole difficulty. "no_information" means the
// credential has never been used *or* was last used before AWS began
// recording — two different facts, and only one of them would justify
// retiring an account. "N/A" is the same position for a key. Both come back
// as unknown rather than as a zero time a caller might read as "never".
func readWhen(v string) (at time.Time, unknown bool) {
	switch strings.TrimSpace(v) {
	case "", "N/A", "no_information", "not_supported":
		return time.Time{}, true
	}
	parsed, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, true
	}
	return parsed, false
}

// Throttled reports whether AWS asked us to slow down, using the SDK's own
// classification rather than looking for words in a message.
//
// Guessing from the text is how a role called ThrottleReader turns an
// access-denied into "wait an hour", and the operator waits for something
// that will never clear.
func Throttled(err error) bool {
	if err == nil {
		return false
	}
	// The SDK publishes the set of codes it treats as throttling, so this
	// stays right as AWS adds to it.
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	_, throttled := retry.DefaultThrottleErrorCodes[api.ErrorCode()]
	return throttled
}

// assumer fetches temporary credentials for a role in another account.
type assumer struct {
	sts        *sts.Client
	arn        string
	externalID string
}

func (a assumer) Retrieve(ctx context.Context) (aws.Credentials, error) {
	in := &sts.AssumeRoleInput{
		RoleArn:         aws.String(a.arn),
		RoleSessionName: aws.String("acciew-collector"),
	}
	if a.externalID != "" {
		in.ExternalId = aws.String(a.externalID)
	}
	out, err := a.sts.AssumeRole(ctx, in)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("aws: assuming %s: %w", a.arn, err)
	}
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
		Expires:         aws.ToTime(out.Credentials.Expiration),
		CanExpire:       true,
	}, nil
}

// ConfigError is a failure to assemble a client from files and environment on
// this machine. AWS was not called, so it is never the source's doing.
type ConfigError struct{ Err error }

func (e *ConfigError) Error() string { return e.Err.Error() }

func (e *ConfigError) Unwrap() error { return e.Err }
