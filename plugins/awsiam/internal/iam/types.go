// Package iam is the narrow view of AWS IAM this collector reads.
//
// The types are defined here rather than reused from the AWS SDK so that the
// mapping can be tested without one, and so that what this collector depends
// on is a page rather than a library surface. Every field is one a real
// account was observed to return.
package iam

import "time"

// Account is the scope: one AWS account.
type Account struct {
	ID    string
	Alias string
}

// User is an IAM user.
type User struct {
	// ID is the unique id (AIDA…), which survives a rename. The ARN embeds
	// the name and path and does not.
	ID   string
	Name string
	Arn  string
	Path string
	// CreatedAt is when the user was created.
	CreatedAt time.Time
	// Groups the user belongs to, which arrive with the user rather than
	// needing a call of their own.
	Groups []string
	// AttachedPolicies are managed policy ARNs.
	AttachedPolicies []PolicyRef
	// InlinePolicies are policies that exist only on this principal.
	InlinePolicies []string
	Tags           map[string]string
	// Root marks the account root user, which is not returned by the
	// authorization-details call at all and is the most privileged principal
	// in the account.
	Root bool
}

// Group is an IAM group: a grouping of users that holds policies.
type Group struct {
	ID               string
	Name             string
	Arn              string
	Path             string
	CreatedAt        time.Time
	AttachedPolicies []PolicyRef
	InlinePolicies   []string
}

// Role is both a principal that holds policies and an entitlement somebody
// may hold: "may assume role X" is a permission. One object, two domain
// types, which is the case the contract was shaped around.
type Role struct {
	// ID is the unique id (AROA…).
	ID               string
	Name             string
	Arn              string
	Path             string
	CreatedAt        time.Time
	AttachedPolicies []PolicyRef
	InlinePolicies   []string
	Tags             map[string]string
	// TrustPolicy names who may assume this role.
	Trust []Principal
	// LastUsed is what AWS reports about this role, and it arrives with the
	// same call as everything else. A zero time means AWS has no record —
	// which is not the same as the role never having been used, because
	// tracking began at a date AWS documents.
	LastUsed time.Time
	// LastUsedRegion is where, when there is a record.
	LastUsedRegion string
	// Profiles names the instance profiles this role is attached to, which
	// is how an EC2 instance comes to act as it.
	Profiles []string
}

// InstanceProfiles is how a workload comes to act as this role.
func (r Role) InstanceProfiles() []string { return r.Profiles }

// PolicyRef names a managed policy.
type PolicyRef struct {
	Arn  string
	Name string
}

// Principal is one entry from a role's trust policy: who may assume it.
type Principal struct {
	// Kind is AWS's own word: "AWS", "Service", "Federated", or "*".
	Kind string
	// Value is the ARN, service name or provider the entry names. For a
	// wildcard it is "*".
	Value string
	// External is true when the principal is not in the account being
	// collected: another account, a service, a federation provider, or
	// anybody at all.
	External bool
	// Conditional is true when the statement naming this principal carries a
	// Condition. The assumption is then allowed only when the condition
	// holds — a source IP, an MFA claim, a matching OIDC subject — and this
	// collector does not evaluate conditions. A grant that says "may assume"
	// without saying "when" overstates what the principal can do, which is
	// the one thing an evidence product must not do quietly.
	Conditional bool
}

// Policy is a managed policy definition.
type Policy struct {
	Arn        string
	Name       string
	ID         string
	AWSManaged bool
	// AttachmentCount is how many principals hold it, as AWS counts.
	AttachmentCount int32
}

// Credentials is one row of the credential report: what AWS knows about a
// user's own credentials and when they were last used.
//
// The two signals are independent facts. A user who last signed in to the
// console long ago and used an access key recently is active; merging
// them into one "last used" would lose which credential to take away.
type Credentials struct {
	User string
	Arn  string
	// PasswordEnabled says whether there is a console password at all.
	PasswordEnabled bool
	// PasswordLastUsed is when it was last used. Zero means AWS said
	// something other than a date — see PasswordUnknown.
	PasswordLastUsed time.Time
	// PasswordUnknown is AWS's "no_information": the password has never been
	// used, *or* it was last used before AWS began recording. Two different
	// facts in one value, and only one of them would justify retiring an
	// account.
	PasswordUnknown bool
	Keys            []AccessKey
	MFAActive       bool
}

// AccessKey is one of a user's access keys and what is known about its use.
type AccessKey struct {
	// Number is 1 or 2, which is how the report names them.
	Number int
	Active bool
	// LastUsed is zero when the report said "N/A", meaning the key has not
	// been used since AWS began recording rather than that it is unused.
	LastUsed time.Time
	Unknown  bool
	Region   string
	Service  string
}

// CredentialReport is the whole report plus when AWS produced it, which is
// how stale the answers in it may be.
type CredentialReport struct {
	GeneratedAt time.Time
	Rows        []Credentials
}

// Snapshot is everything one call to the authorization-details API returns,
// plus the pieces that call does not carry.
type Snapshot struct {
	// ReadAt is when the read finished. A large account takes minutes to
	// paginate, so an answer taken from it covers a period ending then
	// rather than ending now.
	ReadAt   time.Time
	Account  Account
	Users    []User
	Groups   []Group
	Roles    []Role
	Policies []Policy
}
