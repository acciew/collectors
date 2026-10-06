package iam

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// The conversion from the SDK's records to this collector's. What matters is
// what a real account leaves out: verified against one, a user with no inline
// policies has no UserPolicyList at all, and a role AWS has no record of
// carries RoleLastUsed with no date.

func TestAUserWithNothingAttachedConvertsWithoutInventing(t *testing.T) {
	got := convertUser(iamtypes.UserDetail{
		UserId: aws.String("AIDAEXAMPLE"), UserName: aws.String("alice"),
		Arn: aws.String("arn:aws:iam::1:user/alice"), Path: aws.String("/"),
	})
	if got.ID != "AIDAEXAMPLE" || got.Name != "alice" {
		t.Errorf("got %+v", got)
	}
	if len(got.InlinePolicies) != 0 || len(got.AttachedPolicies) != 0 || len(got.Groups) != 0 {
		t.Errorf("policies were invented: %+v", got)
	}
}

// Group membership arrives with the user, so no separate call is needed.
func TestAUsersGroupsArriveWithTheUser(t *testing.T) {
	got := convertUser(iamtypes.UserDetail{
		UserId: aws.String("AIDA"), UserName: aws.String("alice"),
		GroupList: []string{"engineers", "oncall"},
		AttachedManagedPolicies: []iamtypes.AttachedPolicy{
			{PolicyArn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess"),
				PolicyName: aws.String("ReadOnlyAccess")},
		},
		UserPolicyList: []iamtypes.PolicyDetail{{PolicyName: aws.String("Extra")}},
	})
	if len(got.Groups) != 2 || len(got.AttachedPolicies) != 1 || len(got.InlinePolicies) != 1 {
		t.Errorf("got %+v", got)
	}
}

// A role AWS has no record of carries the field with no date. Read as a zero
// time somebody treats as "never", it retires a role that is in use.
func TestARoleWithNoLastUsedRecordConvertsToNoTime(t *testing.T) {
	got := convertRole(iamtypes.RoleDetail{
		RoleId: aws.String("AROA"), RoleName: aws.String("Audit"),
		Arn:          aws.String("arn:aws:iam::1:role/Audit"),
		RoleLastUsed: &iamtypes.RoleLastUsed{}, // present, empty
	})
	if !got.LastUsed.IsZero() {
		t.Errorf("last used = %v, want no time at all", got.LastUsed)
	}
}

// And a role with one carries the date and the region it was used in.
func TestARoleThatWasAssumedCarriesWhenAndWhere(t *testing.T) {
	when := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	got := convertRole(iamtypes.RoleDetail{
		RoleId: aws.String("AROA"), RoleName: aws.String("Deploy"),
		Arn: aws.String("arn:aws:iam::1:role/Deploy"),
		RoleLastUsed: &iamtypes.RoleLastUsed{
			LastUsedDate: aws.Time(when), Region: aws.String("us-west-2"),
		},
	})
	if !got.LastUsed.Equal(when) || got.LastUsedRegion != "us-west-2" {
		t.Errorf("got %+v", got)
	}
}

// The field is a pointer and can be absent entirely.
func TestARoleWithNoLastUsedFieldDoesNotPanic(t *testing.T) {
	got := convertRole(iamtypes.RoleDetail{
		RoleId: aws.String("AROA"), RoleName: aws.String("Old"),
		Arn: aws.String("arn:aws:iam::1:role/Old"),
	})
	if !got.LastUsed.IsZero() {
		t.Errorf("last used = %v", got.LastUsed)
	}
}

// The trust policy is read out of the document the role carries.
func TestARolesTrustPolicyIsRead(t *testing.T) {
	got := convertRole(iamtypes.RoleDetail{
		RoleId: aws.String("AROA"), RoleName: aws.String("Deploy"),
		Arn: aws.String("arn:aws:iam::111122223333:role/Deploy"),
		AssumeRolePolicyDocument: aws.String(
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}]}`),
	})
	if len(got.Trust) != 1 || got.Trust[0].Kind != "Service" {
		t.Errorf("trust = %+v", got.Trust)
	}
}

// Whether a policy is AWS's or the account's own is what a reviewer reading a
// list of attachments needs to tell apart, and the ARN says which.
func TestAPolicyKnowsWhoWroteIt(t *testing.T) {
	for _, c := range []struct {
		arn        string
		awsManaged bool
	}{
		{"arn:aws:iam::aws:policy/ReadOnlyAccess", true},
		{"arn:aws:iam::111122223333:policy/Deploy", false},
	} {
		got := convertPolicy(iamtypes.ManagedPolicyDetail{
			Arn: aws.String(c.arn), PolicyName: aws.String("X"), PolicyId: aws.String("ANPA"),
		})
		if got.AWSManaged != c.awsManaged {
			t.Errorf("%s: aws managed = %v, want %v", c.arn, got.AWSManaged, c.awsManaged)
		}
	}
}

func TestAGroupConverts(t *testing.T) {
	got := convertGroup(iamtypes.GroupDetail{
		GroupId: aws.String("AGPA"), GroupName: aws.String("engineers"),
		Arn:             aws.String("arn:aws:iam::1:group/engineers"),
		GroupPolicyList: []iamtypes.PolicyDetail{{PolicyName: aws.String("Inline")}},
	})
	if got.ID != "AGPA" || len(got.InlinePolicies) != 1 {
		t.Errorf("got %+v", got)
	}
}

// Tags travel, because they are how most accounts record who owns a role.
func TestTagsSurvive(t *testing.T) {
	got := convertRole(iamtypes.RoleDetail{
		RoleId: aws.String("AROA"), RoleName: aws.String("X"),
		Arn:  aws.String("arn:aws:iam::1:role/X"),
		Tags: []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("platform")}},
	})
	if got.Tags["owner"] != "platform" {
		t.Errorf("tags = %v", got.Tags)
	}
}

// An account id is pulled out of an ARN to decide whether a trust principal
// is local, and a malformed one must not make everything look local.
func TestAnArnThatIsNotOneYieldsNoAccount(t *testing.T) {
	for _, arn := range []string{"", "nonsense", "arn:aws:iam"} {
		if got := accountOf(arn); got != "" {
			t.Errorf("accountOf(%q) = %q", arn, got)
		}
	}
	if got := accountOf("arn:aws:iam::111122223333:role/X"); got != "111122223333" {
		t.Errorf("accountOf = %q", got)
	}
}
