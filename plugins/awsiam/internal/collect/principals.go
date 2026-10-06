package collect

import (
	"fmt"
	"strconv"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/awsiam/internal/iam"
	"go.acciew.io/collector/sdk/go/collector"
)

func emitGroups(snap iam.Snapshot, out collector.Stream, g *graph) error {
	for _, grp := range snap.Groups {
		key := collector.GroupingKey(g.scope, grp.ID)
		if err := out.Node(collector.WithContext(
			collector.Grouping(key, grp.Name, "iam_group"),
			map[string]string{"account": g.scope, "arn": grp.Arn, "path": grp.Path},
		)); err != nil {
			return err
		}
		g.byArn[grp.Arn] = grp.ID

		for _, p := range grp.AttachedPolicies {
			if err := g.policy(p.Arn, p.Name, nil, out); err != nil {
				return err
			}
			if err := g.holds(key, p.Arn, "group_policy_attachment", out); err != nil {
				return err
			}
		}
		for _, name := range grp.InlinePolicies {
			if err := g.inline(grp.ID, grp.Name, name, out); err != nil {
				return err
			}
			if err := g.holds(key, inlineID(grp.ID, name), "group_inline_policy", out); err != nil {
				return err
			}
		}
	}
	return nil
}

func emitUsers(snap iam.Snapshot, credentials map[string]iam.Credentials,
	out collector.Stream, g *graph) error {
	byName := map[string]iam.Group{}
	for _, grp := range snap.Groups {
		byName[grp.Name] = grp
	}

	for _, u := range snap.Users {
		key := collector.IdentityKey(g.scope, u.ID)
		attrs := map[string]string{"account": g.scope, "arn": u.Arn, "path": u.Path}
		if u.Root {
			// The root user is not in the authorization details at all, and
			// it can do everything. A reviewer needs to see it named as what
			// it is rather than as another user.
			attrs["root_user"] = "true"
		}
		for k, v := range u.Tags {
			attrs["tag."+k] = v
		}
		if err := out.Node(collector.WithContext(
			collector.Identity(key, u.Name, sourceTypeOf(u), kindOf(u), statusOf(u, credentials)),
			attrs)); err != nil {
			return err
		}
		g.byArn[u.Arn] = u.ID

		for _, p := range u.AttachedPolicies {
			if err := g.policy(p.Arn, p.Name, nil, out); err != nil {
				return err
			}
			if err := g.holds(key, p.Arn, "user_policy_attachment", out); err != nil {
				return err
			}
		}
		for _, name := range u.InlinePolicies {
			if err := g.inline(u.ID, u.Name, name, out); err != nil {
				return err
			}
			if err := g.holds(key, inlineID(u.ID, name), "user_inline_policy", out); err != nil {
				return err
			}
		}

		// Group membership arrives with the user, and what the group holds
		// reaches them through it. The route is the membership, which is
		// what a reviewer would end.
		for _, name := range u.Groups {
			grp, known := byName[name]
			if !known {
				// The user says they are in it and the account listing did
				// not return it. Whatever that group holds reaches them and
				// this collection does not show it.
				if err := out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
					"aws.group.not-in-listing",
					fmt.Sprintf("%s is in group %s, which the account's authorization "+
						"details did not return; anything that group holds is access "+
						"this collection does not show", u.Name, name)); err != nil {
					return err
				}
				continue
			}
			grouping := collector.GroupingKey(g.scope, grp.ID)
			if err := out.Edge(collector.MemberOf(key, grouping)); err != nil {
				return err
			}
			for _, p := range grp.AttachedPolicies {
				if err := g.holds(key, p.Arn, "group_membership", out, grouping); err != nil {
					return err
				}
			}
			for _, inline := range grp.InlinePolicies {
				if err := g.holds(key, inlineID(grp.ID, inline), "group_membership",
					out, grouping); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// sourceTypeOf names what kind of user this is in AWS's own words.
func sourceTypeOf(u iam.User) string {
	if u.Root {
		return "account_root_user"
	}
	return "iam_user"
}

// kindOf says whether an IAM user is a person.
//
// AWS does not say, and it is not a detail: in most accounts a large share of
// the users are deployment and integration identities. Guessing from the name
// is what every consumer would do instead, differently each time, so the
// honest answer is that the source did not say.
func kindOf(u iam.User) collectorv1.IdentityKind {
	if u.Root {
		// The account root is the account itself, not a person, whoever
		// holds its credentials.
		return collector.UnknownKind
	}
	return collector.UnknownKind
}

// statusOf says whether this user can still do anything.
//
// AWS has no enabled flag on a user. What it has is credentials: a user with
// no console password and no active access key cannot authenticate, and that
// is the closest thing to disabled the source states. Without a credential
// report to read, nothing is known and the status says so.
func statusOf(u iam.User, credentials map[string]iam.Credentials) collectorv1.IdentityStatus {
	c, known := credentials[u.Name]
	if !known {
		return collector.UnknownStatus
	}
	if c.PasswordEnabled {
		return collector.Active
	}
	for _, k := range c.Keys {
		if k.Active {
			return collector.Active
		}
	}
	// No password and no active key: there is nothing left to sign in with.
	return collector.Disabled
}

// emitRoles records every role twice: as a principal that holds policies, and
// as an entitlement somebody may hold.
//
// This is the case §3.1 of the mapping document is built around. A model
// where an object has exactly one type cannot express it, and AWS is where it
// stops being an edge case: roles are the largest identity class in a real
// account by a wide margin.
func emitRoles(snap iam.Snapshot, out collector.Stream, g *graph) error {
	for _, r := range snap.Roles {
		identity := collector.IdentityKey(g.scope, r.ID)
		attrs := map[string]string{
			"account": g.scope, "arn": r.Arn, "path": r.Path,
		}
		if r.LastUsedRegion != "" {
			attrs["last_used_region"] = r.LastUsedRegion
		}
		// One key each rather than a joined list: an instance profile name
		// may legally contain a comma, and a joined list would then read as
		// two profiles that do not exist.
		for i, profile := range r.InstanceProfiles() {
			attrs["instance_profile."+strconv.Itoa(i)] = profile
		}
		for k, v := range r.Tags {
			attrs["tag."+k] = v
		}
		// A role is not a person and never was. Every consumer would
		// otherwise re-derive that from the name.
		if err := out.Node(collector.WithContext(
			collector.Identity(identity, r.Name, "iam_role", collector.MachineKind, collector.Active),
			attrs)); err != nil {
			return err
		}
		g.byArn[r.Arn] = r.ID

		// The same role as the thing somebody holds.
		entitlement := roleEntitlementID(r.ID)
		if err := out.Node(collector.WithContext(
			collector.Entitlement(collector.EntitlementKey(g.scope, entitlement),
				"assume "+r.Name, "assumable_role"),
			map[string]string{"account": g.scope, "arn": r.Arn})); err != nil {
			return err
		}
		if err := out.Edge(collector.AppliesTo(
			collector.EntitlementKey(g.scope, entitlement),
			collector.Scope(g.scope, g.scope))); err != nil {
			return err
		}
		// Holding it lets the holder act as the role: the two nodes are one
		// object, and this edge is what says so.
		if err := out.Edge(collector.ActsAs(
			collector.EntitlementKey(g.scope, entitlement), identity)); err != nil {
			return err
		}

		for _, p := range r.AttachedPolicies {
			if err := g.policy(p.Arn, p.Name, nil, out); err != nil {
				return err
			}
			if err := g.holds(identity, p.Arn, "role_policy_attachment", out); err != nil {
				return err
			}
		}
		for _, name := range r.InlinePolicies {
			if err := g.inline(r.ID, r.Name, name, out); err != nil {
				return err
			}
			if err := g.holds(identity, inlineID(r.ID, name), "role_inline_policy", out); err != nil {
				return err
			}
		}
	}
	return nil
}

func roleEntitlementID(roleID string) string { return "assume:" + roleID }

// emitTrust records who may assume each role.
//
// This release derives this from the trust policy, because it arrives with data
// already fetched. Assumption in fact requires both sides — the trust policy
// naming the principal and the principal holding sts:AssumeRole — so this
// over-reports rather than under-reports, and the plugin says so.
//
// A principal outside the account is emitted as referenced rather than
// dropped: "anybody in account 444455556666 may assume this role" is
// precisely the finding a reviewer wants, and dropping it because the subject
// is not local would hide it.
func emitTrust(snap iam.Snapshot, out collector.Stream, g *graph) error {
	for _, r := range snap.Roles {
		entitlement := roleEntitlementID(r.ID)
		for _, p := range r.Trust {
			subject, err := g.trustSubject(p, out)
			if err != nil {
				return err
			}
			if subject == nil {
				continue
			}
			// Said in the grant itself, because "may assume this role" and
			// "may assume this role from the office network with MFA" are
			// different access and only one of them is what the unqualified
			// sentence means.
			how := "trust_policy"
			if p.Conditional {
				how = "trust_policy_with_unevaluated_condition"
			}
			if err := g.holds(subject, entitlement, how, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// trustSubject resolves one trust-policy entry to a principal, emitting a
// referenced node for anything outside the account.
func (g *graph) trustSubject(p iam.Principal, out collector.Stream) (*collectorv1.Key, error) {
	if id, local := g.byArn[p.Value]; local {
		return collector.IdentityKey(g.scope, id), nil
	}
	// Named to us and not enumerated: another account's principal, an AWS
	// service, a federation provider, anybody at all — or a principal in
	// this account that the authorization details did not return, which the
	// account root is.
	id := "external:" + p.Kind + ":" + p.Value
	key := collector.IdentityKey(g.scope, id)
	if g.emitted[id] {
		return key, nil
	}
	// Reference, not Identity: this principal was named to us, never
	// enumerated, and the difference is one the contract keeps so that "we
	// did not look" cannot be read as "we looked and this is all there is".
	// A federation provider in particular stands for people who live in
	// another source — very often the identity provider another collector
	// reads — and nothing in the contract yet lets the two be recognised as
	// the same people.
	node := collector.Reference(key, externalName(p), "external_principal")
	// Whether it is outside the account is what the trust policy actually
	// said, not an assumption from the fact that we could not resolve it.
	// The commonest trust policy in AWS names this account's own root, and
	// calling that external would send a reviewer looking for another
	// account that does not exist.
	if err := out.Node(collector.WithContext(node, map[string]string{
		"account":         g.scope,
		"principal_kind":  p.Kind,
		"principal_value": p.Value,
		"outside_account": strconv.FormatBool(p.External),
		"conditional":     strconv.FormatBool(p.Conditional),
	})); err != nil {
		return nil, err
	}
	g.emitted[id] = true
	return key, nil
}

func externalName(p iam.Principal) string {
	switch p.Kind {
	case "*":
		return "anybody"
	case "Service":
		return p.Value + " (AWS service)"
	case "Federated":
		return p.Value + " (federated)"
	}
	return p.Value
}

func emitActivity(snap iam.Snapshot, report iam.CredentialReport, reportFailed bool,
	now time.Time, out collector.Stream) error {
	byUser := map[string]iam.Credentials{}
	for _, row := range report.Rows {
		byUser[row.User] = row
	}
	for _, u := range snap.Users {
		row, known := byUser[u.Name]
		if !known {
			// Either the report could not be read at all, or this user is
			// not in it — AWS generates it on a schedule, so somebody
			// created since the last one is missing. Neither is the same as
			// their never having used a credential.
			reason := "this user is not in the credential report, which AWS generates on a " +
				"schedule; a user created since the last one was made is not in it yet"
			code := "aws.credential_report.no_row"
			if reportFailed {
				reason = "the credential report could not be read, so nothing is known about " +
					"this user's console password or access keys"
				code = "aws.credential_report.unreadable"
			}
			if err := out.Activity(collector.Unavailable(
				collector.IdentityKey(snap.Account.ID, u.ID), SignalConsolePassword, now,
				code, reason)); err != nil {
				return err
			}
			continue
		}
		if err := userActivity(snap.Account.ID, u, row, report, now, out); err != nil {
			return err
		}
	}
	// The account was read before now: pagination takes minutes, and the
	// window a role's answer covers ends when we stopped reading.
	readAt := snap.ReadAt
	if readAt.IsZero() {
		readAt = now
	}
	for _, r := range snap.Roles {
		if err := roleActivity(snap.Account.ID, r, readAt, now, out); err != nil {
			return err
		}
	}
	return nil
}
