package collect

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// groups writes the groups. Their members are read by the part after it, once
// every group is known, so that a member that is a group made since the list
// was read is told from one the list had.
func (st *state) groups(ctx context.Context) error {
	err := walk(ctx, st, func(gs []graph.Group) error {
		for _, g := range gs {
			if err := st.emitGroup(g); err != nil {
				return err
			}
		}
		return nil
	})
	return needs(err, "Group.Read.All", "list the groups")
}

// groupMemberships reads the members of every group, and states each one's place
// in it.
func (st *state) groupMemberships(ctx context.Context) error {
	if st.failed["groups"] {
		return st.skipFor("group_members", "groups", "memberships")
	}
	err := walk(ctx, st, func(gs []graph.Group) error {
		for _, g := range gs {
			name := g.DisplayName
			if name == "" {
				name = g.ID
			}
			// A group made since the list was read is named here, as referenced.
			// The groups part having failed ends this part before it starts.
			if _, _, err := st.named("groups", collector.GroupingKey(st.tenant, g.ID), name, "group"); err != nil {
				return err
			}
			err := st.groupMembers(ctx, g.ID, name,
				func() (bool, string, error) { return g.Visibility == hiddenMembership, name, nil }, nil)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return needs(err, "Group.Read.All", "read the members of the groups")
}

func (st *state) emitGroup(g graph.Group) error {
	key := collector.GroupingKey(st.tenant, g.ID)
	sourceType, membership := "group", "static"
	if g.Dynamic() {
		sourceType, membership = "dynamic_group", "dynamic"
	}
	attrs := map[string]string{"membership": membership}
	setIf(attrs, "group_types", strings.Join(g.GroupTypes, ","))
	setIf(attrs, "membership_rule", g.MembershipRule)
	setIf(attrs, "membership_rule_state", g.MembershipRuleProcessingState)
	setIf(attrs, "visibility", g.Visibility)
	setIf(attrs, "on_premises_sid", g.OnPremisesSecurityIdentifier)
	if g.IsAssignableToRole != nil {
		attrs["is_assignable_to_role"] = strconv.FormatBool(*g.IsAssignableToRole)
	}
	if g.OnPremisesSyncEnabled != nil {
		attrs["on_premises_sync_enabled"] = strconv.FormatBool(*g.OnPremisesSyncEnabled)
	}
	name := g.DisplayName
	if name == "" {
		name = g.ID
	}
	if err := st.out.Node(collector.WithContext(collector.Grouping(key, name, sourceType), attrs)); err != nil {
		return err
	}
	st.note("groups", g.ID)
	if g.MembershipRuleProcessingState == "Paused" {
		// Its members are whatever the rule last decided. Nothing is keeping
		// them current, so a reviewer should not read them as current.
		if err := st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.membership.paused",
			fmt.Sprintf("dynamic membership processing is paused for group %q, so its members are not being "+
				"kept up to date and may be stale", name)); err != nil {
			return err
		}
	}

	return nil
}

const hiddenMembership = "HiddenMembership"

// reportSkipped says what a part left out because it is of a type this
// collector does not collect, once, in the part that left it out.
func (st *state) reportSkipped(phase string) error {
	if len(st.skipped) == 0 {
		return nil
	}
	kinds := make([]string, 0, len(st.skipped))
	for k := range st.skipped {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var parts []string
	for _, k := range kinds {
		label := k
		if label == "" {
			label = "of unknown type"
		}
		parts = append(parts, fmt.Sprintf("%d %s", st.skipped[k], label))
	}
	st.skipped = map[string]int{}
	return st.out.Diagnostic(collectorv1.Severity_SEVERITY_INFO, "entra.skipped",
		"objects of types this collector does not collect were left out of the "+phase+" part: "+strings.Join(parts, ", "))
}
