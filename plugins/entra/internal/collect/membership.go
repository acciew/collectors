package collect

import (
	"context"
	"errors"
	"fmt"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// The members of a group are read where the group is listed, and again by
// whatever reads a role the group holds, and a directory changes in between.
// What a role is held through a group for is a path, and a path is only a path
// if each hop was stated: so every read that finds a member states its place
// in the group, and the edge that says what it holds through the group comes
// from the same read. The two cannot disagree, because they are one answer.

// groupMembers reads a group's direct members, states each one's place in the
// group, and hands it to each. hidden says, if the read is refused, whether the
// group is one whose members need a permission of their own.
//
// A group read before in this stream, and small enough to keep, is not read
// again; its members were stated when it was. One too large to keep is read
// again a page at a time and stated again, which costs duplicate edges and
// nothing else.
func (st *state) groupMembers(ctx context.Context, id, name string, hidden func() (bool, string, error),
	each func(graph.DirectoryObject) error) error {
	if kept, ok := st.members[id]; ok {
		for _, m := range kept {
			if each == nil {
				break
			}
			if err := each(m); err != nil {
				return err
			}
		}
		return nil
	}
	group := collector.GroupingKey(st.tenant, id)
	var kept []graph.DirectoryObject
	keep := true
	counted := st.counted[id]
	err := pages(ctx, st, graph.MembersPath(id, st.pageSize), func(ms []graph.DirectoryObject) error {
		for _, m := range ms {
			if err := st.observe(ctx, m); err != nil {
				return err
			}
			if err := st.stateMembership(m, group, !counted); err != nil {
				return err
			}
			if each != nil {
				if err := each(m); err != nil {
					return err
				}
			}
		}
		if keep {
			if kept = append(kept, ms...); len(kept) > maxCachedMembers {
				keep, kept = false, nil
			}
		}
		return nil
	})
	var ge *graph.Error
	switch {
	case err == nil:
		st.counted[id] = true
		if keep && st.cachedTotal+len(kept) <= maxCachedTotal {
			st.members[id] = kept
			st.cachedTotal += len(kept)
		}
		return nil
	case errors.As(err, &ge) && ge.Kind == graph.KindPermission:
		// The members of a group with hidden membership need a permission of
		// their own. Refused, that group is the only thing unread, and what it
		// holds is still its own grant; any other group refused is the group
		// permission.
		isHidden, hiddenName, herr := hidden()
		if herr != nil {
			return herr
		}
		if isHidden {
			st.hiddenRefused(hiddenName)
			st.members[id] = nil
			return nil
		}
	case errors.As(err, &ge) && ge.Kind == graph.KindNotFound:
		// Listed, then deleted before its members were read: it has none, and
		// nothing holds a role through it. The group is not unread.
		st.members[id] = nil
		return st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.group.gone",
			fmt.Sprintf("group %q was deleted between listing it and reading its members, so it has none here", name))
	}
	return err
}

// stateMembership writes the edge that places a member in a group, if it is the
// kind of member this collector collects, and counts it if it is not.
func (st *state) stateMembership(m graph.DirectoryObject, group *collectorv1.Key, count bool) error {
	switch m.Kind() {
	case "user", "servicePrincipal":
		// Microsoft documents that the v1.0 list leaves service principals out.
		// If it ever returns one it is a member like any other, and the roles it
		// holds through the group are only paths if the membership was stated.
		subject, ok, err := st.holder(m)
		if err != nil || !ok {
			return err
		}
		return st.sendOnce(collector.MemberOf(subject, group))
	case "group":
		// Child first. Never expanded: a nested group's members are reached
		// through the edge that is here, and flattening them would state a
		// membership the source did not.
		child := collector.GroupingKey(st.tenant, m.ID)
		ok, _, err := st.named("groups", child, m.DisplayName, "group")
		if err != nil || !ok {
			return err
		}
		return st.sendOnce(collector.ChildOf(child, group))
	}
	if count {
		st.skipped[m.Kind()]++
	}
	return nil
}
