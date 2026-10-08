package collect

import (
	"context"
	"errors"
	"fmt"
	"sort"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
)

// permissionToRead is the application permission that lets Graph describe an
// object of a type, instead of answering for it with its type and id alone.
var permissionToRead = map[string]string{
	"user":             "User.Read.All",
	"group":            "Group.Read.All",
	"servicePrincipal": "Application.Read.All",
}

// confirmDenied asks whether the application may read objects of a member's
// type, by reading that object directly.
//
// An object that comes back as its type and id with a null name is how Graph
// answers a type the caller may not read, and it is also what an object with no
// name looks like. Only a refusal on reading the object itself tells them
// apart, and only that is called a missing permission. A read that could not be
// answered, a 404 for a member removed since or an outage that outlasts the
// retries, settles nothing: answered is false, and the caller asks again with
// another member rather than take silence for a yes. A throttle that will not
// end is an error, because the stream should stop there.
func confirmDenied(ctx context.Context, g *graph.Client, do retryFunc, m graph.DirectoryObject) (denied, answered bool, err error) {
	path, ok := graph.ObjectPath(m.Kind(), m.ID)
	if !ok {
		return false, false, nil
	}
	err = do(ctx, func() error { return g.Read(ctx, path) })
	var halt *stopError
	var ge *graph.Error
	switch {
	case err == nil:
		return false, true, nil
	case errors.As(err, &halt):
		return false, false, err
	case errors.As(err, &ge) && ge.Kind == graph.KindPermission:
		return true, true, nil
	}
	return false, false, nil
}

// memberKind is what has been found out about one type of member.
type memberKind struct {
	// settled says the question is answered, or has been given up on, and
	// answered that it was answered.
	settled, answered bool
	tries             int
}

// maxConfirmTries is how many members of a type are asked about before giving
// up on finding out whether the type can be read.
const maxConfirmTries = 3

// observe notes a group member that came back as an id alone. Whether a type
// can be read is one question and not one per member, so it is asked until it is
// answered, and not again.
func (st *state) observe(ctx context.Context, m graph.DirectoryObject) error {
	kind := m.Kind()
	if !m.IDOnly() || permissionToRead[kind] == "" {
		return nil
	}
	k := st.kinds[kind]
	if k.settled {
		return nil
	}
	denied, answered, err := confirmDenied(ctx, st.Graph, st.retrying, m)
	if err != nil {
		return err
	}
	k.tries++
	switch {
	case answered:
		k.settled, k.answered = true, true
		if denied {
			st.problem("unreadable:"+kind, refused("grant the application permission %s (admin consent) to read %s "+
				"objects: group members of that type came back as an id and nothing else, which is how Graph "+
				"answers an object the application may not read", permissionToRead[kind], kind))
		}
	case k.tries >= maxConfirmTries:
		k.settled = true
	}
	st.kinds[kind] = k
	return nil
}

// hiddenRefused notes that the members of a group with hidden membership were
// refused. They need a permission of their own, and the group is the only thing
// unread.
func (st *state) hiddenRefused(group string) {
	st.problem("hidden", refused("grant the application permission Member.Read.Hidden (admin consent) to read the "+
		"members of groups with hidden membership: the members of %q, for one, were refused", group))
}

// reportUnconfirmed says which types of member came back as an id alone and
// could not be confirmed either way, so that silence about them is not taken for
// a yes.
func (st *state) reportUnconfirmed() error {
	kinds := make([]string, 0, len(st.kinds))
	for kind, k := range st.kinds {
		if k.tries > 0 && !k.answered {
			kinds = append(kinds, kind)
		}
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		if err := st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.members.unconfirmed",
			fmt.Sprintf("%s group members came back as an id and nothing else, and whether the application may "+
				"read %s objects could not be found out, so they are not reported as a missing permission", kind, kind)); err != nil {
			return err
		}
		k := st.kinds[kind]
		k.tries = 0 // said once
		st.kinds[kind] = k
	}
	return nil
}
