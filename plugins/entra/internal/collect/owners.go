package collect

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"sort"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

// Parts name each other's nodes: a group member names a user, a role assignment
// names a group, an app role assignment names a user. A directory is not a
// snapshot, so an edge can name something the part that owns it never wrote,
// because it was made after the part ran or because the part did not finish.
// Either way the edge would name a node nobody emitted, and the store would
// refuse the collection that holds it.
//
// The parts that write nodes (users, service principals, administrative units
// and groups) run before the parts that write edges, so by the time an edge is
// written its owner has ended or failed:
//
//   - The owner failed: it wrote some of its nodes and not others, and which is
//     not known. An edge naming one of them is left out, and counted.
//   - The owner ended and wrote the node: the edge is written.
//   - The owner ended and did not write the node: it did not exist then. It is
//     written here, as referenced, which is what it is: seen as the subject of
//     a grant or a member, and not read.
//
// A collection is one stream and keeps what each owner wrote in memory, so the
// answer is exact. What it keeps is a hash of each id, and an owner cannot write
// more than the stream may send (see limit.go). See the README: Entra does not
// resume.

// owners are the parts that write the nodes the other parts name.
var owners = []string{"users", "service_principals", "administrative_units", "groups"}

func hashID(id string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return h.Sum64()
}

// roster is the ids an owner wrote.
type roster struct {
	ids map[uint64]struct{}
}

// note records that a part wrote the node with this id.
func (st *state) note(part, id string) {
	if r := st.rosters[part]; r != nil {
		r.ids[hashID(id)] = struct{}{}
	}
}

// named says an edge may name the node with this id, which a part owns. It
// writes the node, as referenced, when the part ended and did not write it.
// False means the part failed and the edge is to be left out; it is counted, and
// said by the part that left it out.
func (st *state) named(part string, key *collectorv1.Key, name, sourceType string) (ok, referenced bool, err error) {
	if st.failed[part] {
		st.leftOut[part]++
		return false, false, nil
	}
	r := st.rosters[part]
	if r == nil || !st.done[part] {
		return true, false, nil
	}
	if _, wrote := r.ids[hashID(key.GetId())]; wrote || !st.once(key) {
		return true, false, nil
	}
	if name == "" {
		name = key.GetId()
	}
	return true, true, st.out.Node(collector.Reference(key, name, sourceType))
}

var leftOutNouns = map[string]string{
	"users":                "users",
	"groups":               "groups",
	"service_principals":   "service principals and applications",
	"administrative_units": "administrative units",
}

// reportLeftOut says how much the part that just ended left out for want of a
// node a part that failed would have written.
func (st *state) reportLeftOut(phase string) error {
	failed := make([]string, 0, len(st.leftOut))
	for owner := range st.leftOut {
		failed = append(failed, owner)
	}
	sort.Strings(failed)
	for _, owner := range failed {
		n := st.leftOut[owner]
		delete(st.leftOut, owner)
		if err := st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.edges.left-out",
			fmt.Sprintf("%d grants, memberships or groups naming %s were left out of the %s part: the %s part failed, "+
				"so the nodes they would join were not collected", n, leftOutNouns[owner], phase, owner)); err != nil {
			return err
		}
	}
	return nil
}

// skipFor says a part that only names what another part owns was not run,
// because the other failed and every edge it would write would be left out.
func (st *state) skipFor(part, owner, what string) error {
	return st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.edges.left-out",
		fmt.Sprintf("the %s part was not run: the %s part failed, so every %s it would write names a node that was "+
			"not collected", part, owner, what))
}

// sendOnce sends an edge unless this stream already has. Two instances of one
// eligibility, or a group read again for each role it holds, are one edge, and the
// service refuses a record it is sent twice. An edge is remembered by 16 bytes of
// a hash of its type, ends and path, so what is kept is bounded by the events the
// stream may send.
func (st *state) sendOnce(e *collectorv1.Edge) error {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%d\x00%s\x00%d\x00%s", e.GetType(), e.GetFrom().GetScope(), e.GetFrom().GetType(), e.GetFrom().GetId(),
		e.GetTo().GetType(), e.GetTo().GetId())
	for _, v := range e.GetPath().GetVia() {
		fmt.Fprintf(h, "\x00%d\x00%s", v.GetType(), v.GetId())
	}
	var id [16]byte
	copy(id[:], h.Sum(nil))
	if _, sent := st.sent[id]; sent {
		return nil
	}
	st.sent[id] = struct{}{}
	return st.out.Edge(e)
}
