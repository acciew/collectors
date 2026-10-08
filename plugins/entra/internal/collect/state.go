package collect

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// state is what one call to Collect accumulates.
type state struct {
	Run
	req collector.CollectRequest
	out collector.Stream
	// lim is out, counting what goes past it.
	lim      *limited
	wants    Wanted
	pageSize int
	started  time.Time

	// phase is the part being read and firstPage the request that begins it.
	// pagesRead is how many pages of their own each part has read.
	phase     string
	firstPage string
	pagesRead map[string]int
	// lastEvent is when this stream last told its caller it was alive.
	lastEvent time.Time
	// stopErr is why the stream stopped.
	stopErr error

	// done and failed are the parts that ended and the parts that failed, and
	// problems the reasons the tenant is not whole. A collection is one stream
	// and keeps them in memory.
	done     map[string]bool
	failed   map[string]bool
	problems []problem

	tenant string
	scope  *collectorv1.Key
	// created is when the tenant was made, zero when it could not be read.
	created time.Time
	// observed is when this stream read the tenant, the time activity is
	// reported as of.
	observed time.Time
	// activity is whether the tenant answers about sign-in activity.
	activity ActivityAnswer

	// seen is the nodes emitted by this stream, so a node several records need
	// is written once.
	seen map[string]bool
	// skipped counts group members of types this collector does not collect.
	skipped map[string]int
	// kinds is what is known of the types of member that came back as an id
	// alone.
	kinds map[string]memberKind
	// nested counts groups inside groups that hold an app role, and pim the
	// schedule instances left out, by reason.
	nested int
	pim    map[string]int
	// names caches service principal display names looked up by id, and
	// principals what an id named by a role assignment turned out to be.
	names      map[string]string
	principals map[string]principalAnswer
	// members caches a group's direct members, so a group is read once however
	// many roles it holds, and cachedTotal how many are held. counted is the
	// groups whose members of a kind not collected were counted, once.
	members     map[string][]graph.DirectoryObject
	cachedTotal int
	counted     map[string]bool
	// rosters is what each part that writes nodes has written, and leftOut
	// counts what was left out for a part that failed.
	rosters map[string]*roster
	leftOut map[string]int
	// sent is the edges that can be sent twice (memberships and grants) this
	// stream has sent, by a hash of their type, ends and path.
	sent map[[16]byte]struct{}

	roles map[string]graph.RoleDefinition
}

func (r Run) newState(_ context.Context, req collector.CollectRequest, out collector.Stream) *state {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Wait == nil {
		r.Wait = pause
	}
	st := &state{
		Run: r, req: req, out: out,
		wants: r.Config.Wants(), pageSize: r.Config.PageSize, started: r.Now(), observed: r.Now().UTC(),
		done: map[string]bool{}, failed: map[string]bool{}, pagesRead: map[string]int{},
		seen: map[string]bool{}, skipped: map[string]int{}, kinds: map[string]memberKind{}, members: map[string][]graph.DirectoryObject{}, counted: map[string]bool{},
		rosters: map[string]*roster{}, leftOut: map[string]int{}, sent: map[[16]byte]struct{}{}, pim: map[string]int{}, names: map[string]string{}, principals: map[string]principalAnswer{},
	}
	for _, p := range owners {
		st.rosters[p] = &roster{ids: map[uint64]struct{}{}}
	}
	st.lastEvent = st.started
	st.tenant = r.Graph.TenantID()
	if st.tenant == "" {
		st.tenant = r.Config.TenantID
	}
	st.scope = collector.Scope(st.tenant, st.tenant)
	return st
}

func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// requested says whether the caller's scope selection includes the tenant. An
// empty selection means every scope the credential reaches, and there is one.
func (st *state) requested(scopes []string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if s == st.tenant || strings.EqualFold(s, st.Config.TenantID) {
			return true
		}
	}
	return false
}

// unrequested ends a collection that named only scopes this credential does
// not reach. Reporting a whole population of nothing would be the lie.
func (st *state) unrequested(scopes []string) error {
	err := fmt.Errorf("this credential reaches tenant %s and none of the scopes asked for (%s)",
		st.tenant, strings.Join(scopes, ", "))
	for _, s := range scopes {
		if s == "" {
			continue
		}
		// The outcome names a scope, and a scope is a node: this one was asked
		// for and not reached, so it is written as referenced.
		if e := st.lim.writeScope(collector.Reference(collector.Scope(s, s), s, "tenant")); e != nil {
			return e
		}
		if e := st.out.ScopeDone(collector.ScopeResult{
			Scope: collector.Scope(s, s), Status: collector.Unreachable, Err: err,
			ActivityUndetermined: true,
		}); e != nil {
			return e
		}
	}
	return &collector.Incomplete{Cause: collector.ScopeUnreachable, Err: err}
}

// announce emits the tenant as the one scope, named by the organisation when
// the credential may read it.
func (st *state) announce(ctx context.Context) error {
	name, attrs := st.tenant, map[string]string{"tenant_id": st.tenant, "cloud": string(st.Config.Cloud())}
	var page graph.Page[graph.Organization]
	err := st.retrying(ctx, func() error {
		var err error
		page, err = graph.GetPage[graph.Organization](ctx, st.Graph, graph.OrganizationPath())
		return err
	})
	// A throttle that will not end ends the stream, with the scope written first:
	// the outcome that says why names it.
	var halt *stopError
	if errors.As(err, &halt) {
		if e := st.lim.writeScope(collector.WithContext(collector.ScopeNode(st.scope, name, "tenant"), attrs)); e != nil {
			return e
		}
		return err
	}
	switch {
	case err == nil && len(page.Items) > 0:
		org := page.Items[0]
		if org.DisplayName != "" {
			name = org.DisplayName
		}
		if org.Created != nil {
			st.created = org.Created.UTC()
			attrs["created"] = st.created.Format(time.RFC3339)
		}
	default:
		// The name is a convenience and the tenant is collectable without it,
		// so this says so and goes on.
		why := "no organization was returned"
		if err != nil {
			why = err.Error()
		}
		msg := "the organization's name could not be read, so the tenant is named by its ID (" + why + ")"
		// Only a refusal is a permission to grant; an outage is not.
		var ge *graph.Error
		if errors.As(err, &ge) && ge.Kind == graph.KindPermission {
			msg += ". Organization.Read.All allows it"
		}
		if e := st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.organization.unreadable", msg); e != nil {
			return e
		}
	}
	return st.lim.writeScope(collector.WithContext(collector.ScopeNode(st.scope, name, "tenant"), attrs))
}

// finish records what happened to the scope.
func (st *state) finish(status collectorv1.ScopeStatus, why error) error {
	return st.out.ScopeDone(collector.ScopeResult{
		Scope: st.scope, Status: status, Err: why,
		ActivityAvailable:    st.activity.State == ActivityAvailable,
		ActivityUndetermined: st.activity.State == ActivityUndetermined,
	})
}

// stop ends the collection with a cause. Nothing is offered to resume from: a
// collection starts from the beginning.
//
// Failures are carried whatever the cause: a throttle that stops the stream
// after a part failed must not drop the failure, because it is the one thing an
// operator has to fix.
func (st *state) stop(cause collectorv1.IncompleteCause) error {
	if err := st.reportSkipped(st.phase); err != nil {
		return err
	}
	if err := st.reportLeftOut(st.phase); err != nil {
		return err
	}
	if err := st.reportUnconfirmed(); err != nil {
		return err
	}
	var why error
	if len(st.problems) > 0 || st.stopErr != nil {
		why = errors.Join(append(st.problemErrors(), st.stopErr)...)
	}
	status := collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL
	if why == nil {
		status = collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED
	}
	if err := st.finish(status, why); err != nil {
		return err
	}
	return &collector.Incomplete{Cause: cause, Err: why}
}

// problem records a reason the tenant is not whole, once for each key. The kind
// of failure is kept with it.
func (st *state) problem(key string, err error) {
	for _, p := range st.problems {
		if p.Key == key {
			return
		}
	}
	fault := collector.FaultSource
	var faulty interface{ Fault() collector.Fault }
	if errors.As(err, &faulty) {
		fault = faulty.Fault()
	}
	st.problems = append(st.problems, problem{Key: key, Text: clip(err.Error(), maxProblemText), Fault: int(fault)})
}

// clip cuts text to at most n bytes of whole characters. A cut through the
// middle of one leaves bytes that are not text, and a message that is not valid
// UTF-8 cannot be sent: the host would get a transport error in place of the
// verdict.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

// faulted is an error with a stated kind, which is what the SDK reads to say
// "grant this" and not "the source failed".
type faulted struct {
	text  string
	fault collector.Fault
}

func (e *faulted) Error() string { return e.text }

func (e *faulted) Fault() collector.Fault { return e.fault }

// partial is a read that stopped after it had begun. It is the source failing,
// whatever the answer said, and not a permission to grant.
type partial struct {
	err  error
	text string
}

func (e *partial) Error() string { return e.text + ": " + e.err.Error() }

func (e *partial) Unwrap() error { return e.err }

func (e *partial) Fault() collector.Fault { return collector.FaultSource }

// refused is an error for a permission the application lacks.
func refused(format string, args ...any) error {
	return &faulted{text: fmt.Sprintf(format, args...), fault: collector.FaultPermission}
}

func (st *state) problemErrors() []error {
	out := make([]error, 0, len(st.problems))
	for _, p := range st.problems {
		out = append(out, &faulted{text: p.Text, fault: collector.Fault(p.Fault)})
	}
	return out
}

// checkpoint offers the one point a collection can be resumed from: its start,
// before anything was sent. Resuming from it reads the tenant from the beginning,
// which is all that resuming could do. See the README.
func (st *state) checkpoint() error {
	if err := st.out.Checkpoint([]byte(checkpointToken)); err != nil {
		return err
	}
	st.mark()
	return nil
}

// checkpointToken is the cursor a stream offers: a few bytes, naming no place.
const checkpointToken = `{"v":1}`

// mark notes that the caller has just heard from this stream.
func (st *state) mark() { st.lastEvent = st.Now() }

// beat tells the caller the stream is alive when it has been quiet for the
// heartbeat it asked for. Nothing sends one for a collector: a read that goes
// an hour between pages has to say so itself.
func (st *state) beat() error {
	interval := st.req.Heartbeat
	if interval <= 0 {
		interval = defaultHeartbeat
	}
	if st.Now().Sub(st.lastEvent) < interval {
		return nil
	}
	st.mark()
	return st.out.Progress(st.phase, nil)
}

// defaultHeartbeat is the silence a stream allows itself when the caller did
// not say how long it will tolerate.
const defaultHeartbeat = 30 * time.Second

// once reports whether a node is new to this stream.
func (st *state) once(k *collectorv1.Key) bool {
	id := fmt.Sprintf("%d\x00%s\x00%s", k.GetType(), k.GetScope(), k.GetId())
	if st.seen[id] {
		return false
	}
	st.seen[id] = true
	return true
}

// fetch reads one page, waiting out a throttle or an outage as retry.go says.
func fetch[T any](ctx context.Context, st *state, target string) (graph.Page[T], error) {
	var page graph.Page[T]
	err := st.retrying(ctx, func() error {
		var err error
		page, err = graph.GetPage[T](ctx, st.Graph, target)
		return err
	})
	return page, err
}

// errRepeated is what a collection whose next-page link comes back is told.
func repeated(link string) error {
	return &graph.Error{Kind: graph.KindSource, Message: "Graph returned the same page link twice (" + pathOf(link) +
		"); reading on would never end"}
}

func pathOf(link string) string {
	if i := strings.Index(link, "?"); i >= 0 {
		link = link[:i]
	}
	return link
}

// pageSignature names a page by the ids of what is on it. Zero means the page is
// empty or of a kind that is not checked: an empty page with a next link is
// something Graph does.
func pageSignature(items any) uint64 {
	var ids []string
	switch v := items.(type) {
	case []graph.DirectoryObject:
		for _, i := range v {
			ids = append(ids, i.ID)
		}
	case []graph.AppRoleAssignment:
		for _, i := range v {
			ids = append(ids, i.ID)
		}
	case []graph.RoleDefinition:
		for _, i := range v {
			ids = append(ids, i.ID)
		}
	}
	if len(ids) == 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(strings.Join(ids, "\x00")))
	return binary.BigEndian.Uint64(sum[:8]) | 1
}

// readCeiling is the most pages one read may take: a part's own collection, or
// what is read inside a page of something else, such as the members of a group.
// A next link that is never the same twice and never ends would otherwise read
// for ever. It is a variable so that a test can lower it.
var readCeiling = maxPartPages

// maxPartPages is more pages than any one part of any tenant has: users at the
// smallest page size Graph returns with activity, for a million of them.
const maxPartPages = 100_000

// pages reads a collection to its end, handing each page to fn. A link that
// comes back is a loop; so is a page that does, under a link that does not; and
// a read that reaches the ceiling is stopped. Each is a failure of the part,
// because a read that never ends is worse than one that does not finish.
func pages[T any](ctx context.Context, st *state, first string, fn func([]T) error) error {
	seen := map[string]bool{st.digest(first): true}
	said := map[uint64]bool{}
	read := 0
	for target := first; target != ""; {
		page, err := fetch[T](ctx, st, target)
		if err != nil {
			return err
		}
		// A next link that is never the same twice but a page that is, is a
		// source going round: stop on the page that says nothing new, not a
		// hundred thousand pages on.
		if sig := pageSignature(page.Items); sig != 0 {
			if said[sig] {
				return &graph.Error{Kind: graph.KindSource, Message: "Graph returned the same page twice (" + pathOf(first) +
					") under different links; reading on would never end"}
			}
			said[sig] = true
		}
		if err := fn(page.Items); err != nil {
			return err
		}
		if err := st.beat(); err != nil {
			return err
		}
		read++
		if page.Next != "" {
			next := st.digest(page.Next)
			if seen[next] {
				return repeated(page.Next)
			}
			if read >= readCeiling {
				return &graph.Error{Kind: graph.KindSource, Message: fmt.Sprintf("read %d pages of %s and Graph still names another; reading on would never end", read, pathOf(first))}
			}
			seen[next] = true
		}
		target = page.Next
	}
	return nil
}

// walk reads a part's own collection page by page, and counts the pages the
// part has read.
func walk[T any](ctx context.Context, st *state, fn func([]T) error) error {
	return pages(ctx, st, st.firstPage, func(items []T) error {
		st.pagesRead[st.phase]++
		return fn(items)
	})
}

// digest names a page link in few bytes, whichever way it is spelled.
func (st *state) digest(link string) string {
	abs := st.Graph.Absolute(link)
	if abs == "" {
		abs = link
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:8])
}

// readsActivity says whether the users are read with their sign-in activity.
func (st *state) readsActivity() bool { return st.activity.State == ActivityAvailable }

// fail marks a part failed, with the reason.
func (st *state) fail(part string, err error) {
	st.failed[part] = true
	st.problem("part:"+part, fmt.Errorf("%s: %w", part, err))
}

// needs names the permission a refused read wants, so that a collection says
// what the check says about the same failure. Only a refusal: anything else is
// not about a grant, and naming one sends somebody to change a permission that
// was never the problem.
func needs(err error, permission, what string) error {
	var ge *graph.Error
	if err == nil || !errors.As(err, &ge) || ge.Kind != graph.KindPermission {
		return err
	}
	return fmt.Errorf("grant the application permission %s (admin consent) to %s: %w", permission, what, err)
}
