// Command minimal is a reference collector.
//
// It has no external source: it returns a small fixed inventory. Its purpose
// is to be the shortest complete answer to "what does a collector look like",
// and to be the collector the core's own tests run against — core tests stay
// fast and Docker-free.
//
// The shape below is the shape of a real collector. A Keycloak or GitHub
// collector differs in where the data comes from and in nothing else.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

func main() { collector.Serve(&minimal{}) }

type minimal struct{}

const scope = "example"

func (m *minimal) Describe(context.Context) (*collector.Description, error) {
	return &collector.Description{
		Name:        "minimal",
		Version:     "0.1.0",
		Description: "A reference collector with a fixed, invented inventory.",
		Activity:    true,
		// Declare only what you actually emit. The host degrades against
		// this, and the conformance suite fails a plugin that emits a type it
		// did not declare.
		Fidelities: []collectorv1.Fidelity{collector.Direct, collector.Effective},
		NodeTypes: []collectorv1.NodeType{
			collectorv1.NodeType_NODE_TYPE_SCOPE,
			collectorv1.NodeType_NODE_TYPE_IDENTITY,
			collectorv1.NodeType_NODE_TYPE_GROUPING,
			collectorv1.NodeType_NODE_TYPE_ENTITLEMENT,
		},
		EdgeTypes: []collectorv1.EdgeType{
			collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF,
			collectorv1.EdgeType_EDGE_TYPE_HOLDS,
		},
		Signals: []collector.Signal{{
			Name:        "example_login",
			Description: "An invented login timestamp. Real collectors read this from the source.",
		}},
	}, nil
}

func (m *minimal) ValidateConfig(_ context.Context, config []byte) ([]collector.Issue, error) {
	// The empty field path addresses the document as a whole, which is where
	// a parse failure belongs: there is no field to point at yet.
	if len(config) == 0 {
		return []collector.Issue{{
			Severity: collectorv1.Severity_SEVERITY_ERROR,
			Code:     "minimal.config.empty",
			Message:  "a configuration document is required, even an empty JSON object",
		}}, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(config, &doc); err != nil {
		return []collector.Issue{{
			Severity: collectorv1.Severity_SEVERITY_ERROR,
			Code:     "minimal.config.malformed",
			Message:  "the configuration is not valid JSON: " + err.Error(),
		}}, nil
	}
	return nil, nil
}

func (m *minimal) TestConnection(context.Context, []byte) ([]collector.ScopeProbe, error) {
	return []collector.ScopeProbe{{
		Scope:             collector.Scope(scope, scope),
		Name:              "the example scope",
		Reachable:         true,
		ActivityAvailable: true,
	}}, nil
}

func (m *minimal) Collect(_ context.Context, req collector.CollectRequest, out collector.Stream) error {
	realm := collector.Scope(scope, scope)
	alice := collector.IdentityKey(scope, "alice")
	robot := collector.IdentityKey(scope, "svc-backup")
	platform := collector.GroupingKey(scope, "platform")
	admin := collector.EntitlementKey(scope, "admin")
	now := time.Now().UTC()
	window := collector.Window(now.Add(-30*24*time.Hour), now)

	// The inventory as an ordered list, so that resuming is a matter of
	// starting further down it. A real collector's list is a paged API and
	// the cursor is that API's page token; the shape is the same.
	records := []func() error{
		func() error { return out.Node(collector.ScopeNode(realm, "the example scope", "example_scope")) },
		func() error {
			return out.Node(collector.Identity(alice, "alice", "user", collector.Human, collector.Active))
		},
		// A non-human principal, because in a real tenant most of them are.
		func() error {
			return out.Node(collector.Identity(robot, "svc-backup", "service_account",
				collector.ServiceKind, collector.Active))
		},
		func() error { return out.Node(collector.Grouping(platform, "Platform", "group")) },
		func() error { return out.Node(collector.Entitlement(admin, "admin", "role")) },
		func() error { return out.Edge(collector.MemberOf(alice, platform)) },
		// The group holds the role; alice holds it through the group. Both
		// are emitted, because a derived grant's path has to be a walk over
		// edges that were actually stated.
		func() error { return out.Edge(collector.Holds(platform, admin, collector.Direct)) },
		func() error {
			return out.Edge(collector.Holds(alice, admin, collector.Effective, collector.Via(platform)...))
		},
		func() error {
			return out.Activity(collector.Seen(alice, "example_login", now, window, 0,
				now.Add(-2*time.Hour), collector.Exact))
		},
		// The service account has no login of its own, and saying "never"
		// would be a different claim from "we cannot answer for this one".
		func() error {
			return out.Activity(collector.Unavailable(robot, "example_login", now,
				"minimal.no_service_account_logins",
				"this example does not invent activity for service accounts"))
		},
	}

	from, restarted := resumePoint(req.ResumeFrom, len(records))
	if restarted {
		// The contract lets a collector that cannot read a cursor start over,
		// and requires it to say so under this code. Starting over silently
		// leaves an operator watching a resume take as long as a full run
		// with no reason given.
		if err := out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "cursor.rejected",
			"this build could not read the cursor it was given, so the collection started "+
				"from the beginning"); err != nil {
			return err
		}
	}

	var emitted uint64
	for i := from; i < len(records); i++ {
		if err := records[i](); err != nil {
			return err
		}
		emitted++
		// A checkpoint after every record, so the cursor always names a real
		// boundary. A real collector emits one per page.
		if err := out.Checkpoint(cursor(i + 1)); err != nil {
			return err
		}
		// Stop at a checkpoint boundary once the budget is spent, and say
		// where to pick up. Honouring this is what makes a collection that
		// cannot finish in one window still usable.
		if req.MaxRecords > 0 && emitted >= req.MaxRecords && i+1 < len(records) {
			// The scope is reported before the stop, because a scope nobody
			// reported is a scope the host never heard of, and a population
			// missing a scope it was never told about reads as whole.
			// The error arrives as ERROR_CODE_SOURCE_ERROR, which is not
			// what happened — the source was fine and the caller stopped us.
			// The contract has no code for a budget, so this is the least
			// wrong one until it does.
			if err := out.ScopeDone(collector.ScopeResult{
				Scope: realm, Status: collector.Partial,
				// The scope still answers about activity; the budget stopped
				// the stream, not the source. Dropping it here would have
				// the two halves of a resumed pair disagree about the same
				// scope.
				ActivityAvailable: true,
				Err:               errors.New("the record budget ran out before this scope was finished"),
			}); err != nil {
				return err
			}
			return &collector.Incomplete{
				Cause:      collector.BudgetExhausted,
				ResumeFrom: cursor(i + 1),
			}
		}
	}

	// What this stream did with the scope, not what the pair of them did. A
	// continuation carrying half the records has not collected the scope, and
	// saying it has is how a reader of one stream concludes they have
	// everything.
	result := collector.ScopeResult{Scope: realm, Status: collector.Collected, ActivityAvailable: true}
	if from > 0 {
		result = collector.ScopeResult{
			Scope: realm, Status: collector.Partial,
			// Still true, and still needed: the flag says whether this scope
			// can answer about activity at all, not whether this stream
			// finished it. Dropping it would say nobody in the scope has an
			// activity answer while the stream carries one.
			ActivityAvailable: true,
			Err: fmt.Errorf("this stream resumed after record %d and carries the rest; the "+
				"earlier part of the scope is in the stream that produced the cursor", from),
		}
	}
	if err := out.ScopeDone(result); err != nil {
		return err
	}

	// A stream that started from a cursor carries the rest of a population
	// and not the whole of one, however cleanly it ran. Ending it COMPLETE
	// would let a caller read a continuation as an inventory, which is the
	// one thing this contract exists to prevent. A restart is different: it
	// ignored the cursor and collected everything, and said so above.
	// from > 0 means a cursor was given, was readable, and skipped something.
	// A fresh collection has from == 0 and is whole; a restart collected
	// everything and said so above.
	if from > 0 {
		return &collector.Incomplete{
			Cause: collector.PartialStream,
			// Saying which part. A cursor naming the end produces a stream
			// with nothing in it, and "incomplete" with no reason reads like
			// a failure rather than like the last page being empty.
			// The message, not the code: a continuation is not an error and
			// the contract has no code that says so, which is the same gap
			// the budget stop above runs into.
			Err: fmt.Errorf("resumed after record %d of %d, so this stream carries the "+
				"remaining %d and not the whole population",
				from, len(records), len(records)-from),
		}
	}
	return nil
}

// cursor and resumePoint are the whole of this collector's resume protocol:
// an index into the list above. The host never looks inside it.
func cursor(next int) []byte { return []byte(strconv.Itoa(next)) }

// resumePoint reads a cursor, and says whether it had to give up on one.
//
// A cursor this build cannot read is not a reason to fail: the contract
// allows starting over. It also requires saying so, which is the second
// return — a caller left to wonder why the work was repeated is the thing
// that rule exists to prevent.
func resumePoint(token []byte, records int) (int, bool) {
	if len(token) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(string(token))
	// Any position this build could not have written counts as unreadable.
	// Past the end would otherwise collect nothing and report a whole
	// population of nobody; zero would collect everything and call it a
	// continuation. The checkpoints above start at one. Spellings this build
	// would not produce but Atoi accepts — "+1", "01" — are honoured rather
	// than refused, because the position is the thing that matters.
	if err != nil || n < 1 || n > records {
		return 0, true
	}
	return n, false
}
