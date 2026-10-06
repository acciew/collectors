package collector

import (
	"context"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// Collector is what a plugin implements. Four methods, and none of them
// mentions a transport, a socket or a protobuf service.
//
// The host calls Describe before it has any configuration, so it must answer
// from what the plugin is rather than from what it is pointed at. Everything
// config-dependent belongs in TestConnection.
type Collector interface {
	// Describe reports what this plugin can do. The host degrades against
	// what you claim here rather than assuming, so an honest narrow answer is
	// worth more than a broad one.
	Describe(context.Context) (*Description, error)

	// ValidateConfig checks a configuration document without contacting the
	// source. Return one issue per problem, addressed by JSON Pointer, so a
	// CLI can point at the field rather than at the file.
	ValidateConfig(ctx context.Context, config []byte) ([]Issue, error)

	// TestConnection contacts the source and reports which scopes the
	// credentials actually reach. A scope the credentials cannot see is a
	// result, not an error: the operator needs the list to fix it.
	TestConnection(ctx context.Context, config []byte) ([]ScopeProbe, error)

	// Collect streams the inventory into the Stream.
	//
	// Return nil only when every requested scope was collected. Return
	// Incomplete when the population is not whole -- rate limits, a budget,
	// an unreachable scope -- and the host will surface that to the caller
	// rather than presenting a partial population as a complete one.
	//
	// Honour req.ResumeFrom if you can. If you cannot use a cursor you may
	// start over, but say so with a Diagnostic so nobody is surprised by the
	// duplicate work.
	Collect(ctx context.Context, req CollectRequest, out Stream) error
}

// Description is a plugin's answer to "what are you and what can you do".
type Description struct {
	// Stable identifier, e.g. "keycloak". Not the configured instance.
	Name string
	// Your build version, semver.
	Version string
	// One paragraph, shown by `acciew plugins list`.
	Description string

	// Whether you may emit Activity records. If false you emit none, ever.
	Activity bool
	// Every Fidelity you may put on an edge. Emitting one you did not declare
	// fails conformance.
	Fidelities []collectorv1.Fidelity
	// Every node and edge type you may emit.
	NodeTypes []collectorv1.NodeType
	EdgeTypes []collectorv1.EdgeType

	// What your data does not mean. Required when you declare Coarse: a
	// coarse entitlement model is a limit on what a reviewer can conclude,
	// and it belongs in the contract rather than only in your README.
	Limitations []Limitation
	// Every distinct activity signal you may emit. Required when Activity is
	// true: "I have activity data" without naming the signal is not a claim a
	// reviewer can weigh.
	Signals []Signal
}

// Limitation is a declared limit on what this plugin's data means.
type Limitation struct {
	Code      string
	Summary   string
	DetailURL string
}

// Signal is one kind of activity evidence.
type Signal struct {
	// Your own name for it: "login_event", "client_login_event",
	// "role_last_used". Not normalised across sources.
	Name string
	// What it means and, more usefully, what it misses.
	Description string
	// The lag the source documents for it, if any.
	TypicalLag time.Duration
}

// Issue is one finding about a configuration document.
type Issue struct {
	// RFC 6901 JSON Pointer, e.g. "/realms/0". Empty addresses the whole
	// document: malformed JSON, a missing section.
	Field string
	// Only Error blocks use.
	Severity collectorv1.Severity
	Code     string
	Message  string
}

// ScopeProbe is one discovered scope and whether the credentials reach it.
type ScopeProbe struct {
	// A scope key, from Scope().
	Scope *collectorv1.Key
	// A human name: the realm name, the org login, the account alias.
	Name string
	// False reads as "not reached", which is the safe direction.
	Reachable bool
	// Required when Reachable is false. An operator has to fix something, so
	// tell them what.
	Err error
	// Whether activity data exists for this scope at all. A Keycloak realm
	// with event storage off answers nothing for anyone in it.
	ActivityAvailable bool
	// ActivityUndetermined says the plugin could not find out, as opposed to
	// finding out that there is nothing. The call that would have answered
	// failed, typically on a permission, and that sends an operator to check
	// a credential rather than to switch something on.
	ActivityUndetermined bool
	// Why not, in terms an operator can act on. "Event storage is off for
	// this realm" tells somebody what to turn on; the flag alone does not.
	// Leave empty when activity is available.
	ActivityNote string
}

// CollectRequest is what the host asked for.
type CollectRequest struct {
	// The configuration document, as given to ValidateConfig.
	Config []byte
	// Scope ids to collect. Empty means every scope the credentials reach.
	Scopes []string
	// A cursor from a previous run's Checkpoint, or nil to start fresh.
	ResumeFrom []byte
	// Stop at the next checkpoint boundary after either limit. Zero means no
	// limit.
	MaxRecords  uint64
	MaxDuration time.Duration
	// Heartbeat is how often the caller wants to hear something while you
	// work, so it can tell "slow" from "stuck". Nothing sends one for you:
	// a collector that goes quiet between pages emits a Progress itself.
	// Zero means the caller did not say.
	Heartbeat time.Duration
}
