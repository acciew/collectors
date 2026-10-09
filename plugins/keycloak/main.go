// Command keycloak is the Keycloak collector.
//
// Built exactly as a third party would build it: its own module, depending on
// the SDK and the contract and never on the server. It reads through the
// Admin REST API only — no SPI, no Java — and it never writes.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/plugins/keycloak/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

// version is stamped at build time; the default is what a local build reports.
var version = "0.2.0-dev"

// masterRealm is the only realm that can administer another.
const masterRealm = "master"

func main() { collector.Serve(&keycloak{}) }

type keycloak struct{}

func (k *keycloak) Describe(context.Context) (*collector.Description, error) {
	return &collector.Description{
		Name:        "keycloak",
		Version:     version,
		Description: "Collects identities, groups, roles and clients from Keycloak realms over the Admin REST API.",
		// Whether any given realm can answer is a per-realm fact, reported
		// on each scope: event storage is off by default, so most realms
		// answer nothing until an operator turns it on.
		Activity: true,
		Fidelities: []collectorv1.Fidelity{
			collector.Direct,
			// Keycloak can be resolved: composites and group inheritance are
			// enumerable, so a grant reached through them is EFFECTIVE and we
			// stand behind it. Nothing here is COARSE.
			collector.Effective,
		},
		NodeTypes: []collectorv1.NodeType{
			collectorv1.NodeType_NODE_TYPE_SCOPE,
			collectorv1.NodeType_NODE_TYPE_IDENTITY,
			collectorv1.NodeType_NODE_TYPE_GROUPING,
			collectorv1.NodeType_NODE_TYPE_ENTITLEMENT,
			collectorv1.NodeType_NODE_TYPE_RESOURCE,
		},
		EdgeTypes: []collectorv1.EdgeType{
			collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF,
			collectorv1.EdgeType_EDGE_TYPE_CHILD_OF,
			collectorv1.EdgeType_EDGE_TYPE_HOLDS,
			collectorv1.EdgeType_EDGE_TYPE_INCLUDES,
			collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO,
		},
		Signals: []collector.Signal{
			{
				Name: collect.SignalLogin,
				Description: "An interactive login by a person, from the realm event log. " +
					"Exact, and bounded by the realm's event retention.",
			},
			{
				Name: collect.SignalClientLogin,
				Description: "A service account obtaining a token. Keycloak records this as " +
					"CLIENT_LOGIN rather than LOGIN, so a collector that asks only for LOGIN " +
					"reports every service account as never used.",
			},
		},
		Limitations: []collector.Limitation{
			{
				Code: "keycloak.realm-scoped",
				Summary: "A realm is an isolation boundary. Identities are not correlated across " +
					"realms, because Keycloak does not correlate them either.",
			},
			{
				Code: "keycloak.activity-needs-event-storage",
				Summary: "Last activity comes from the realm event log, which Keycloak leaves off " +
					"by default. A realm without it answers nothing for anyone in it, and turning " +
					"it on records from that moment: the past cannot be filled in.",
			},
		},
	}, nil
}

func (k *keycloak) ValidateConfig(_ context.Context, raw []byte) ([]collector.Issue, error) {
	_, issues := collect.Validate(raw)
	return issues, nil
}

func (k *keycloak) TestConnection(ctx context.Context, raw []byte) ([]collector.ScopeProbe, error) {
	client, cfg, err := dial(ctx, raw)
	if err != nil {
		return nil, err
	}
	realms, err := client.Realms(ctx)
	if err != nil {
		return nil, cannotListRealms(client, cfg, err)
	}

	var probes []collector.ScopeProbe
	// OnePage: a check asks whether a read is allowed, not what it
	// returns, and checking a realm of a hundred thousand users should not
	// download a hundred thousand users to find out.
	for _, p := range collect.Probes(ctx, client.OnePage(), realms, requested(cfg)) {
		probe := collector.ScopeProbe{
			Scope:                collector.Scope(p.Realm, p.Realm),
			Name:                 p.Realm,
			Reachable:            p.Reachable,
			Err:                  p.Err,
			ActivityAvailable:    p.ActivityAvailable,
			ActivityUndetermined: p.ActivityUndetermined,
			// The actionable half: "no activity" without "turn on event
			// storage" leaves an operator with nothing to do.
			ActivityNote: p.ActivityNote,
		}
		probes = append(probes, probe)
	}
	return probes, nil
}

func (k *keycloak) Collect(ctx context.Context, req collector.CollectRequest, out collector.Stream) error {
	// A raw error here is reported as a plugin error — a defect in this
	// code — and a lost role, a rotated secret and an unreachable Keycloak
	// are none of those. The check already says which of them it is; a
	// scheduled run, which is the only thing that runs this, deserves the
	// same answer.
	client, cfg, err := dial(ctx, req.Config)
	if err != nil {
		// The cause, not only the error code: the host reads the cause, and
		// a configuration failure filed under "source error" sends an
		// operator to a Keycloak that was never contacted.
		return &collector.Incomplete{Cause: collector.CauseFor(err), Err: err}
	}
	realms, err := client.Realms(ctx)
	if err != nil {
		// The same sentence the check gives, for the same failure. A
		// scheduled run getting a shorter answer than the pre-flight did is
		// the two disagreeing in a quieter form.
		return &collector.Incomplete{Cause: collector.SourceFailed,
			Err: cannotListRealms(client, cfg, err)}
	}
	// A caller may narrow further than the configuration does.
	if len(req.Scopes) == 0 {
		req.Scopes = configured(cfg)
	}
	return collect.All(ctx, client, realms, req, out)
}

// cannotListRealms turns a refused realm listing into the one thing an
// operator can act on.
//
// The first state anybody is in: the client exists, nothing is granted to its
// service account, and every realm read is refused. Returned raw it is a
// transport error to decode.
func cannotListRealms(client *admin.Client, cfg collect.Config, err error) error {
	// Only a refusal says anything about the grant. Telling somebody to add
	// roles because Keycloak was briefly unwell, or because the secret was
	// rotated, sends them to change a permission that was never the problem.
	var ae *admin.Error
	if !errors.As(err, &ae) || ae.Kind != admin.KindPermission {
		return fmt.Errorf("the realms could not be listed: %w", err)
	}
	// Where the roles live, and which realms this client could ever collect.
	// Only master administers another realm, so naming "each realm you
	// collect" anywhere else describes a route that does not exist.
	where := "realm-management inside " + cfg.AuthRealm
	reach := fmt.Sprintf(". Only master can administer another realm, so this client, "+
		"authenticating against %s, can collect that realm and no other", cfg.AuthRealm)
	if cfg.AuthRealm == masterRealm {
		where = "the <realm>-realm client in master, one for each realm you collect"
		reach = ""
	}
	// A token carrying no roles at all is a different problem from one
	// carrying the wrong roles, and it is visible from here.
	if _, known := client.GrantedRoles(cfg.AuthRealm); !known {
		reach += ". This token also carries no statement of the roles it holds, so if they " +
			"are granted already, either the client's full scope is off, its roles client " +
			"scope was removed, or lightweight access tokens are on for it"
	}
	return fmt.Errorf("this token cannot list realms, so no realm can be read. Grant its "+
		"service account view-users, view-clients and view-realm (and view-events for "+
		"last-activity) on %s%s: %w", where, reach, err)
}

// dial resolves the configuration and connects.
func dial(ctx context.Context, raw []byte) (*admin.Client, collect.Config, error) {
	cfg, issues := collect.Validate(raw)
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			// Marked where it happens, so the cause and the code cannot drift
			// apart later. Everything past the resolve below is Keycloak.
			return nil, cfg, collector.BadConfig(
				fmt.Errorf("configuration: %s: %s", i.Field, i.Message))
		}
	}
	secret, err := resolveSecret(cfg.ClientSecret)
	if err != nil {
		// The reference is in the document and the thing it points at is not
		// there. Either way the fix is in the deployment, not in Keycloak.
		return nil, cfg, collector.BadConfig(err)
	}
	client, err := admin.Dial(ctx, admin.Config{
		BaseURL: cfg.BaseURL, AuthRealm: cfg.AuthRealm,
		ClientID: cfg.ClientID, ClientSecret: secret, PageSize: cfg.PageSize,
	})
	return client, cfg, err
}

// resolveSecret reads the credential inside this process, so it never crosses
// the boundary to the core.
func resolveSecret(ref string) (string, error) {
	secret, err := collector.ParseSecret(ref)
	if err != nil {
		return "", err
	}
	switch secret.Scheme() {
	case "env":
		name := ref[len("env:"):]
		value := os.Getenv(name)
		if value == "" {
			return "", fmt.Errorf("the environment variable %s is empty or unset", name)
		}
		return value, nil
	case "file":
		path := ref[len("file:"):]
		body, err := os.ReadFile(path) //nolint:gosec // reading the operator's own secret file is the point
		if err != nil {
			return "", fmt.Errorf("reading the client secret: %w", err)
		}
		return trimNewline(string(body)), nil
	}
	return "", fmt.Errorf("unsupported secret scheme")
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// configured is the realm list from the configuration document. Empty means
// every realm the credentials reach.
func configured(cfg collect.Config) []string { return cfg.Realms }

func requested(cfg collect.Config) map[string]bool {
	if len(cfg.Realms) == 0 {
		return nil
	}
	out := make(map[string]bool, len(cfg.Realms))
	for _, r := range cfg.Realms {
		out[r] = true
	}
	return out
}
