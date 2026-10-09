// Command github is the GitHub collector.
//
// Built exactly as a third party would build it: its own module, depending on
// the SDK and the contract and never on the core. It reads the REST API and
// never writes.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/github/internal/api"
	"go.acciew.io/collector/plugins/github/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

// version is stamped at build time; the default is what a local build reports.
var version = "0.3.0-dev"

func main() { collector.Serve(&github{}) }

type github struct{}

func (g *github) Describe(context.Context) (*collector.Description, error) {
	return &collector.Description{
		Name:    "github",
		Version: version,
		Description: "Collects members, teams, repositories and installed applications from " +
			"GitHub organizations over the REST API.",
		// No activity at all, and this is the considered answer rather than
		// an unfinished one. See the limitation below: nothing GitHub offers
		// on a plan short of Enterprise is a last-seen signal that a
		// dormancy decision could rest on, and producing a bad one would be
		// worse than producing none.
		Activity: false,
		Fidelities: []collectorv1.Fidelity{
			collector.Direct,
			// GitHub can be resolved: the base permission, ownership, teams
			// and direct grants are all enumerable, and this collector
			// checks its own answer against GitHub's. Nothing here is COARSE.
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
			collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO,
		},
		Limitations: []collector.Limitation{
			{
				Code: "github.no-last-activity",
				Summary: "This collector reports no last-activity for anybody, on purpose. The " +
					"audit log is the only signal GitHub offers that could support a dormancy " +
					"decision and it is Enterprise-gated (verified: HTTP 404 on a plan below Enterprise). " +
					"The public event feed is not a substitute: verified against a real " +
					"organization, it covered public repositories only, reached back about " +
					"three weeks because it is capped by event count rather than by time, and " +
					"listed bots among the actors while many human members never " +
					"appeared at all. Reporting those members as dormant would be a confident " +
					"wrong answer, which is worse than no answer.",
			},
			{
				Code: "github.base-permission-is-organization-wide",
				Summary: "An organization's base permission reaches every member on every " +
					"repository, and GitHub states it once. It is collected once, as an " +
					"entitlement applying to the organization rather than as a grant per member " +
					"per repository: expanding it would emit relationships GitHub never stated, " +
					"quadratically in the size of the organization. A reviewer asking who can " +
					"write to one repository must read the organization-wide grant too.",
			},
			{
				Code: "github.custom-roles-are-not-on-the-ladder",
				Summary: "Repository permissions are an ordered ladder — read, triage, write, " +
					"maintain, admin — and custom repository roles are not on it: a custom role " +
					"is a base role plus fine-grained permissions, so two grants that both read " +
					"'write' need not be the same access. Default levels carry their rank; " +
					"custom roles carry none and are marked as not comparable.",
			},
			{
				Code: "github.archived-repositories",
				Summary: "An archived repository is read-only whatever a permission says. The " +
					"grants are collected as GitHub reports them and the repository is marked " +
					"archived, because a write grant on an archived repository is not the " +
					"access it appears to be.",
			},
			{
				Code: "github.enterprise-surfaces-not-collected",
				Summary: "Organization roles and custom repository role definitions are " +
					"plan-gated and are not collected. Where a custom role is held, the grant " +
					"is collected under the role's name.",
			},
		},
	}, nil
}

func (g *github) ValidateConfig(_ context.Context, raw []byte) ([]collector.Issue, error) {
	_, issues := collect.Validate(raw)
	return issues, nil
}

func (g *github) TestConnection(ctx context.Context, raw []byte) ([]collector.ScopeProbe, error) {
	client, cfg, err := dial(raw)
	if err != nil {
		return nil, err
	}
	orgs, err := visibleOrgs(ctx, client, cfg)
	if err != nil {
		return nil, err
	}

	var probes []collector.ScopeProbe
	for _, p := range collect.Probes(ctx, client, orgs, requested(cfg)) {
		probes = append(probes, collector.ScopeProbe{
			Scope:     collector.Scope(p.Org, p.Org),
			Name:      p.Org,
			Reachable: p.Reachable,
			Err:       p.Err,
		})
	}
	return probes, nil
}

func (g *github) Collect(ctx context.Context, req collector.CollectRequest, out collector.Stream) error {
	// A raw error here is reported as a plugin error — a defect in this
	// code — and a revoked token, a rate limit and an unreachable GitHub are
	// none of those.
	client, cfg, err := dial(req.Config)
	if err != nil {
		// A document we cannot use is not GitHub's doing, and the host reads
		// the cause: filed as a source error it sends an operator to look at
		// a GitHub that was never contacted.
		return &collector.Incomplete{Cause: collector.CauseFor(err), Err: err}
	}
	orgs, err := visibleOrgs(ctx, client, cfg)
	if err != nil {
		return &collector.Incomplete{Cause: collector.SourceFailed, Err: err}
	}
	if len(req.Scopes) == 0 {
		req.Scopes = cfg.Orgs
	}
	return collect.AllWith(ctx, client, orgs, cfg, req, out)
}

// visibleOrgs is what this token can see, narrowed to nothing: the caller's
// list is applied later, so an organization they named and cannot see is
// reported rather than silently dropped.
func visibleOrgs(ctx context.Context, client *api.Client, cfg collect.Config) ([]string, error) {
	orgs, err := client.Orgs(ctx)
	if err != nil {
		return nil, err
	}
	return collect.OrgNames(ctx, orgs), nil
}

func requested(cfg collect.Config) map[string]bool {
	if len(cfg.Orgs) == 0 {
		return nil
	}
	out := make(map[string]bool, len(cfg.Orgs))
	for _, o := range cfg.Orgs {
		out[o] = true
	}
	return out
}

// dial resolves the configuration and prepares a client. It contacts nothing.
func dial(raw []byte) (*api.Client, collect.Config, error) {
	cfg, issues := collect.Validate(raw)
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			// Marked where it happens, so the cause and the code cannot drift.
			return nil, cfg, collector.BadConfig(
				fmt.Errorf("configuration: %s: %s", i.Field, i.Message))
		}
	}
	token, err := resolveSecret(cfg.Token)
	if err != nil {
		// The reference is in the document and the thing it points at is not
		// there. Either way the fix is in the deployment, not on GitHub.
		return nil, cfg, collector.BadConfig(err)
	}
	client, err := api.Dial(api.Config{
		BaseURL: cfg.BaseURL, Token: token, PageSize: cfg.PageSize,
	})
	if err != nil {
		// Unreachable today — Validate has already checked the base URL and
		// resolveSecret guarantees a token — and marked anyway, because the
		// next check added here would otherwise land as a source error.
		// Dial contacts nothing, so everything it can say is the document.
		return nil, cfg, collector.BadConfig(err)
	}
	return client, cfg, nil
}

// resolveSecret reads the credential the configuration points at.
//
// The configuration carries a reference and never the credential, so that
// whatever stores, hashes or logs the document never holds the secret.
func resolveSecret(ref string) (string, error) {
	switch {
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		value := os.Getenv(name)
		if value == "" {
			return "", fmt.Errorf("the environment variable %s is empty or unset", name)
		}
		return value, nil
	case strings.HasPrefix(ref, "file:"):
		path := strings.TrimPrefix(ref, "file:")
		body, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own reference
		if err != nil {
			return "", fmt.Errorf("reading the token from %s: %w", path, err)
		}
		token := strings.TrimSpace(string(body))
		if token == "" {
			return "", fmt.Errorf("the file %s is empty", path)
		}
		return token, nil
	}
	return "", errors.New("the token must be a reference: env:VARNAME or file:/path")
}
