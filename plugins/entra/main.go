// Command entra is the Microsoft Entra ID collector.
//
// Built exactly as a third party would build it: its own module, depending on
// the SDK and the contract and never on the server. It reads through Microsoft
// Graph only, with an application token, and it never writes.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// version is stamped at build time; the default is what a local build reports.
var version = "0.1.1-dev"

func main() { collector.Serve(&entra{}) }

type entra struct {
	// endpoints resolves a cloud to its hosts; nil means Microsoft's. A test
	// points it at a fake.
	endpoints func(graph.Cloud) (graph.Endpoints, bool)
}

func (e *entra) Describe(context.Context) (*collector.Description, error) {
	return &collector.Description{
		Name:    "entra",
		Version: version,
		Description: "Collects users, groups, service principals, directory roles and app roles, and who " +
			"holds them, from a Microsoft Entra ID tenant over Microsoft Graph.",
		// Whether a tenant can answer is a per-tenant fact, reported on its
		// scope: sign-in activity needs Entra ID P1 or P2.
		Activity: true,
		Fidelities: []collectorv1.Fidelity{
			collector.Direct,
			// A role held through a role-assignable group is derived by one
			// hop over facts the source states, so we stand behind it.
			// Nothing here is COARSE: a directory role is the source's own
			// named permission object, as a Keycloak role is.
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
		Signals: []collector.Signal{
			{
				Name: collect.SignalInteractive,
				Description: "The last interactive sign-in attempt (lastSignInDateTime). It counts failed " +
					"attempts, so it does not say the person got in. Recorded from April 2020.",
				TypicalLag: 24 * time.Hour,
			},
			{
				Name: collect.SignalNonInteractive,
				Description: "The last non-interactive sign-in attempt (lastNonInteractiveSignInDateTime), " +
					"made by a client on the person's behalf. It counts failed attempts. Recorded from May 2020.",
				TypicalLag: 24 * time.Hour,
			},
			{
				Name: collect.SignalSuccessful,
				Description: "The last sign-in that succeeded (lastSuccessfulSignInDateTime), interactive or " +
					"not. Recorded from 1 December 2023 and not backfilled, so a user whose last success was " +
					"earlier has no value.",
				TypicalLag: 24 * time.Hour,
			},
			{
				Name: collect.SignalServicePrincipal,
				Description: "An application's sign-in. Always unavailable: a service principal's sign-ins " +
					"are a separate surface that this collector does not read.",
			},
		},
		Limitations: []collector.Limitation{
			{
				Code: "entra.activity-needs-p1",
				Summary: "Sign-in activity needs Microsoft Entra ID P1 or P2 and the AuditLog.Read.All " +
					"permission. A tenant that cannot answer is reported as unable to, for everyone in it, " +
					"never as having no activity. What Graph answers a tenant without the licence has not " +
					"been verified, so a refusal of a shape nobody has seen is reported as not knowing.",
			},
			{
				Code: "entra.blank-sign-in-is-unanswerable",
				Summary: "Entra leaves a sign-in blank for a user who never signed in that way and for one " +
					"whose last attempt was before Entra began recording it, and the two cannot be told " +
					"apart. A blank is reported as unavailable, never as not seen.",
			},
			{
				Code: "entra.sign-in-lag-24h",
				Summary: "A sign-in can take up to 24 hours to appear. The interactive and non-interactive " +
					"values count failed attempts as well as successes; only the successful sign-in says " +
					"the person got in, and it exists only from 1 December 2023.",
			},
			{
				Code: "entra.sp-sign-in-not-collected",
				Summary: "An application's sign-ins are a separate surface that is not read, so every " +
					"service principal is reported as having no answer, never as inactive.",
			},
			{
				Code: "entra.tenant-scoped",
				Summary: "A tenant is the isolation boundary and the only scope. One configuration " +
					"reads one tenant, and people are not correlated across tenants.",
			},
			{
				Code: "entra.external-tenants-not-supported",
				Summary: "A guest is collected as this tenant sees them. What they hold in their " +
					"home tenant, or in any other, is outside this tenant and is not read.",
			},
			{
				Code: "entra.group-service-principal-members-not-listed",
				Summary: "Microsoft documents that the v1.0 endpoint that lists a group's members " +
					"returns no service principals, and this collector reads v1.0 only. So long as " +
					"that holds, an application that is a member of a group is not collected as one, " +
					"and a role that reaches an application through a group is not shown for it. If " +
					"Graph lists one it is collected as a member like any other.",
			},
			{
				Code: "entra.app-roles-nested-groups-not-expanded",
				Summary: "When an app role is assigned to a group, Microsoft states that the group's direct " +
					"members are assigned it and does not state that the members of a group inside it " +
					"are. Only direct members are shown as holding it; a nested group is counted in a " +
					"diagnostic and not expanded, so this may under-report who can use the application.",
			},
			{
				Code: "entra.eligible-is-a-separate-entitlement",
				Summary: "A role a principal is eligible for through Privileged Identity Management, and one " +
					"held for a limited time, are entitlements of their own, role:<id>:eligible and " +
					"role:<id>:active, and never the role itself: an eligibility is not a grant. Whether " +
					"they are reviewed with the roles that are held is for the reviewer to decide. Activations, " +
					"which last hours, are not collected.",
			},
			{
				Code: "entra.oauth2-grants-off-by-default",
				Summary: "Delegated permission grants, an application allowed to act on behalf of users, " +
					"are not collected unless collect.oauth2_grants is switched on, because reading them " +
					"needs Directory.Read.All, far broader than anything else here. Switched on, each " +
					"grant is an entitlement its client holds; who consented is context, not a holder.",
			},
			{
				Code: "entra.replication-delay",
				Summary: "Microsoft notes that listing who is assigned an application's roles may lag " +
					"assignments that were granted or removed recently. A collection is as of its read, " +
					"not of the instant after a change.",
			},
			{
				Code: "entra.hidden-membership-needs-permission",
				Summary: "The members of a group whose membership is hidden are read only with the " +
					"Member.Read.Hidden permission. Without it that group is collected with no " +
					"members and the tenant is reported partial, naming the permission.",
			},
			{
				Code: "entra.conditional-access-not-evaluated",
				Summary: "Conditional Access policies decide whether a sign-in succeeds and whether " +
					"a role can be used. They are not read, so a grant shown here may be limited, " +
					"or refused, by a policy this data does not show.",
			},
			{
				Code: "entra.azure-rbac-not-collected",
				Summary: "Azure resource roles, assigned on subscriptions and resource groups, are " +
					"managed in Azure RBAC, a different API from the directory roles collected here.",
			},
			{
				Code: "entra.workload-roles-not-collected",
				Summary: "Roles that belong to a workload such as Exchange Online, SharePoint or " +
					"Teams are managed in that workload and are not directory roles. Licences are " +
					"not collected either.",
			},
		},
	}, nil
}

func (e *entra) ValidateConfig(_ context.Context, raw []byte) ([]collector.Issue, error) {
	_, issues := collect.Validate(raw)
	return issues, nil
}

func (e *entra) TestConnection(ctx context.Context, raw []byte) ([]collector.ScopeProbe, error) {
	run, err := e.dial(ctx, raw)
	if err != nil {
		return nil, err
	}
	var probes []collector.ScopeProbe
	for _, p := range run.Probes(ctx) {
		probes = append(probes, collector.ScopeProbe{
			Scope: collector.Scope(p.Tenant, p.Tenant), Name: p.Name,
			Reachable: p.Reachable, Err: p.Err,
			ActivityAvailable:    p.Activity.State == collect.ActivityAvailable,
			ActivityUndetermined: p.Activity.State == collect.ActivityUndetermined,
			// The actionable half: "no activity" without "needs P1" leaves an
			// operator with nothing to do.
			ActivityNote: p.Activity.Note,
		})
	}
	return probes, nil
}

func (e *entra) Collect(ctx context.Context, req collector.CollectRequest, out collector.Stream) error {
	// A raw error here is reported as a plugin error, a defect in this code,
	// and a rotated secret or an unreachable tenant is neither. The cause as
	// well as the code: the host reads the cause, and a configuration failure
	// filed under "source error" sends an operator to a tenant that was never
	// contacted.
	run, err := e.dial(ctx, req.Config)
	if err != nil {
		return &collector.Incomplete{Cause: collector.CauseFor(err), Err: err}
	}
	return run.Collect(ctx, req, out)
}

// dial resolves the configuration and signs in.
func (e *entra) dial(ctx context.Context, raw []byte) (collect.Run, error) {
	cfg, issues := collect.Validate(raw)
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			// Marked where it happens, so the cause and the code cannot drift
			// apart later. Everything past the resolve below is Microsoft.
			return collect.Run{}, collector.BadConfig(fmt.Errorf("configuration: %s: %s", i.Field, i.Message))
		}
	}
	endpoints := e.endpoints
	if endpoints == nil {
		endpoints = graph.EndpointsFor
	}
	hosts, _ := endpoints(cfg.Cloud())

	gc := graph.Config{TenantID: cfg.TenantID, ClientID: cfg.ClientID, Endpoints: hosts}
	if cfg.Certificate != "" {
		pemText, err := resolve(cfg.Certificate)
		if err != nil {
			return collect.Run{}, collector.BadConfig(fmt.Errorf("the certificate: %w", err))
		}
		if gc.Certificate, err = graph.ParseCertificate([]byte(pemText)); err != nil {
			return collect.Run{}, collector.BadConfig(fmt.Errorf("the certificate: %w", err))
		}
	} else {
		secret, err := resolve(cfg.ClientSecret)
		if err != nil {
			return collect.Run{}, collector.BadConfig(fmt.Errorf("the client secret: %w", err))
		}
		gc.ClientSecret = secret
	}
	client, err := graph.Dial(ctx, gc)
	if err != nil {
		return collect.Run{}, err
	}
	return collect.Run{Graph: client, Config: cfg}, nil
}

// resolve reads a credential inside this process, so it never crosses the
// boundary to the core. The reference is in the document and the thing it
// points at is not there: either way the fix is in the deployment.
func resolve(ref string) (string, error) {
	secret, err := collector.ParseSecret(ref)
	if err != nil {
		return "", err
	}
	switch secret.Scheme() {
	case "env":
		name := strings.TrimPrefix(ref, "env:")
		value := os.Getenv(name)
		if value == "" {
			return "", fmt.Errorf("the environment variable %s is empty or unset", name)
		}
		return value, nil
	case "file":
		path := strings.TrimPrefix(ref, "file:")
		body, err := os.ReadFile(path) //nolint:gosec // reading the operator's own secret file is the point
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", path, err)
		}
		value := strings.TrimRight(string(body), "\r\n")
		if value == "" {
			return "", fmt.Errorf("%s is empty", path)
		}
		return value, nil
	}
	return "", fmt.Errorf("unsupported secret scheme")
}
