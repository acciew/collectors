package collect

import (
	"context"
	"errors"
	"strings"

	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// administrativeUnits reads the units a role can be scoped to. They are the
// resources an AU-scoped role applies to; the role assignments already say who
// holds a role over one, so their members are not read.
func (st *state) administrativeUnits(ctx context.Context) error {
	err := walk(ctx, st, func(us []graph.AdministrativeUnit) error {
		for _, u := range us {
			key := collector.ResourceKey(st.tenant, "au:"+u.ID)
			name := u.DisplayName
			if name == "" {
				name = u.ID
			}
			attrs := map[string]string{}
			setIf(attrs, "description", u.Description)
			setIf(attrs, "visibility", u.Visibility)
			if err := st.out.Node(collector.WithContext(collector.Resource(key, name, "administrative_unit"), attrs)); err != nil {
				return err
			}
			st.note("administrative_units", "au:"+u.ID)
		}
		return nil
	})
	return needs(err, "AdministrativeUnit.Read.All", "list the administrative units")
}

// oauth2Grants reads the delegated permission grants: a client application
// allowed to act on behalf of users against a resource application.
//
// Each grant is an entitlement the client holds. Who consented is context, not
// a holder: a user who consented did not gain anything. A client or a resource
// that nothing else reads is named here as referenced, by looking up its name,
// because an id alone is not something a reviewer can decide about.
func (st *state) oauth2Grants(ctx context.Context) error {
	err := walk(ctx, st, func(gs []graph.OAuth2PermissionGrant) error {
		for _, g := range gs {
			if err := st.emitOAuth2Grant(ctx, g); err != nil {
				return err
			}
		}
		return nil
	})
	return needs(err, "Directory.Read.All", "list the delegated permission grants")
}

func (st *state) emitOAuth2Grant(ctx context.Context, g graph.OAuth2PermissionGrant) error {
	resource, err := st.nameOf(ctx, g.ResourceID)
	if err != nil {
		return err
	}
	key := collector.EntitlementKey(st.tenant, "oauth2-grant:"+g.ID)
	attrs := map[string]string{
		"consent_type": g.ConsentType, "scope": g.Scope, "client_id": g.ClientID, "resource_id": g.ResourceID,
	}
	setIf(attrs, "principal_id", g.PrincipalID)
	if err := st.out.Node(collector.WithContext(collector.Entitlement(key,
		"Delegated: "+strings.Join(strings.Fields(g.Scope), ", ")+" on "+resource, "oauth2_permission_grant"), attrs)); err != nil {
		return err
	}

	// The application is written by the service principals part when app roles
	// are collected, and named here, as referenced, when they are not.
	app := collector.ResourceKey(st.tenant, g.ResourceID)
	known := true
	if st.wants.AppRoles {
		if known, _, err = st.named("service_principals", app, resource, "application"); err != nil {
			return err
		}
	} else if st.once(app) {
		if err := st.out.Node(collector.Reference(app, resource, "application")); err != nil {
			return err
		}
	}
	if known {
		if err := st.out.Edge(collector.AppliesTo(key, app)); err != nil {
			return err
		}
	}

	clientName, err := st.nameOf(ctx, g.ClientID)
	if err != nil {
		return err
	}
	client, ok, err := st.holder(graph.DirectoryObject{
		Type: "#microsoft.graph.servicePrincipal", ID: g.ClientID, DisplayName: clientName,
	})
	if err != nil || !ok {
		return err
	}
	return st.sendOnce(collector.HowGranted(collector.Holds(client, key, collector.Direct), "oauth2_permission_grant"))
}

// nameOf looks up a service principal's display name, once per stream. A name
// that cannot be read is its id: the grant is worth more with an id than not
// at all. A throttle that will not end is not a name that cannot be read: it
// ends the stream.
func (st *state) nameOf(ctx context.Context, id string) (string, error) {
	if name, ok := st.names[id]; ok {
		return name, nil
	}
	name := id
	var sp graph.ServicePrincipal
	err := st.retrying(ctx, func() error {
		var err error
		sp, err = graph.Get[graph.ServicePrincipal](ctx, st.Graph, graph.NamePath(id))
		return err
	})
	var halt *stopError
	if errors.As(err, &halt) {
		return "", err
	}
	if err == nil && sp.DisplayName != "" {
		name = sp.DisplayName
	}
	st.names[id] = name
	return name, nil
}
