package graph_test

import (
	"net/http"
	"testing"

	"go.acciew.io/collector/plugins/entra/internal/graph"
)

func TestOnlyARefusalWithAKnownLicenceCodeIsALicenceProblem(t *testing.T) {
	for _, c := range []struct {
		name string
		err  graph.Error
		want bool
	}{
		{"the code Graph is known to use", graph.Error{Kind: graph.KindPermission, Status: http.StatusForbidden, Code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant"}, true},
		{"the same, in another case", graph.Error{Kind: graph.KindPermission, Code: "authentication_requestfromnonpremiumtenantorb2ctenant"}, true},
		{"a licence refusal that is a 400", graph.Error{Kind: graph.KindBadRequest, Code: "AadPremiumLicenseRequired"}, true},
		{"a missing permission", graph.Error{Kind: graph.KindPermission, Code: "Authorization_RequestDenied"}, false},
		{"a refusal nobody has seen", graph.Error{Kind: graph.KindPermission, Code: "SomethingNew"}, false},
		{"a known code on an outage", graph.Error{Kind: graph.KindUnavailable, Code: "AadPremiumLicenseRequired"}, false},
	} {
		if got := c.err.LicenceRequired(); got != c.want {
			t.Errorf("%s: LicenceRequired = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAnObjectIsReadByTypeAndNothingElseIs(t *testing.T) {
	if p, ok := graph.ObjectPath("user", "a b"); !ok || p != "/users/a%20b?%24select=id%2CdisplayName" {
		t.Errorf("user path = %q, %v", p, ok)
	}
	for _, kind := range []string{"group", "servicePrincipal"} {
		if _, ok := graph.ObjectPath(kind, "x"); !ok {
			t.Errorf("%s has no object path", kind)
		}
	}
	if _, ok := graph.ObjectPath("device", "x"); ok {
		t.Error("a type the collector does not read was given a path")
	}
}
