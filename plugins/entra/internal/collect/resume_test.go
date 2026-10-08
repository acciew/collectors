package collect_test

import (
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

func incomplete(t *testing.T, err error) *collector.Incomplete {
	t.Helper()
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want an incomplete collection", err)
	}
	return inc
}

func TestAScopeTheCredentialDoesNotReachIsUnreachableNotEmpty(t *testing.T) {
	w := newWorld(t, directory())
	out, err := w.run("", collector.CollectRequest{Scopes: []string{"someone-elses-tenant.example.com"}})
	if inc := incomplete(t, err); inc.Cause != collector.ScopeUnreachable {
		t.Fatalf("cause = %v, want ScopeUnreachable", inc.Cause)
	}
	if len(out.scopes) != 1 || out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_UNREACHABLE {
		t.Errorf("scopes = %+v, want the requested scope reported unreachable", out.scopes)
	}
}
