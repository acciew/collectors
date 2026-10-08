package collect_test

import (
	"net/http"
	"testing"
)

const noApplications = `{"service_principals":false,"app_roles":false}`

func hiddenEngineering(t *testing.T) *world {
	t.Helper()
	d := directory()
	d.Groups[0].Visibility = "HiddenMembership"
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/groups/"+engineering+"/members", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	return w
}
