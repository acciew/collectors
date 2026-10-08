package collect_test

import (
	"net/http"
	"testing"

	"go.acciew.io/collector/sdk/go/collector"
)

// A refusal is not a blip, and is recorded at once.
func TestARefusalStillFailsThePartAtOnce(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/groups", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	_, err := w.run("", collector.CollectRequest{})
	if got := incomplete(t, err); got.Cause != collector.ScopeUnreachable {
		t.Errorf("cause = %v, want the part failed at once", got.Cause)
	}
}
