package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.acciew.io/collector/sdk/go/collector"
)

// A collection that could not list realms is reporting a fact about the
// source: a role that was never granted, a secret that was rotated, a
// Keycloak that is down. Returned raw it arrives as a plugin error — "there
// is a defect in this collector" — which sends whoever reads it to the wrong
// place entirely.
func TestACollectionThatCannotReachKeycloakBlamesKeycloak(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		says   string
	}{
		{"a missing role", http.StatusForbidden, "view-users"},
		{"a rotated secret", http.StatusUnauthorized, "could not be listed"},
		{"an unwell Keycloak", http.StatusServiceUnavailable, "could not be listed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/realms/acme/protocol/openid-connect/token" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token": "e30.e30.sig", "expires_in": 60,
					})
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(`{"error":"no"}`))
			}))
			t.Cleanup(srv.Close)

			t.Setenv("KC_TEST_SECRET", "s3cr3t")
			cfg, err := json.Marshal(map[string]any{
				"base_url": srv.URL, "auth_realm": "acme",
				"client_id": "acciew", "client_secret": "env:KC_TEST_SECRET",
				"realms": []string{"acme"},
			})
			if err != nil {
				t.Fatal(err)
			}

			err = (&keycloak{}).Collect(context.Background(),
				collector.CollectRequest{Config: cfg}, nil)

			var incomplete *collector.Incomplete
			if !errors.As(err, &incomplete) {
				t.Fatalf("want an incomplete collection the host can classify, got %v", err)
			}
			if incomplete.Cause != collector.SourceFailed {
				t.Errorf("Cause = %v, want source failed", incomplete.Cause)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("the message does not say what happened: %v", err)
			}
		})
	}
}

// A configuration this collector cannot use is not the source's doing. The
// source was never reached, and an operator sent to look at Keycloak is
// looking at the wrong thing.
func TestABadConfigurationIsNotASourceError(t *testing.T) {
	t.Setenv("KC_TEST_EMPTY", "")
	for _, c := range []struct{ name, config string }{
		{"a document that is not JSON", `{not json`},
		{"a document missing what it needs", `{"base_url": "", "realms": []}`},
		{"a secret reference pointing at nothing",
			`{"base_url":"http://kc","auth_realm":"acme","client_id":"a",` +
				`"client_secret":"env:KC_TEST_EMPTY","realms":["acme"]}`},
		{"a secret that is not a reference",
			`{"base_url":"http://kc","auth_realm":"acme","client_id":"a",` +
				`"client_secret":"s3cr3t","realms":["acme"]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			assertConfigFailure(t, (&keycloak{}).Collect(context.Background(),
				collector.CollectRequest{Config: []byte(c.config)}, nil))
		})
	}
}

func assertConfigFailure(t *testing.T, err error) {
	t.Helper()
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("want an incomplete collection, got %v", err)
	}
	var faulty interface{ Fault() collector.Fault }
	if !errors.As(inc.Err, &faulty) {
		t.Fatalf("the failure does not classify itself: %v", inc.Err)
	}
	if got := faulty.Fault(); got != collector.FaultConfig {
		t.Errorf("Fault = %v, want FaultConfig", got)
	}
	// The cause as well as the code. The host reads the cause, so a
	// configuration failure filed under "source error" is what an operator
	// actually reads however the error is classified underneath.
	if inc.Cause != collector.InvalidConfig {
		t.Errorf("Cause = %v, want InvalidConfig; an operator is sent to look at Keycloak",
			inc.Cause)
	}
}
