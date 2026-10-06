// Package kctest starts a real Keycloak for tests.
//
// The collector's assumptions about Keycloak are the kind that a minor
// version can quietly invalidate — that `GET /users` omits service accounts,
// that a group's subgroups are not inline, that group members are direct
// only. A fake cannot notice when one of those stops being true. This can.
package kctest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Image is pinned to a patch version, not a minor one: "26.4" floats across
// patch releases, so a Keycloak release could change the meaning of a test
// run without anybody choosing it, which is the whole thing pinning prevents.
const Image = "quay.io/keycloak/keycloak:26.4.7"

const (
	AdminUser = "admin"
	AdminPass = "admin"
)

// Start brings up Keycloak and returns its base URL. The container is stopped
// when the test finishes.
func Start(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        Image,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": AdminUser,
			"KC_BOOTSTRAP_ADMIN_PASSWORD": AdminPass,
		},
		Cmd: []string{"start-dev"},
		WaitingFor: wait.ForHTTP("/realms/master").
			WithPort("8080/tcp").
			WithStartupTimeout(3 * time.Minute),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Skipf("could not start Keycloak (is Docker running?): %v", err)
	}
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(container) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("http://%s:%s", host, port.Port())
}
