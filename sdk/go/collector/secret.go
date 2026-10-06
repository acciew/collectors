package collector

import (
	"fmt"
	"strings"
)

// Secret is a reference to credential material, never the material itself.
//
// The core stores, hashes and logs a plugin's configuration without knowing
// what any field means, which is only safe if no field holds a live
// credential. It cannot check that. This type is the SDK's half of the
// bargain: it refuses to be constructed from a literal, so a plugin author has
// to go out of their way to get it wrong.
//
// That is a discipline, not a guarantee — a plugin can always put a string
// somewhere else in its config. The authoring guide says so plainly rather
// than implying an enforcement that does not exist.
type Secret struct {
	scheme string
	target string
}

// Supported schemes. Both resolve inside the plugin's own process, so the
// credential never crosses the boundary to the core.
const (
	schemeEnv  = "env"  // env:GITHUB_TOKEN
	schemeFile = "file" // file:/var/run/secrets/keycloak-client-secret
)

// ParseSecret reads a reference of the form "env:NAME" or "file:/path".
//
// Anything else is refused, including a bare string that looks like a token —
// especially a bare string that looks like a token.
func ParseSecret(s string) (Secret, error) {
	scheme, target, found := strings.Cut(s, ":")
	if !found {
		return Secret{}, fmt.Errorf(
			"secret must be a reference such as %q or %q, not a literal value",
			"env:MY_TOKEN", "file:/run/secrets/my-token")
	}
	if target == "" {
		return Secret{}, fmt.Errorf("secret reference %q names no target", scheme+":")
	}
	switch scheme {
	case schemeEnv, schemeFile:
		return Secret{scheme: scheme, target: target}, nil
	default:
		return Secret{}, fmt.Errorf("unknown secret scheme %q: use %q or %q",
			scheme, schemeEnv, schemeFile)
	}
}

// String deliberately renders nothing useful. A Secret reaching a log line by
// accident is the failure this type exists to prevent, so it does not print
// its target and there is no method that returns it as a string.
func (s Secret) String() string { return "acciew.Secret(redacted)" }

// Scheme reports how the secret is resolved, which is safe to log.
func (s Secret) Scheme() string { return s.scheme }
