package secrets_test

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
)

const dsn = "postgres://acciew:Xk29pQ7zrLm4Vb8n@db.corp.local:5432/postgres?sslmode=require"

// A collector that is configured with a DSN names its own endpoint. The start and the end of a DSN
// are public text and a database collector cannot run if it may not say them.
func TestADatabaseCollectorMayNameItsOwnEndpointButNotItsPassword(t *testing.T) {
	r := redactorFor(t, dsn)
	for _, mention := range []string{
		"db.corp.local:5432/postgres", "postgres://acciew_reader@db", "?sslmode=require", "sslmode=require",
		"postgres://acciew@db.corp.local:5432", "connected to postgres://", "db.corp.local", "5432/postgres?sslmode=require",
	} {
		if r.Leaks([]byte("event: " + mention)) {
			t.Errorf("%q was taken for the credential", mention)
		}
	}
	// The whole thing, the password alone and the login with it are the credential.
	for _, echo := range []string{dsn, "Xk29pQ7zrLm4Vb8n", "acciew:Xk29pQ7zrLm4Vb8n", "password Xk29pQ7zrLm4Vb8n rejected"} {
		if !r.Leaks([]byte(echo)) {
			t.Errorf("%q was not caught", echo)
		}
	}
	// And the password written other ways.
	if !r.Leaks([]byte(base64.StdEncoding.EncodeToString([]byte("acciew:Xk29pQ7zrLm4Vb8n")))) {
		t.Error("the Basic form of the login was not caught")
	}
}

func TestThePasswordInAURLSecretIsScrubbedWhateverItsLength(t *testing.T) {
	for _, pw := range []string{"Xk29pQ7zrLm4Vb8n", "Pw7!x", "p4ss"} {
		r := redactorFor(t, "mysql://app:"+pw+"@db.corp.local:3306/app")
		if got := r.Scrub("failed for " + pw + " here"); strings.Contains(got, pw) {
			t.Errorf("%q survived: %q", pw, got)
		}
	}
	// Short ones are never enforced: they are in ordinary data.
	if redactorFor(t, "mysql://app:p4ss@db.corp.local:3306/app").Leaks([]byte("p4ss")) {
		t.Error("a four byte password was enforced")
	}
}

func TestAPasswordInADriverStyleAddressWithNoSchemeIsFound(t *testing.T) {
	r := redactorFor(t, "acciew:Xk29pQ7zrLm4Vb8n@tcp(db.corp.local:3306)/app?parseTime=true")
	if !r.Leaks([]byte("Xk29pQ7zrLm4Vb8n")) {
		t.Error("the password of a driver address was not caught")
	}
	if r.Leaks([]byte("tcp(db.corp.local:3306)/app?parseTime=true")) {
		t.Error("the endpoint was taken for the credential")
	}
}

func TestAPasswordInAKeywordConnectionStringIsFoundButNotTheRest(t *testing.T) {
	r := redactorFor(t, "host=db.corp.local port=5432 user=acciew password='Xk29 pQ7zrLm4Vb8n' dbname=postgres sslmode=require")
	if !r.Leaks([]byte("Xk29 pQ7zrLm4Vb8n")) {
		t.Error("the password was not caught")
	}
	for _, mention := range []string{"host=db.corp.local port=5432", "dbname=postgres sslmode=require", "user=acciew"} {
		if r.Leaks([]byte(mention)) {
			t.Errorf("%q was taken for the credential", mention)
		}
	}
}

func jwtOf(t *testing.T, payloadLen, sigLen int) string {
	t.Helper()
	seg := func(n int) string {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	return header + "." + seg(payloadLen) + "." + seg(sigLen)
}

// The header of every RS256 token is the same sixteen characters, and a collector that is given one
// token sees others.
func TestATokenSecretIsCaughtButAnotherTokenWithTheSameHeaderIsNot(t *testing.T) {
	mine, other := jwtOf(t, 60, 128), jwtOf(t, 60, 128)
	if !strings.HasPrefix(mine, "eyJhbGciOiJSUzI1") {
		t.Fatalf("the test's token does not have the header the review named: %s", mine)
	}
	r := redactorFor(t, mine)
	if r.Leaks([]byte("bearer " + other)) {
		t.Error("another token with the same header was taken for the credential")
	}
	if r.Leaks([]byte("alg " + mine[:16])) {
		t.Error("the header alone was taken for the credential")
	}
	segs := strings.Split(mine, ".")
	for name, echo := range map[string]string{"the whole": mine, "its payload": segs[1], "its signature": segs[2]} {
		if !r.Leaks([]byte("saw " + echo)) {
			t.Errorf("%s was not caught", name)
		}
	}
}

// A long plain token still has a start and an end that are worth looking for by themselves.
func TestAPlainTokensStartAndEndAreStillLookedForButAStructuredOnesAreNot(t *testing.T) {
	r := redactorFor(t, apiToken)
	if !r.Leaks([]byte(apiToken[:16])) || !r.Leaks([]byte(apiToken[len(apiToken)-16:])) {
		t.Error("the start or the end of a plain token was not caught")
	}
}

const oidcSettings = `{"token_endpoint_auth_method":"client_secret_basic","authority_host":"login.microsoftonline.com",` +
	`"key_vault":"prod-keyvault-001","tenant":"contoso.onmicrosoft.com","client_id":"0b3f6a2e-1c44-4d7e-9a55-2f1d3c7b8e90",` +
	`"client_secret":"Zq8vN3mT7xK2pR9wL5cB1dF6"}`

// A credential file is mostly settings, and a collector names its settings.
func TestTheSettingsInACredentialFileMayBeNamedButNotItsSecrets(t *testing.T) {
	r := redactorFor(t, oidcSettings)
	for _, mention := range []string{
		"client_secret_basic", "login.microsoftonline.com", "prod-keyvault-001", "contoso.onmicrosoft.com",
		"0b3f6a2e-1c44-4d7e-9a55-2f1d3c7b8e90", "token_endpoint_auth_method",
	} {
		if r.Leaks([]byte("issuer " + mention)) {
			t.Errorf("%q was taken for the credential", mention)
		}
	}
	if !r.Leaks([]byte("secret Zq8vN3mT7xK2pR9wL5cB1dF6 was refused")) {
		t.Error("the client secret was not caught")
	}
}

// Each kind of value that a key's or a token's name does not make a secret of, under a name that is
// only a key's or a token's: a URL, an address, a host, a number, one letter over and over.
func TestWhatLooksLikeASettingIsNotTakenForAKeyEvenUnderAKeysName(t *testing.T) {
	for name, c := range map[string]struct{ json, mention string }{
		"a URL":      {`{"token":"https://user.example.com/path/xyz"}`, "https://user.example.com/path/xyz"},
		"an address": {`{"api_key":"ops-team@corp.example.com"}`, "ops-team@corp.example.com"},
		"a host":     {`{"access_token":"login.microsoftonline.com"}`, "login.microsoftonline.com"},
		"a number":   {`{"token":"1234567890123456789012"}`, "1234567890123456789012"},
		"one letter": {`{"accountKey":"aaaaaaaaaaaaaaaaaaaaaaaa"}`, "aaaaaaaaaaaaaaaaaaaaaaaa"},
		"too short":  {`{"token":"short-one"}`, "short-one"},
	} {
		r := redactorFor(t, c.json)
		// Not on its own: the whole file is still the credential, and is caught whole.
		if r.Leaks([]byte("event " + c.mention)) {
			t.Errorf("%s: %q was taken for a secret", name, c.mention)
		}
		if !r.Leaks([]byte(c.json)) {
			t.Errorf("%s: the whole file was not caught", name)
		}
	}
}

func TestAServiceAccountFileGivesUpItsKeyAndNotItsIdentifiers(t *testing.T) {
	r := redactorFor(t, saFile)
	for _, mention := range []string{
		"0123456789abcdef0123456789abcdef01234567", // private_key_id: a key's name, not the key
		"svc@my-project-12345.iam.gserviceaccount.com", "https://oauth2.googleapis.com/token", "123456789012345678901", "my-project-12345",
	} {
		if r.Leaks([]byte("account " + mention)) {
			t.Errorf("%q was taken for the credential", mention)
		}
	}
	if !r.Leaks([]byte("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj")) {
		t.Error("a line of the private key was not caught")
	}
}

func TestAProxyWithNoSchemeButALoginIsFound(t *testing.T) {
	for _, proxy := range []string{"svc:pr0xy-Pa55word@proxy.corp.example:3128", "http://svc:pr0xy-Pa55word@proxy.corp.example:3128", "socks5://svc:pr0xy-Pa55word@10.0.0.1:1080"} {
		red := &secrets.Redactor{}
		if err := red.AddURLCredentials("env:HTTPS_PROXY", proxy); err != nil {
			t.Fatal(err)
		}
		if !red.Leaks([]byte("pass pr0xy-Pa55word seen")) {
			t.Errorf("%s: the password was not caught", proxy)
		}
	}
	red := &secrets.Redactor{}
	for _, plain := range []string{"proxy.corp.example:3128", "http://proxy.corp.example:3128", "10.0.0.1:1080", "user@example.com", "localhost"} {
		if err := red.AddURLCredentials("env:HTTPS_PROXY", plain); err != nil {
			t.Fatal(err)
		}
	}
	if red.Leaks([]byte("proxy.corp.example:3128 user@example.com localhost 10.0.0.1:1080")) {
		t.Error("an address with no login was taken for a credential")
	}
}
