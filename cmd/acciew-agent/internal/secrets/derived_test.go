package secrets_test

import (
	"encoding/json"
	"strings"
	"testing"

	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
)

// What is guaranteed is the exact value of each reference, in the encodings the Redactor lists. What
// is read out of the structure of a value (a JSON field, the login of an address, a parameter of a
// query or a connection string, a line of a private key) is best effort: a part is taken only when
// it is clearly the part that unlocks, and the tests below hold both ways, what it must find and
// what it must leave to the collector to say.

func caught(t *testing.T, r *secrets.Redactor, what string, echoes ...string) {
	t.Helper()
	for _, e := range echoes {
		if !r.Leaks([]byte("event: " + e + " end")) {
			t.Errorf("%s: %q was not caught", what, e)
		}
		if got := r.Scrub("log " + e + " end"); strings.Contains(got, e) {
			t.Errorf("%s: %q was not scrubbed: %q", what, e, got)
		}
	}
}

func mentioned(t *testing.T, r *secrets.Redactor, what string, mentions ...string) {
	t.Helper()
	for _, m := range mentions {
		if r.Leaks([]byte("event: " + m + " end")) {
			t.Errorf("%s: %q was taken for the credential", what, m)
		}
	}
}

// ---- names

// A name is compared as it is spelled in snake_case, camelCase, PascalCase, with dashes or spaces.
func TestSecretFieldNamesAreComparedWhateverTheirCase(t *testing.T) {
	const s = "Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY"
	for _, name := range []string{
		"client_secret", "clientSecret", "ClientSecret", "client-secret", "CLIENT_SECRET", "Client Secret",
		"secret_access_key", "SecretAccessKey", "secretAccessKey",
		"session_token", "SessionToken", "sessionToken", "access_token", "accessToken", "AccessToken",
		"refresh_token", "refreshToken", "id_token", "idToken", "api_key", "apiKey", "ApiKey", "APIKey",
		"private_key", "privateKey", "PrivateKey", "AccountKey", "accountKey", "account_key",
		"SharedAccessKey", "sharedAccessKey", "shared_access_key", "password", "Password", "PASSWORD", "passwd", "pwd", "secret", "Secret",
	} {
		r := redactorFor(t, `{"id":"0b3f6a2e-1c44-4d7e-9a55-2f1d3c7b8e90","`+name+`":"`+s+`","tenant":"contoso.onmicrosoft.com"}`)
		if !r.Leaks([]byte("saw " + s)) {
			t.Errorf("a secret under %q was not caught on its own", name)
		}
	}
	for _, name := range []string{
		"clientId", "AccessKeyId", "access_key_id", "tenantId", "token_endpoint_auth_method", "authority_host", "key_vault", "keyboard",
		"author", "passage", "secretary", "monkey", "accessTokenUrl", "passwordPolicy", "tokenType", "sessionTokenTtl",
	} {
		r := redactorFor(t, `{"`+name+`":"`+s+`","note":"x"}`)
		if r.Leaks([]byte("saw " + s)) {
			t.Errorf("a value under %q was taken for a secret on its own", name)
		}
	}
}

func TestTheFormsOfAzureAndAWSCredentialFilesGiveUpTheirSecretsAndNotTheirIdentifiers(t *testing.T) {
	azure := `{"clientId":"0b3f6a2e-1c44-4d7e-9a55-2f1d3c7b8e90","clientSecret":"Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY","subscriptionId":"7c5d1a90-3f2e-4b8a-8e11-6a4f2b9d0c33","tenantId":"d4e8f1a2-5b6c-4d7e-8f90-a1b2c3d4e5f6","activeDirectoryEndpointUrl":"https://login.microsoftonline.com"}`
	r := redactorFor(t, azure)
	caught(t, r, "azure", "Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY")
	mentioned(t, r, "azure", "0b3f6a2e-1c44-4d7e-9a55-2f1d3c7b8e90", "d4e8f1a2-5b6c-4d7e-8f90-a1b2c3d4e5f6", "https://login.microsoftonline.com")

	aws := `{"Version":1,"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","SessionToken":"IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQD","Expiration":"2026-10-09T10:00:00Z"}`
	r = redactorFor(t, aws)
	caught(t, r, "aws", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQD")
	mentioned(t, r, "aws", "AKIAIOSFODNN7EXAMPLE", "2026-10-09T10:00:00Z")
}

// A field that is called password is a password: the name is the evidence, and a password may look
// like an address, a host, a number or a short word.
func TestWhatAFieldCalledPasswordHoldsIsAPasswordWhateverItLooksLike(t *testing.T) {
	for _, pw := range []string{"Tr0ub4dor&3xyz", "Winter@2026-Secure!", "correct.horse.battery.staple", "12345678", "https://x.example/y", "aaaaaaaa", "login.example.com"} {
		for _, name := range []string{"password", "passwd", "pwd", "secret", "client_secret", "clientSecret"} {
			r := redactorFor(t, `{"user":"svc","`+name+`":"`+pw+`"}`)
			caught(t, r, name+" "+pw, pw)
		}
	}
	// Under seven bytes it is scrubbed and not enforced.
	r := redactorFor(t, `{"password":"Pw7!xy"}`)
	if r.Leaks([]byte("Pw7!xy")) {
		t.Error("a six byte password was enforced")
	}
	if got := r.Scrub("pw Pw7!xy here"); strings.Contains(got, "Pw7!xy") {
		t.Errorf("a six byte password was not scrubbed: %q", got)
	}
}

// ---- addresses and strings of settings

func TestACredentialInTheQueryOfAnAddressIsFoundAndTheRestOfTheAddressIsNot(t *testing.T) {
	for name, c := range map[string]struct {
		secret   string
		unlocks  []string
		mentions []string
	}{
		"client_secret": {"https://login.corp.example/oauth2/token?client_id=acciew-prod&client_secret=S3cr3tValueXYZ123456&scope=read",
			[]string{"S3cr3tValueXYZ123456"}, []string{"https://login.corp.example/oauth2/token", "client_id=acciew-prod", "scope=read", "acciew-prod"}},
		"access_token": {"https://api.corp.example/v1/items?access_token=gho_Zq8vN3mT7xK2pR9wL5cB1dF6&limit=10",
			[]string{"gho_Zq8vN3mT7xK2pR9wL5cB1dF6"}, []string{"https://api.corp.example/v1/items", "limit=10"}},
		"password": {"https://corp.example/login?user=svc&password=Winter@2026-Secure!",
			[]string{"Winter@2026-Secure!"}, []string{"https://corp.example/login", "user=svc"}},
		"function key": {"https://app.azurewebsites.net/api/run?code=Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY",
			[]string{"Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY"}, []string{"https://app.azurewebsites.net/api/run"}},
		"a key": {"https://maps.corp.example/v1?key=AIzaSyZq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0",
			[]string{"AIzaSyZq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0"}, []string{"https://maps.corp.example/v1"}},
		"service bus": {"Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY+x/9w=",
			[]string{"Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY+x/9w="}, []string{"sb://ns.servicebus.windows.net/", "SharedAccessKeyName=RootManageSharedAccessKey", "Endpoint=sb://ns.servicebus.windows.net/"}},
		"a name with spaces": {"Server=db.corp.example;Database=app;Shared Access Key=Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY;Application Name=reports",
			[]string{"Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY"}, []string{"Server=db.corp.example", "Application Name=reports", "Database=app"}},
		"a name of two words": {"Server=db.corp.example;Pass Phrase=correct-horse-battery-staple;Application Name=reports",
			[]string{"correct-horse-battery-staple"}, []string{"Server=db.corp.example", "Application Name=reports"}},
		"sas": {"https://acct.blob.core.windows.net/c/b.csv?sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2026-12-01T00:00:00Z&sig=Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY%2Bx%2F9w%3D",
			[]string{"Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY%2Bx%2F9w%3D", "Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY+x/9w="},
			[]string{"https://acct.blob.core.windows.net/c/b.csv", "sv=2022-11-02", "sp=rl", "se=2026-12-01T00:00:00Z"}},
	} {
		r := redactorFor(t, c.secret)
		caught(t, r, name, c.unlocks...)
		mentioned(t, r, name, c.mentions...)
	}
}

func TestALoginInAnAddressThatIsNotUserAndPasswordIsFound(t *testing.T) {
	for name, c := range map[string]struct {
		secret   string
		unlocks  []string
		mentions []string
	}{
		"an empty user":    {"redis://:R3disPassw0rdXYZ@cache.corp.example:6379/0", []string{"R3disPassw0rdXYZ"}, []string{"redis://cache.corp.example:6379/0", "cache.corp.example:6379"}},
		"a token as user":  {"https://ghp_Zq8vN3mT7xK2pR9wL5cB1dF6hJ@github.com/org/repo.git", []string{"ghp_Zq8vN3mT7xK2pR9wL5cB1dF6hJ"}, []string{"https://github.com/org/repo.git", "github.com/org/repo.git"}},
		"a slash":          {"svc:Pa55/w0rdXYZ12@tcp(db.corp.example:3306)/app?parseTime=true", []string{"Pa55/w0rdXYZ12"}, []string{"tcp(db.corp.example:3306)/app", "parseTime=true"}},
		"an at sign in it": {"postgres://svc:p@ss-w0rd-XYZ@db.corp.example:5432/app", []string{"p@ss-w0rd-XYZ"}, []string{"db.corp.example:5432/app"}},
		"a username":       {"https://alice@corp.example/path", nil, []string{"alice", "https://corp.example/path", "alice@corp.example"}},
		"a long user name": {"https://administrator.reader.svc@corp.example/path", nil, []string{"administrator.reader.svc", "administrator.reader.svc@corp.example"}},
		"an at in a query": {"https://corp.example/path?email=svc.reader@corp.example", nil, []string{"svc.reader@corp.example", "email=svc.reader"}},
	} {
		r := redactorFor(t, c.secret)
		caught(t, r, name, c.unlocks...)
		mentioned(t, r, name, c.mentions...)
	}
}

// An email address in a JSON file is not the login of an address, and the length byte of a string
// of 34 bytes is a quote.
func TestAnEmailInACompactJSONFileIsNotTakenForALogin(t *testing.T) {
	r := redactorFor(t, `{"username":"svc.reader@corp.com","password":"Zq8vN3mT7xK2","upn":"svc.reader@corp.com"}`)
	mentioned(t, r, "an email", `{"upn":"svc.reader@corp.com"}`, `"svc.reader@corp.com"`, "svc.reader@corp.com", "svc.reader")
	if r.Leaks([]byte("\"svc.reader")) || r.Leaks([]byte("\x22svc.reader@corp.com\x12")) {
		t.Error("a quote and the start of the address were taken for a credential")
	}
	caught(t, r, "the password", "Zq8vN3mT7xK2")
}

func TestADriverAndAnODBCPasswordAreCutWhereTheyEnd(t *testing.T) {
	odbc := "Driver={ODBC Driver 18 for SQL Server};Server=tcp:db.corp.example,1433;Database=app;UID=svc;PWD={p@ss;w0rd!xyzQ};Encrypt=yes"
	r := redactorFor(t, odbc)
	caught(t, r, "odbc", "p@ss;w0rd!xyzQ")
	mentioned(t, r, "odbc", "Server=tcp:db.corp.example,1433", "Database=app", "Driver={ODBC Driver 18 for SQL Server}", "UID=svc", "Encrypt=yes", "p@ss", "w0rd!xyzQ")

	braced := redactorFor(t, "Server=db;PWD={a}}b;c-secret};UID=svc")
	caught(t, braced, "a brace inside braces", "a}b;c-secret")

	r = redactorFor(t, "host=db.corp.example port=5432 user=svc password='Xk29 pQ7zrLm4Vb8n' dbname=app sslmode=require")
	caught(t, r, "libpq", "Xk29 pQ7zrLm4Vb8n")
	mentioned(t, r, "libpq", "host=db.corp.example port=5432", "dbname=app sslmode=require")

	r = redactorFor(t, `Server=db;Password="a ;b c-secret";User=x`)
	caught(t, r, "double quotes", "a ;b c-secret")
}

func TestAnAzureStorageConnectionStringGivesUpItsKeyAndNotItsEndpoint(t *testing.T) {
	const key = "Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aYZq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aYZq8vN3mT7xK2pR9wL5cB1dF6hJ4=="
	cs := "DefaultEndpointsProtocol=https;AccountName=acciewprod;AccountKey=" + key + ";EndpointSuffix=core.windows.net"
	r := redactorFor(t, cs)
	caught(t, r, "the key", key)
	mentioned(t, r, "the endpoint", "https://acciewprod.blob.core.windows.net/", "DefaultEndpointsProtocol=https", "AccountName=acciewprod",
		"EndpointSuffix=core.windows.net", "core.windows.net", "acciewprod", "https://acciewprod.queue.core.windows.net/q1")
	// The whole connection string is the guarantee and is caught whole.
	if !r.Leaks([]byte(cs)) {
		t.Error("the whole connection string was not caught")
	}
}

// ---- private keys and the certificates beside them

const certBlock = "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\nRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\n-----END CERTIFICATE-----\n"

func keyBlock(label string) string {
	return "-----BEGIN " + label + "-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n-----END " + label + "-----\n"
}

func TestOnlyTheLinesOfAPrivateKeyAreWatchedForNotThoseOfTheCertificateBesideIt(t *testing.T) {
	for _, label := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY"} {
		r := redactorFor(t, certBlock+keyBlock(label))
		caught(t, r, label, "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj")
		mentioned(t, r, label, "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ",
			"RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD", "-----BEGIN "+label+"-----", "-----END CERTIFICATE-----")
		// The same, the key first.
		r = redactorFor(t, keyBlock(label)+certBlock)
		caught(t, r, label+" first", "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu")
		mentioned(t, r, label+" first", "RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD")
	}
	// A certificate on its own is public, and a collector will say it: only its whole is the credential.
	r := redactorFor(t, certBlock)
	mentioned(t, r, "a certificate", "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ")
	if !r.Leaks([]byte(certBlock)) {
		t.Error("the whole certificate block was not caught")
	}
	// Text that is not PEM and has several lines is watched for line by line, as before.
	plain := redactorFor(t, "user: svc\npassphrase: correct-horse-battery-staple\nregion: eu-west-1")
	caught(t, plain, "a plain file", "passphrase: correct-horse-battery-staple")
}

func TestAPrivateKeyInAJSONFileIsWatchedForLineByLineAndItsCertificateIsNot(t *testing.T) {
	text := `{"private_key":"` + strings.ReplaceAll(keyBlock("PRIVATE KEY"), "\n", `\n`) + `","certificate":"` + strings.ReplaceAll(certBlock, "\n", `\n`) + `","client_email":"svc@corp.example"}`
	r := redactorFor(t, text)
	caught(t, r, "the key", "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu")
	mentioned(t, r, "the certificate", "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ")
}

// ---- a part that was URL-escaped in the value and is not in the event

func TestAPasswordThatIsURLEscapedInTheAddressIsFoundAsItReads(t *testing.T) {
	r := redactorFor(t, "mysql://app:p%40ssw0rd-xyz%2F9@db.corp.example:3306/app")
	caught(t, r, "decoded", "p@ssw0rd-xyz/9")
	caught(t, r, "as written", "p%40ssw0rd-xyz%2F9")
}

// ---- the cap on what is watched for

func TestTheCapOnPatternsIsAnExactBoundary(t *testing.T) {
	var probe secrets.Redactor
	if err := probe.Add("env:A", "abcdefghijkl"); err != nil {
		t.Fatal(err)
	}
	n := probe.Patterns()
	if n < 5 {
		t.Fatalf("a twelve byte value comes to %d patterns", n)
	}
	exact := secrets.Redactor{MaxPatterns: n}
	if err := exact.Add("env:A", "abcdefghijkl"); err != nil {
		t.Errorf("a cap of exactly %d patterns refused %d: %v", n, n, err)
	}
	short := secrets.Redactor{MaxPatterns: n - 1}
	if err := short.Add("env:A", "abcdefghijkl"); err == nil || !strings.Contains(err.Error(), "too large to be watched for") {
		t.Errorf("a cap of %d accepted %d patterns: %v", n-1, n, err)
	}
	// A second value past the cap is refused, and what fitted is still watched for.
	two := secrets.Redactor{MaxPatterns: n + 3}
	if err := two.Add("env:A", "abcdefghijkl"); err != nil {
		t.Fatal(err)
	}
	if err := two.Add("env:B", "mnopqrstuvwx"); err == nil {
		t.Errorf("a second value past the cap was accepted")
	}
	if !two.Leaks([]byte("abcdefghijkl")) {
		t.Error("the first value is no longer watched for")
	}
}

// The padding at the end of a base64 token is an equals sign and not a setting: a token that ends in one
// is still a plain token, and its start and end are still looked for.
func TestABase64TokenWithPaddingKeepsItsStartAndEnd(t *testing.T) {
	const token = "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
	r := redactorFor(t, token)
	caught(t, r, "a padded token", token[:16], token[len(token)-16:])
}

// ---- a name that ends in a secret's name

// bind_password, bindPassword and github_token are a password and a token: a name that ends in one of
// the names as a word is that name's, in any case and with any of the separators.
func TestANameThatEndsInASecretWordIsASecretName(t *testing.T) {
	const long = "Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY"
	for _, name := range []string{
		"bind_password", "bindPassword", "adminPassword", "db_password", "user_password", "keystore_password",
		"app_secret", "kc_client_secret", "spring.datasource.password", "DB-PASSWORD", "Admin Password",
		"github_token", "bot_token", "personal_access_token", "botToken", "access_key", "accessKey", "master_key",
		"AWS_SECRET_ACCESS_KEY", "stripe.api.key", "credentials", "credential", "x_api_key", "myAPIKey", "DBPassword",
		"oauth2Token", "shared_access_signature",
	} {
		r := redactorFor(t, `{"id":"0b3f6a2e-1c44-4d7e-9a55-2f1d3c7b8e90","`+name+`":"`+long+`","tenant":"contoso.onmicrosoft.com"}`)
		caught(t, r, name, long)
		mentioned(t, r, name, "contoso.onmicrosoft.com", "0b3f6a2e-1c44-4d7e-9a55-2f1d3c7b8e90")
	}
	// A password under any of them is one whatever it looks like.
	r := redactorFor(t, `{"bind_password":"12345678","ldap_url":"ldaps://dc1.corp.example"}`)
	caught(t, r, "a number", "12345678")
	// Not names that end in something else, however much they mention one.
	for _, name := range []string{
		"password_policy", "token_endpoint", "secretary", "bind_password_age", "keyboard", "access_key_id", "tokens",
		"credentials_file", "pass_through", "bypass", "monkey",
	} {
		r := redactorFor(t, `{"`+name+`":"`+long+`","note":"x"}`)
		mentioned(t, r, name, long)
	}
}

// DB_PASSWORD=... in a file of lines is the password of a name, found as the lines of a connection
// string are: the host beside it is not.
func TestTheSettingsOfADotEnvFileAreFoundByTheirNames(t *testing.T) {
	env := "DB_HOST=db.internal.example.com\nDB_PORT=5432\nDB_PASSWORD=pw-8-chars\nAPP_SECRET=Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY\n" +
		"GITHUB_TOKEN=gho_Zq8vN3mT7xK2pR9wL5cB1dF6\nLOG_LEVEL=debug\n"
	r := redactorFor(t, env)
	caught(t, r, "the env file", "pw-8-chars", "Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY", "gho_Zq8vN3mT7xK2pR9wL5cB1dF6")
	mentioned(t, r, "the env file", "db.internal.example.com", "5432", "debug")
	// A glued name is not split: it is the listed name or it is not a secret's.
	r = redactorFor(t, "bindpassword=hunter2-hunter2\nhost=db.internal.example.com\n")
	mentioned(t, r, "a glued name", "hunter2-hunter2")
}

// ---- parts of a value that are read as they are written and as they read

func TestAnEscapedCredentialInTheQueryOfAnAddressIsFoundAsItReads(t *testing.T) {
	r := redactorFor(t, "https://corp.example/login?user=svc&password=p%40ss-w0rd%21x")
	caught(t, r, "a strong name", "p@ss-w0rd!x", "p%40ss-w0rd%21x")
	r = redactorFor(t, "https://api.corp.example/v1?access_token=Zq8vN3mT7xK2pR9w%40L5cB1dF6&limit=10")
	caught(t, r, "a token", "Zq8vN3mT7xK2pR9w@L5cB1dF6", "Zq8vN3mT7xK2pR9w%40L5cB1dF6")
	mentioned(t, r, "the rest", "limit=10", "https://api.corp.example/v1")
}

// ---- private keys, to the end

func TestOnlyAPrivateKeyIsWatchedForLineByLineAndNotAPublicKey(t *testing.T) {
	const line = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq5kUvQm9Zp3kLn4yXc2WbR7tHs1d"
	r := redactorFor(t, "-----BEGIN PUBLIC KEY-----\n"+line+"\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PUBLIC KEY-----\n")
	mentioned(t, r, "a public key", line)
	// A key whose END line was cut off is still a key: its lines are watched for.
	r = redactorFor(t, keyBlock("PRIVATE KEY")[:len(keyBlock("PRIVATE KEY"))-len("-----END PRIVATE KEY-----\n")])
	caught(t, r, "no END line", "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj")
}

// ---- words that are not secrets under a secret's name

// has_password is a flag and not a password. Nothing read out of the structure of a file takes a boolean,
// a null, a number of a few digits or a plain word of that kind, not even to scrub: every "true" in
// every reason and log line would be hidden.
func TestAFlagUnderAPasswordsNameIsNotWatchedForNotEvenToScrubIt(t *testing.T) {
	const file = `{"must_change_password":"false","has_password":"true","proxy_pass":"none","pass":"null","pwd":"enabled",` +
		`"x_password":"Disabled","reset_password":"yes","retry_password":"1234","okay_password":"off","client_secret":"Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY"}`
	r := redactorFor(t, file)
	const text = "flag=false ok=true none null enabled Disabled yes 1234 off on no"
	if got := r.Scrub(text); got != text {
		t.Errorf("scrubbed = %q", got)
	}
	if r.Leaks([]byte(text)) {
		t.Error("a flag was enforced")
	}
	caught(t, r, "the secret in the same file", "Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY")
	// A password of four to seven bytes that is not one of those is still scrubbed.
	short := redactorFor(t, `{"password":"Pw7!xy","has_password":"true"}`)
	if got := short.Scrub("pw Pw7!xy and true"); strings.Contains(got, "Pw7!xy") || !strings.Contains(got, "and true") {
		t.Errorf("scrubbed = %q", got)
	}
}

// ---- names that hold something that is not a secret

// An access key id, and a path to a file with a credential in it, are what a file names, not the
// credential: an inventory lists the first and a collector says the second.
func TestAnAccessKeyIdAndAPathAreNotTakenForTheSecretUnderAKeyOrCredentialsName(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"access_key", "AKIAIOSFODNN7EXAMPLE"}, {"access_key", "ASIAIOSFODNN7EXAMPLE"}, {"AccessKey", "AKIAIOSFODNN7EXAMPLE"},
		{"credentials", "/etc/acciew/gcp-sa.json"}, {"credentials", `C:\Users\svc\gcp-sa.json`}, {"credentials", "./creds/gcp-sa.json"},
		{"credentials", "~/.config/gcloud/application_default_credentials.json"}, {"credentials", "../secrets/gcp-sa.json"},
		{"token", "/var/run/secrets/kubernetes.io/serviceaccount/token"}, {"private_key", "/etc/ssl/private/acciew.key"},
		{"credential", `\\fileserver\keys\gcp-sa.json`}, {"credentials", "C:/Users/svc/gcp-sa.json"},
	} {
		doc, _ := json.Marshal(map[string]string{"id": "0b3f6a2e-1c44-4d7e-9a55-2f1d3c7b8e90", c.name: c.value, "tenant": "contoso.onmicrosoft.com"})
		r := redactorFor(t, string(doc))
		mentioned(t, r, c.name+" "+c.value, c.value)
	}
	// And what is one is still one: a secret that starts with a slash, or that is a key id's neighbour.
	for _, c := range []struct{ name, value string }{
		{"access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, {"access_key", "Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY"},
		{"credentials", "/Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY+x/9w="}, {"token", "/Zq8vN3mT7xK2pR9wL5cB1dF6/hJ4sG0aY9Xk"},
		{"access_key", "AKIAIOSFODNN7EXAMPLE-and-a-secret-after-it"}, {"credentials", "AKIAIOSFODNN7EXAMPL"},
		{"credentials", "AKIAIOSFODNN7EXAMPLEE"}, {"access_key", "akiaiosfodnn7example"}, {"token", `7:\abcdefghijklmnopqrstu`},
	} {
		doc, _ := json.Marshal(map[string]string{c.name: c.value, "note": "x"})
		r := redactorFor(t, string(doc))
		caught(t, r, c.name+" "+c.value, c.value)
	}
}
