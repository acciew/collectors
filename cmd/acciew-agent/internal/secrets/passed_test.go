package secrets_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"

	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
)

const (
	awsKeyID  = "AKIAIOSFODNN7EXAMPLE"
	awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	awsToken  = "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQD"
)

// A variable the agent passes to a collector is a credential when its name says so: the same words
// as the fields of a file, and a name that ends in KEY. A key id, a region, a profile, a proxy and a
// certificate file are settings, which a collector will mention.
func TestAVariablePassedToACollectorIsWatchedForWhenItsNameSaysItIsASecret(t *testing.T) {
	vars := map[string]string{
		"AWS_ACCESS_KEY_ID": awsKeyID, "AWS_SECRET_ACCESS_KEY": awsSecret, "AWS_SESSION_TOKEN": awsToken,
		"DB_PASSWORD": "Winter@2026-Secure!", "API_TOKEN": "gho_Zq8vN3mT7xK2pR9wL5cB1dF6", "APP_SECRET": "app-secret-value-77",
		"SIGNING_KEY": "signing-key-value-88", "GOOGLE_APPLICATION_CREDENTIALS": "/etc/acciew/gcp-sa.json",
		"AWS_REGION": "eu-west-1-region-x", "AWS_PROFILE": "production-profile", "SSL_CERT_FILE": "/etc/ssl/certs/ca-bundle.crt",
		"COUNTRY_CODE": "NL-country-code", "HTTPS_PROXY": "http://proxy.corp.example:3128", "KEY_ID": "key-id-value-1234",
		"AWS_ACCESS_KEY_ID_X": "AKIAIOSFODNN7EXAMPL2", "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPL4", "HAS_PASSWORD": "true",
		"UNIX_PASSWORD": "/pass/word-of-a-user-1", "DB_PASSWORD_FILE": "/run/secrets/db-password",
	}
	var pass []string
	for name := range vars {
		pass = append(pass, name)
	}
	p := &secrets.Policy{LookupEnv: env(vars)}
	r := &secrets.Redactor{}
	if err := p.WatchPassed(r, pass); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "DB_PASSWORD", "API_TOKEN", "APP_SECRET", "SIGNING_KEY", "UNIX_PASSWORD"} {
		v := vars[name]
		hit, ok := r.Find([]byte("event: " + v + " end"))
		if !ok || hit.Source != "env:"+name {
			t.Errorf("%s: not caught, or named %q", name, hit.Source)
		}
		if !r.Leaks([]byte(base64.StdEncoding.EncodeToString([]byte(v)))) {
			t.Errorf("%s: its base64 was not caught", name)
		}
		if got := r.Scrub("log " + v + " end"); strings.Contains(got, v) {
			t.Errorf("%s: not scrubbed: %q", name, got)
		}
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_REGION", "AWS_PROFILE", "SSL_CERT_FILE", "COUNTRY_CODE", "HTTPS_PROXY", "KEY_ID", "AWS_ACCESS_KEY_ID_X", "GOOGLE_APPLICATION_CREDENTIALS", "AWS_ACCESS_KEY", "HAS_PASSWORD", "DB_PASSWORD_FILE"} {
		if r.Leaks([]byte("event: "+vars[name]+" end")) || r.Scrub("log "+vars[name]+" end") != "log "+vars[name]+" end" {
			t.Errorf("%s: a setting was taken for a credential", name)
		}
	}
}

func TestTheNamesThatAreSecretVariables(t *testing.T) {
	for name, want := range map[string]bool{
		"AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true, "AWS_SECURITY_TOKEN": true, "DB_PASSWORD": true,
		"GITHUB_TOKEN": true, "CLIENT_SECRET": true, "API_KEY": true, "SSH_KEY": true, "KEY": true, "AWS_ACCESS_KEY": true,
		"AWS_ACCESS_KEY_ID": false, "STRIPE_KEY_ID": false, "COUNTRY_CODE": false, "SIGNATURE_VERSION": false, "AWS_REGION": false,
		"HTTPS_PROXY": false, "PATH": false, "TOKEN_ENDPOINT": false, "PASSWORD_FILE": false, "bind_password": true,
	} {
		if got := secrets.SecretVariable(name); got != want {
			t.Errorf("SecretVariable(%q) = %v", name, got)
		}
	}
}

// A proxy address that carries a password is still its password, whatever the variable is called.
func TestAPasswordInAnAddressPassedToACollectorIsStillWatchedFor(t *testing.T) {
	p := &secrets.Policy{LookupEnv: env(map[string]string{"HTTPS_PROXY": "http://svc:pr0xy-Pa55word-9z@proxy.corp.example:3128"})}
	r := &secrets.Redactor{}
	if err := p.WatchPassed(r, []string{"HTTPS_PROXY"}); err != nil {
		t.Fatal(err)
	}
	if !r.Leaks([]byte("pr0xy-Pa55word-9z")) || r.Leaks([]byte("proxy.corp.example:3128")) {
		t.Error("the proxy's password, and only it, should be watched for")
	}
}

func writeAWS(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const awsCredentials = `# keys
[default]
aws_access_key_id = ` + awsKeyID + `
aws_secret_access_key = ` + awsSecret + `

[prod]
AWS_SESSION_TOKEN=` + awsToken + `
aws_access_key_id=AKIAIOSFODNN7EXAMPL3
region = eu-west-1-region-x
`

// The AWS SDK reads its keys from a file when it is told where it is, or finds it under HOME. A file the
// operator hands the collector that way is read at the start of the job, and the secrets in it are
// watched for like any other.
func TestTheKeysInAnAWSFilePassedToACollectorAreWatchedFor(t *testing.T) {
	dir := t.TempDir()
	creds := writeAWS(t, dir, "credentials", awsCredentials)
	conf := writeAWS(t, dir, "config", "[profile ops]\naws_secret_access_key = config-file-secret-key-99\nsso_region = eu-west-1\n")
	home := t.TempDir()
	writeAWS(t, home, ".aws/credentials", "[default]\naws_secret_access_key = home-credentials-secret-1\n")
	writeAWS(t, home, ".aws/config", "[default]\naws_session_token = home-config-session-token-2\n")

	for name, c := range map[string]struct {
		vars    map[string]string
		pass    []string
		caught  []string
		ignored []string
	}{
		"the credentials file": {
			map[string]string{"AWS_SHARED_CREDENTIALS_FILE": creds}, []string{"AWS_SHARED_CREDENTIALS_FILE"},
			[]string{awsSecret, awsToken}, []string{awsKeyID, "AKIAIOSFODNN7EXAMPL3", "eu-west-1-region-x", "default", "[prod]"},
		},
		"the config file": {
			map[string]string{"AWS_CONFIG_FILE": conf}, []string{"AWS_CONFIG_FILE"},
			[]string{"config-file-secret-key-99"}, []string{"eu-west-1", "ops"},
		},
		"both": {
			map[string]string{"AWS_SHARED_CREDENTIALS_FILE": creds, "AWS_CONFIG_FILE": conf}, []string{"AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"},
			[]string{awsSecret, awsToken, "config-file-secret-key-99"}, nil,
		},
		"the home directory": {
			map[string]string{"HOME": home}, []string{"HOME"},
			[]string{"home-credentials-secret-1", "home-config-session-token-2"}, []string{home},
		},
		"a file named, and the home directory": {
			map[string]string{"HOME": home, "AWS_SHARED_CREDENTIALS_FILE": creds}, []string{"HOME", "AWS_SHARED_CREDENTIALS_FILE"},
			[]string{awsSecret, "home-config-session-token-2"}, []string{"home-credentials-secret-1"},
		},
		"not passed": {
			map[string]string{"AWS_SHARED_CREDENTIALS_FILE": creds, "HOME": home}, nil, nil, []string{awsSecret, "home-credentials-secret-1"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := &secrets.Policy{LookupEnv: env(c.vars)}
			r := &secrets.Redactor{}
			if err := p.WatchPassed(r, c.pass); err != nil {
				t.Fatal(err)
			}
			for _, v := range c.caught {
				if !r.Leaks([]byte("event: "+v+" end")) || strings.Contains(r.Scrub("log "+v), v) {
					t.Errorf("%q was not watched for", v)
				}
			}
			for _, v := range c.ignored {
				if r.Leaks([]byte("event: " + v + " end")) {
					t.Errorf("%q was taken for a credential", v)
				}
			}
		})
	}
}

func TestAnAWSFileThatIsNotThereIsNothingToWatchFor(t *testing.T) {
	p := &secrets.Policy{LookupEnv: env(map[string]string{"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(t.TempDir(), "nope"), "HOME": t.TempDir()})}
	if err := p.WatchPassed(&secrets.Redactor{}, []string{"AWS_SHARED_CREDENTIALS_FILE", "HOME"}); err != nil {
		t.Errorf("a missing file was an error: %v", err)
	}
}

// The file is the operator's to hand over, but the agent's own files, /proc and the rest are not
// something a collector's environment can point it at. A file the agent cannot watch for and the
// collector can read is a job not run.
func TestAnAWSFileThatMustNotBeReadOrCannotBeWatchedForIsRefused(t *testing.T) {
	dir := t.TempDir()
	own := writeAWS(t, dir, "own/credentials", awsCredentials)
	big := writeAWS(t, dir, "big", strings.Repeat("# comment\n", 200_000))
	link := filepath.Join(dir, "link")
	if err := os.Symlink(own, link); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path string
		want string
	}{
		"/proc":                 {"/proc/self/environ", "never something"},
		"too big":               {big, "too big"},
		"the agent's":           {own, "never something"},
		"a link to the agent's": {link, "never something"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(c.path); err != nil {
				t.Skipf("%v", err)
			}
			p := &secrets.Policy{
				LookupEnv: env(map[string]string{"AWS_SHARED_CREDENTIALS_FILE": c.path}),
				Forbidden: func(path string) bool {
					resolved, _ := filepath.EvalSymlinks(filepath.Dir(own))
					return strings.HasPrefix(path, filepath.Dir(own)) || strings.HasPrefix(path, resolved)
				},
			}
			err := p.WatchPassed(&secrets.Redactor{}, []string{"AWS_SHARED_CREDENTIALS_FILE"})
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "AWS_SHARED_CREDENTIALS_FILE") {
				t.Errorf("err = %v, want one that names the variable and says %q", err, c.want)
			}
		})
	}
}

// The AWS SDK goes on without a file it cannot use, and so does the collector: nothing is read, the
// agent says so in its log, and the job runs.
func TestAnAWSFileThatNeitherAgentNorCollectorCanUseIsSkippedWithAWarning(t *testing.T) {
	dir := t.TempDir()
	unreadable := writeAWS(t, dir, "unreadable", awsCredentials)
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	closed := filepath.Join(dir, "closed")
	if err := os.MkdirAll(filepath.Join(closed, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeAWS(t, closed, ".aws/credentials", awsCredentials)
	if err := os.Chmod(closed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	asFile := writeAWS(t, dir, "asfile", "text")
	for name, c := range map[string]struct {
		vars  map[string]string
		pass  []string
		root  bool // behaves differently for root, which can read anything
		noted bool
	}{
		"unreadable":               {map[string]string{"AWS_SHARED_CREDENTIALS_FILE": unreadable}, []string{"AWS_SHARED_CREDENTIALS_FILE"}, true, true},
		"a directory":              {map[string]string{"AWS_SHARED_CREDENTIALS_FILE": dir}, []string{"AWS_SHARED_CREDENTIALS_FILE"}, false, true},
		"a loop of links":          {map[string]string{"AWS_CONFIG_FILE": loop}, []string{"AWS_CONFIG_FILE"}, false, true},
		"a relative home":          {map[string]string{"HOME": "home"}, []string{"HOME"}, false, true},
		"a tilde":                  {map[string]string{"AWS_SHARED_CREDENTIALS_FILE": "~/.aws/credentials"}, []string{"AWS_SHARED_CREDENTIALS_FILE"}, false, true},
		"a home that is shut":      {map[string]string{"HOME": closed}, []string{"HOME"}, true, true},
		"a home that is a file":    {map[string]string{"HOME": asFile}, []string{"HOME"}, false, true},
		"a file that is not there": {map[string]string{"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, "nope")}, []string{"AWS_SHARED_CREDENTIALS_FILE"}, false, false},
		"a dangling link": {map[string]string{"AWS_SHARED_CREDENTIALS_FILE": func() string {
			l := filepath.Join(dir, "dangling")
			_ = os.Symlink(filepath.Join(dir, "gone"), l)
			return l
		}()}, []string{"AWS_SHARED_CREDENTIALS_FILE"}, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			if c.root && os.Geteuid() == 0 {
				t.Skip("root can read it")
			}
			var warned []string
			p := &secrets.Policy{LookupEnv: env(c.vars), Warn: func(m string) { warned = append(warned, m) }}
			r := &secrets.Redactor{}
			if err := p.WatchPassed(r, c.pass); err != nil {
				t.Fatalf("the job would be given up: %v", err)
			}
			if r.Leaks([]byte(awsSecret)) {
				t.Error("something was read")
			}
			if c.noted != (len(warned) > 0) {
				t.Errorf("warnings = %q, wanted any: %v", warned, c.noted)
			}
		})
	}
}

// The agent's state directory may be the home of the user it runs as. Nothing is refused for that:
// only a file of AWS's that is itself in a place that is never read.
func TestAHomeThatIsTheAgentsDirectoryIsOnlyRefusedIfTheAWSFileIsInIt(t *testing.T) {
	state := t.TempDir()
	p := &secrets.Policy{
		LookupEnv: env(map[string]string{"HOME": state}),
		Forbidden: func(path string) bool { return strings.HasPrefix(path, state) },
	}
	if err := p.WatchPassed(&secrets.Redactor{}, []string{"HOME"}); err != nil {
		t.Errorf("no AWS file there, and the job was refused: %v", err)
	}
	writeAWS(t, state, ".aws/credentials", awsCredentials)
	if err := p.WatchPassed(&secrets.Redactor{}, []string{"HOME"}); err == nil || !strings.Contains(err.Error(), "never something") {
		t.Errorf("an AWS file in the agent's directory was read: %v", err)
	}
}

func TestTheKeysOfAnAWSFile(t *testing.T) {
	got := secrets.AWSFileSecrets([]byte("[default]\n  AWS_Secret_Access_Key =  abc/def+ghi==  \naws_session_token=tokentoken\naws_security_token = old-token-value\naws_access_key_id=AKIA\nsecret_key = not-aws\n; aws_secret_access_key = commented\n# aws_session_token = commented\n"))
	want := []string{"abc/def+ghi==", "tokentoken", "old-token-value"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The SDK takes the quotes off a value, so the secret is what is inside them; the text with the quotes is
// watched for as well, in case what reads it does not. A short value (LocalStack's "test") is a word
// and not a key, and scrubbing it would hide it everywhere.
func TestAQuotedValueInAnAWSFileIsWatchedForWithoutItsQuotesAndAShortOneNotAtAll(t *testing.T) {
	got := secrets.AWSFileSecrets([]byte("[default]\naws_secret_access_key = \"" + awsSecret + "\"\naws_session_token = '" + awsToken + "'\n[local]\naws_secret_access_key = test\naws_session_token=\"abc\"\naws_security_token = 1234567\naws_secret_access_key = \n"))
	want := []string{`"` + awsSecret + `"`, awsSecret, "'" + awsToken + "'", awsToken}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
	dir := t.TempDir()
	path := writeAWS(t, dir, "credentials", "[default]\naws_secret_access_key = \""+awsSecret+"\"\n[local]\naws_secret_access_key = test\n")
	p := &secrets.Policy{LookupEnv: env(map[string]string{"AWS_SHARED_CREDENTIALS_FILE": path})}
	r := &secrets.Redactor{}
	if err := p.WatchPassed(r, []string{"AWS_SHARED_CREDENTIALS_FILE"}); err != nil {
		t.Fatal(err)
	}
	if !r.Leaks([]byte("event: "+awsSecret+" end")) || !r.Leaks([]byte(`event: "`+awsSecret+`" end`)) {
		t.Error("the secret was not watched for with and without its quotes")
	}
	if got := r.Scrub("the testcollector said test"); got != "the testcollector said test" {
		t.Errorf("scrubbed = %q", got)
	}
}

// hclog writes a quote inside a quoted value as backslash quote and does not touch a backslash, so
// a secret with a quote in it that a collector logs inside JSON or Go quotes reaches the scrub in a
// form it has no other way to know.
func TestASecretWithAQuoteInItIsScrubbedFromALogLineAsHclogWritesIt(t *testing.T) {
	for _, secret := range []string{`pa"ssw0rd!xyz`, `pa"ss\w0rd!x9`} {
		r := redactorFor(t, secret)
		asJSON, _ := json.Marshal(secret)
		for name, written := range map[string]string{
			"raw":       secret,
			"JSON":      strings.Trim(string(asJSON), `"`),
			"Go-quoted": strings.Trim(strconv.Quote(secret), `"`),
		} {
			var buf bytes.Buffer
			hclog.New(&hclog.LoggerOptions{Output: &buf, Level: hclog.Info}).Info("collector says", "body", `{"secret": "`+written+`", "x": 1}`)
			line := strings.TrimRight(buf.String(), "\n")
			if got := r.Line(line); strings.Contains(got, "w0rd") || !strings.Contains(got, "[redacted]") {
				t.Errorf("%s, %s: logged as %q", secret, name, got)
			}
		}
	}
}
