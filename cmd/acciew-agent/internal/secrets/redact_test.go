package secrets_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
)

// bundleOf is n private keys' worth of base64 lines, as a PEM bundle: a lot to watch for.
func bundleOf(t *testing.T, certs int) string {
	t.Helper()
	var b strings.Builder
	for range certs {
		b.WriteString("-----BEGIN PRIVATE KEY-----\n")
		raw := make([]byte, 24*48) // 24 lines of 64 characters
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		enc := base64.StdEncoding.EncodeToString(raw)
		for len(enc) > 0 {
			n := min(64, len(enc))
			b.WriteString(enc[:n] + "\n")
			enc = enc[n:]
		}
		b.WriteString("-----END PRIVATE KEY-----\n")
	}
	return b.String()
}

const apiToken = "tok_Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY"

// A long credential named first used to fill the lists of what to look for, and a token named after
// it was then never looked for and never scrubbed. Everything a job names is watched for, or the
// job is refused: nothing is dropped.
func TestACredentialNamedAfterAHugeOneIsStillLookedForAndScrubbed(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	text := bundleOf(t, 60)
	if err := os.WriteFile(bundle, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	p := policy(t, map[string]string{"TOKEN": apiToken})
	b, err := p.Bind([]byte(`{"ca":"file:` + bundle + `","token":"env:TOKEN"}`))
	if err != nil {
		t.Fatalf("a 60 certificate bundle and a token: %v", err)
	}
	defer func() { _ = b.Close() }()
	if !b.Redact.Leaks([]byte("saw " + apiToken)) {
		t.Error("the token named after the bundle is not looked for")
	}
	if got := b.Redact.Scrub("log: " + apiToken + " end"); strings.Contains(got, apiToken) {
		t.Errorf("the token named after the bundle is not scrubbed: %q", got)
	}
	// And the bundle's own last line, in the last certificate, is.
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if !b.Redact.Leaks([]byte(lines[len(lines)-3])) {
		t.Error("a line from the last certificate is not looked for")
	}
	// The other way round, the token first.
	b2, err := p.Bind([]byte(`{"token":"env:TOKEN","ca":"file:` + bundle + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b2.Close() }()
	if !b2.Redact.Leaks([]byte(apiToken)) {
		t.Error("the token named before the bundle is not looked for")
	}
}

// What is looked for does not cost an event more for being a lot.
func TestWatchingForAHugeCredentialDoesNotMakeEveryEventSlow(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(bundle, []byte(bundleOf(t, 60)), 0o600)
	p := policy(t, map[string]string{"TOKEN": apiToken})
	b, err := p.Bind([]byte(`{"ca":"file:` + bundle + `","token":"env:TOKEN"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	event := []byte(strings.Repeat("user alice of group platform holds role admin ", 22)) // about a kilobyte
	start := time.Now()
	for range 5000 {
		if b.Redact.Leaks(event) {
			t.Fatal("an ordinary event was taken for a credential")
		}
	}
	if took := time.Since(start); took > 8*time.Second {
		t.Errorf("5000 events of 1 KiB took %v", took)
	}
}

// What cannot be watched for is not dropped without a word: the job is refused, naming the reference.
func TestACredentialTooLargeToBeWatchedForRefusesTheJobAndNamesIt(t *testing.T) {
	dir := t.TempDir()
	// Five bundles of 800 KB: each is within what one secret may be, and all of them are within what a
	// job may name, and together they are more patterns than can be watched for.
	var refs []string
	for i := range 5 {
		path := filepath.Join(dir, fmt.Sprintf("bundle%d.pem", i))
		if err := os.WriteFile(path, []byte(bundleOf(t, 500)), 0o600); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, `"b`+fmt.Sprint(i)+`":"file:`+path+`"`)
	}
	p := policy(t, map[string]string{"TOKEN": apiToken})
	_, err := p.Bind([]byte("{" + strings.Join(refs, ",") + `,"token":"env:TOKEN"}`))
	if err == nil {
		t.Fatal("4 MB of bundles was accepted")
	}
	if !strings.Contains(err.Error(), "file:"+dir) || !strings.Contains(err.Error(), "too large to be watched for") {
		t.Errorf("err = %v", err)
	}
	if entries, _ := os.ReadDir(p.Dir); len(entries) != 0 {
		t.Errorf("the refused job left %v behind", entries)
	}
}

func TestAHitNamesTheReferenceAndHowItWasWrittenButNeverTheValue(t *testing.T) {
	p := policy(t, map[string]string{"DB_PASSWORD": "Xk29pQ7zrLm4Vb8n", "OTHER": "another-credential-77"})
	b, err := p.Bind([]byte(`{"a":"env:DB_PASSWORD","b":"env:OTHER"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	hit, ok := b.Redact.Find([]byte("Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("root:Xk29pQ7zrLm4Vb8n"))))
	if !ok || hit.Source != "env:DB_PASSWORD" || !strings.Contains(hit.Form, "base64") {
		t.Fatalf("hit = %+v, %v", hit, ok)
	}
	if d := hit.Describe(); !strings.Contains(d, "env:DB_PASSWORD") || strings.Contains(d, "Xk29pQ7zrLm4Vb8n") {
		t.Errorf("Describe = %q", d)
	}
	if hit, ok := b.Redact.Find([]byte("x another-credential-77 y")); !ok || hit.Source != "env:OTHER" {
		t.Errorf("second credential: %+v %v", hit, ok)
	}
	if _, ok := b.Redact.Find([]byte("nothing")); ok {
		t.Error("a hit in nothing")
	}
	var none *secrets.Redactor
	if _, ok := none.Find([]byte("x")); ok {
		t.Error("a nil redactor found something")
	}
}

func TestEveryCredentialIsScrubbedWhereverItsPiecesFallIncludingOverlaps(t *testing.T) {
	r := &secrets.Redactor{}
	if err := r.Add("env:A", "abcdefghijkl"); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("env:B", "ghijklmnopqr"); err != nil { // overlaps the first at "ghijkl"
		t.Fatal(err)
	}
	if err := r.Add("env:C", "pw12"); err != nil { // four bytes: scrubbed, never enforced
		t.Fatal(err)
	}
	got := r.Scrub("x abcdefghijklmnopqr y pw12 z")
	for _, left := range []string{"abcdef", "ghijkl", "mnopqr", "pw12"} {
		if strings.Contains(got, left) {
			t.Errorf("%q survived: %q", left, got)
		}
	}
	if r.Leaks([]byte("pw12")) {
		t.Error("a four byte value was enforced")
	}
}
