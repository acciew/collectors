package main

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestEmailOf(t *testing.T) {
	for in, want := range map[string]string{
		"A <a@x.test>":        "a@x.test",
		"A <b> <a@x.test>":    "a@x.test",
		"A <a@x.test> ":       "a@x.test",
		"A <A@X.test>":        "A@X.test",
		"A a@x.test":          "",
		"A <a@x.test":         "",
		"":                    "",
		"A <a@x.test> (note)": "a@x.test",
	} {
		if got := emailOf(in); got != want {
			t.Errorf("emailOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignedOff(t *testing.T) {
	const me = "a@users.noreply.github.com"
	tests := []struct {
		name  string
		email string
		by    []string
		ok    bool
	}{
		{"signed by the author", me, []string{"A <a@users.noreply.github.com>"}, true},
		{"no sign-off", me, nil, false},
		{"signed by somebody else", me, []string{"B <b@example.com>"}, false},
		{"email case does not matter", me, []string{"A <A@Users.Noreply.GitHub.com>"}, true},
		{"one of several", me, []string{"B <b@example.com>", "A <a@users.noreply.github.com>"}, true},
		{"a bot is exempt", "49699333+dependabot[bot]@users.noreply.github.com", nil, true},
		{"only a bot's own address is exempt", "x[bot]@example.com", nil, false},
		{"an author with no email is not matched by a sign-off with none", "", []string{"Anyone"}, false},
		{"nor by an empty address", "", []string{"Anyone <>"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := signedOff(commit{email: tc.email, signers: tc.by}); got != tc.ok {
				t.Errorf("signedOff = %v, want %v", got, tc.ok)
			}
		})
	}
}

func TestParseLog(t *testing.T) {
	log := "abc123\x00a@example.com\x00first\x00A <a@example.com>\x1fB <b@example.com>\x00" +
		"def456\x00b@example.com\x00second\x00\x00"
	got, err := parseLog(log)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d commits, want 2: %+v", len(got), got)
	}
	if got[0].sha != "abc123" || got[0].email != "a@example.com" || got[0].subject != "first" ||
		!slices.Equal(got[0].signers, []string{"A <a@example.com>", "B <b@example.com>"}) {
		t.Errorf("first commit read wrong: %+v", got[0])
	}
	if got[1].sha != "def456" || len(got[1].signers) != 0 {
		t.Errorf("second commit read wrong: %+v", got[1])
	}
	if none, err := parseLog(""); err != nil || len(none) != 0 {
		t.Errorf("an empty range read as %v, %v", none, err)
	}
}

// A commit the check cannot read must stop it, not be skipped: a skipped
// commit is one that passes.
func TestAMalformedLogIsAnError(t *testing.T) {
	for name, log := range map[string]string{
		"a record cut short":   "abc123\x00a@example.com\x00first\x00",
		"no final terminator":  "abc123\x00a@example.com\x00first\x00A <a@example.com>",
		"a field too many":     "abc123\x00a@example.com\x00first\x00A <a@example.com>\x00extra\x00",
		"a record with a stub": "abc123\x00a@example.com\x00first\x00\x00def\x00\x00",
	} {
		if _, err := parseLog(log); err == nil {
			t.Errorf("%s: read as a log", name)
		}
	}
}

// isolateGit keeps the test off whatever repository and configuration the
// machine running it has: git hooks export GIT_DIR, and a global config can
// sign commits, add sign-offs from a hook or sign tags.
func isolateGit(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "GIT_") {
			t.Setenv(name, "")
			os.Unsetenv(name) // t.Setenv restores it when the test ends
		}
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "A")
	t.Setenv("GIT_COMMITTER_NAME", "A")
	t.Setenv("GIT_COMMITTER_EMAIL", "a@x.test")
}

// What counts as a sign-off is git's own reading of the trailers, so this runs
// real git over commits shaped the ways a hand-written parser gets wrong.
func TestAgainstRealGit(t *testing.T) {
	isolateGit(t)
	dir := t.TempDir()
	git := func(env string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), env)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	commit := func(author string, msg ...string) {
		args := []string{"commit", "-q", "--allow-empty", "--allow-empty-message"}
		for _, m := range msg {
			args = append(args, "-m", m)
		}
		git("GIT_AUTHOR_EMAIL="+author, args...)
	}
	git("", "init", "-q")
	commit("a@x.test", "base")
	git("", "tag", "base")

	commit("a@x.test", "signed", "Signed-off-by: A <a@x.test>")
	commit("a@x.test", "unsigned", "just a body")
	commit("a@x.test", "Signed-off-by: A <a@x.test>") // the subject is not a trailer
	commit("a@x.test", "indented", "I forgot\n  Signed-off-by: A <a@x.test>\nand more words")
	commit("a@x.test", "wrong person", "Signed-off-by: B <b@x.test>")
	commit("a@x.test", "name has brackets", "Signed-off-by: A <b@x.test> <a@x.test>")
	commit("a@x.test", "control\x01 characters\x1f in the subject")
	commit("", "no author email", "Signed-off-by: Anyone")

	// A developer's own log configuration must not change what is read.
	git("", "config", "i18n.logOutputEncoding", "UTF-16")
	git("", "config", "log.showSignature", "true")

	cs, err := commits(dir, "base..HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 8 {
		t.Fatalf("read %d commits, made 8", len(cs))
	}
	var passed []string
	for _, c := range cs {
		if signedOff(c) {
			passed = append(passed, c.subject)
		}
	}
	slices.Sort(passed)
	if want := []string{"name has brackets", "signed"}; !slices.Equal(passed, want) {
		t.Errorf("signed off: %v, want %v", passed, want)
	}
}

// With nothing but a sign-off in the message, git makes it the subject, so it is
// not a trailer; and `git rebase --signoff` then sees one already there and
// changes nothing. The contributor has to be told what to do instead.
func TestTheSubjectThatIsASignOffGetsItsOwnHint(t *testing.T) {
	if hint(commit{subject: "Signed-off-by: A <a@x.test>"}) == "" {
		t.Error("no hint for a commit whose subject is its sign-off")
	}
	if got := hint(commit{subject: "Fix a thing"}); got != "" {
		t.Errorf("hint for an ordinary subject: %q", got)
	}
}
