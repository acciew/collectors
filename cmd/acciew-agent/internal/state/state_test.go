package state_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
)

const id = "0a1b2c3d-0000-4000-8000-000000000001.9f8e7d6c-0000-4000-8000-000000000002"

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	k, err := identity.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func cfg() state.Config {
	return state.Config{URL: "https://acciew.example.test", AgentID: id, Name: "plant-1", Fingerprint: "aaaa-bbbb"}
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestWhatIsEnrolledIsReadBackAndTheKeyFileIsOnlyTheOwners(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := newKey(t)
	if err := state.Create(dir, cfg(), key); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(dir, "agent.key")); m != 0o600 {
		t.Errorf("the key file is %o, want 600", m)
	}
	if m := mode(t, dir); m&0o077 != 0 {
		t.Errorf("the state directory is %o: others can enter it", m)
	}
	got, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Key.Equal(key) || got.URL != cfg().URL || got.AgentID != id || got.Name != "plant-1" || got.Next != nil {
		t.Errorf("read back %+v", got)
	}
}

// openssl and every other tool reads a PKCS#8 PEM, so the key can be inspected or
// moved by someone who is not the agent.
func TestTheKeyIsStoredAsPKCS8PEM(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	if err := state.Create(dir, cfg(), key); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "agent.key"))
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("not a PEM PRIVATE KEY: %q", raw)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil || !key.Equal(parsed) {
		t.Errorf("parse: %v", err)
	}
}

// Enrolling twice into one directory would replace a key the service still trusts
// with one it has never heard of.
func TestEnrollingIntoAnEnrolledDirectoryNeverReplacesItsKey(t *testing.T) {
	dir := t.TempDir()
	first := newKey(t)
	if err := state.Create(dir, cfg(), first); err != nil {
		t.Fatal(err)
	}
	if err := state.Create(dir, cfg(), newKey(t)); !errors.Is(err, state.ErrEnrolled) {
		t.Fatalf("second Create = %v, want ErrEnrolled", err)
	}
	got, err := state.Load(dir)
	if err != nil || !got.Key.Equal(first) {
		t.Errorf("the first key was lost: %v", err)
	}
}

func TestAKeyOthersCanReadIsRefusedAtStartup(t *testing.T) {
	dir := t.TempDir()
	if err := state.Create(dir, cfg(), newKey(t)); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "agent.key")
	for _, m := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(keyFile, m); err != nil {
			t.Fatal(err)
		}
		_, err := state.Load(dir)
		if err == nil || !strings.Contains(err.Error(), keyFile) || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %o: Load = %v, want a refusal that names the file and the fix", m, err)
		}
	}
}

func TestADirectoryThatWasNeverEnrolledSaysSo(t *testing.T) {
	_, err := state.Load(filepath.Join(t.TempDir(), "nothing"))
	if !errors.Is(err, state.ErrNotEnrolled) {
		t.Errorf("Load = %v, want ErrNotEnrolled", err)
	}
}

func TestAKeyFileThatIsNotAKeyIsRefusedNotUsed(t *testing.T) {
	dir := t.TempDir()
	if err := state.Create(dir, cfg(), newKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.key"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Load(dir); err == nil {
		t.Error("Load accepted a key file with 'hello' in it")
	}
}

func TestARotationIsHeldNextToTheKeyUntilItIsCommitted(t *testing.T) {
	dir := t.TempDir()
	old := newKey(t)
	if err := state.Create(dir, cfg(), old); err != nil {
		t.Fatal(err)
	}
	s, _ := state.Load(dir)
	next := newKey(t)
	if err := s.BeginRotation(next); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(dir, "agent.key.next")); m != 0o600 {
		t.Errorf("the pending key is %o, want 600", m)
	}
	// Seen again, as after a crash: the old key still stands and the new one is waiting.
	again, err := state.Load(dir)
	if err != nil || !again.Key.Equal(old) || !again.Next.Equal(next) {
		t.Fatalf("after BeginRotation: %+v, %v", again, err)
	}
	if err := again.CommitRotation("cccc-dddd"); err != nil {
		t.Fatal(err)
	}
	done, err := state.Load(dir)
	if err != nil || !done.Key.Equal(next) || done.Next != nil || done.Fingerprint != "cccc-dddd" {
		t.Fatalf("after CommitRotation: %+v, %v", done, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.key.next")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the pending key file is still there: %v", err)
	}
}

func TestAnAbandonedRotationLeavesTheOldKeyAlone(t *testing.T) {
	dir := t.TempDir()
	old := newKey(t)
	if err := state.Create(dir, cfg(), old); err != nil {
		t.Fatal(err)
	}
	s, _ := state.Load(dir)
	if err := s.BeginRotation(newKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.AbandonRotation(); err != nil {
		t.Fatal(err)
	}
	got, err := state.Load(dir)
	if err != nil || !got.Key.Equal(old) || got.Next != nil {
		t.Errorf("after AbandonRotation: %+v, %v", got, err)
	}
	if err := s.AbandonRotation(); err != nil {
		t.Errorf("abandoning nothing should be quiet: %v", err)
	}
}

func TestADirectoryUnderTheStateDirectoryIsWhereTheSpoolAndRunFilesGo(t *testing.T) {
	dir := t.TempDir()
	if err := state.Create(dir, cfg(), newKey(t)); err != nil {
		t.Fatal(err)
	}
	s, _ := state.Load(dir)
	if s.SpoolDir() != filepath.Join(dir, "spool") || s.RunDir() != filepath.Join(dir, "run") {
		t.Errorf("spool %q, run %q", s.SpoolDir(), s.RunDir())
	}
	if !s.Contains(filepath.Join(dir, "agent.key")) || s.Contains(filepath.Join(filepath.Dir(dir), "elsewhere")) {
		t.Error("Contains does not tell the state directory's files from others")
	}
}

func TestTwoAgentsCannotRunOnOneStateDirectory(t *testing.T) {
	dir := t.TempDir()
	unlock, err := state.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Lock(dir); err == nil || !strings.Contains(err.Error(), "another acciew-agent") {
		t.Errorf("a second Lock = %v", err)
	}
	unlock()
	again, err := state.Lock(dir)
	if err != nil {
		t.Fatalf("after unlocking: %v", err)
	}
	again()
}

func TestACommitAnotherProcessAlreadyMadeIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := state.Create(dir, cfg(), newKey(t)); err != nil {
		t.Fatal(err)
	}
	a, _ := state.Load(dir)
	b, _ := state.Load(dir)
	next := newKey(t)
	if err := a.BeginRotation(next); err != nil {
		t.Fatal(err)
	}
	b.Next = next // the same rotation, as seen by a second process
	if err := b.CommitRotation("aaaa"); err != nil {
		t.Fatal(err)
	}
	if err := a.CommitRotation("aaaa"); err != nil {
		t.Errorf("the second commit of one rotation failed: %v", err)
	}
	got, _ := state.Load(dir)
	if !got.Key.Equal(next) {
		t.Error("the new key is not the key")
	}
	// But a pending key that is not the one in the file is an error, not a silent success.
	c, _ := state.Load(dir)
	c.Next = newKey(t)
	if err := c.CommitRotation("bbbb"); err == nil {
		t.Error("a commit of a key that was never written succeeded")
	}
}

func TestReloadSeesAKeyChangedByAnotherProcess(t *testing.T) {
	dir := t.TempDir()
	if err := state.Create(dir, cfg(), newKey(t)); err != nil {
		t.Fatal(err)
	}
	mine, _ := state.Load(dir)
	if changed, err := mine.Reload(); err != nil || changed {
		t.Fatalf("nothing changed: %v %v", changed, err)
	}
	other, _ := state.Load(dir)
	next := newKey(t)
	_ = other.BeginRotation(next)
	if changed, err := mine.Reload(); err != nil || !changed || !mine.Next.Equal(next) {
		t.Fatalf("a pending key appeared: %v %v", changed, err)
	}
	_ = other.CommitRotation("cccc")
	if changed, err := mine.Reload(); err != nil || !changed || !mine.Key.Equal(next) || mine.Next != nil {
		t.Fatalf("the key changed: %v %v", changed, err)
	}
	if _, ok := mine.NextAge(); ok {
		t.Error("a pending key is reported with none")
	}
}

func TestAnEnrolmentFileThatIsDamagedOrIncompleteIsRefusedWithItsName(t *testing.T) {
	for name, content := range map[string]string{
		"not JSON":      "{",
		"no service":    `{"agent_id": "` + id + `"}`,
		"no agent":      `{"url": "https://acciew.example.test"}`,
		"an empty file": "",
		"a wrong shape": `[1,2]`,
	} {
		dir := t.TempDir()
		if err := state.Create(dir, cfg(), newKey(t)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "agent.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := state.Load(dir); err == nil || !strings.Contains(err.Error(), "agent.json") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestAPendingKeyThatIsDamagedIsAnErrorNotAFreshStart(t *testing.T) {
	dir := t.TempDir()
	if err := state.Create(dir, cfg(), newKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.key.next"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Load(dir); err == nil {
		t.Error("Load ignored a pending key it could not read")
	}
}

func TestAKeyOfAnotherKindIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := state.Create(dir, cfg(), newKey(t)); err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "agent.key"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Load(dir); err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Errorf("err = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not der")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Load(dir); err == nil {
		t.Error("a PEM block that is not a key was accepted")
	}
}

func TestADirectoryThatCannotBeMadeIsReported(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	if err := state.Create(filepath.Join(blocker, "state"), cfg(), newKey(t)); err == nil {
		t.Error("a state directory was made under a file")
	}
	if _, err := state.Lock(filepath.Join(blocker, "state")); err == nil {
		t.Error("a lock was taken in a directory that is not there")
	}
}

func TestACommitWithNothingPendingIsAnError(t *testing.T) {
	dir := t.TempDir()
	_ = state.Create(dir, cfg(), newKey(t))
	s, _ := state.Load(dir)
	if err := s.CommitRotation("x"); err == nil {
		t.Error("committed a rotation nobody began")
	}
}

func TestWhetherAPathIsInsideTheStateDirectoryFollowsLinksAndSeesWhatIsNotThereYet(t *testing.T) {
	dir := t.TempDir()
	_ = state.Create(dir, cfg(), newKey(t))
	s, _ := state.Load(dir)
	outside := t.TempDir()
	link := filepath.Join(outside, "to-state")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		filepath.Join(dir, "agent.key"):        true,
		filepath.Join(dir, "spool", "not-yet"): true,
		filepath.Join(dir, "a", "b", "c", "d"): true,
		link:                                   true,
		filepath.Join(link, "agent.key"):       true,
		filepath.Join(outside, "other"):        false,
		filepath.Join(dir, "..", "elsewhere"):  false,
		dir + "-sibling":                       false,
	} {
		if got := s.Contains(path); got != want {
			t.Errorf("Contains(%s) = %v, want %v", path, got, want)
		}
	}
}

func TestAStateDirectoryThatVanishesIsAnErrorForEverythingThatWritesOrReadsIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := state.Create(dir, cfg(), newKey(t)); err != nil {
		t.Fatal(err)
	}
	s, _ := state.Load(dir)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reload(); err == nil {
		t.Error("Reload of a directory that is gone succeeded")
	}
	if err := s.BeginRotation(newKey(t)); err == nil {
		t.Error("a rotation was begun in a directory that is gone")
	}
}

// Rotations write the pending key beside the key; two at once overwrite each other's.
func TestOnlyOneRotationRunsAtATimeAndARunningAgentDoesNotBlockIt(t *testing.T) {
	dir := t.TempDir()
	unlock, err := state.LockRotation(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.LockRotation(dir); err == nil || !strings.Contains(err.Error(), "another acciew-agent rotate") {
		t.Errorf("a second rotation: %v", err)
	}
	// The agent that is running holds its own lock, and rotating beside it is supported.
	run, err := state.Lock(dir)
	if err != nil {
		t.Fatalf("the run lock should be independent of the rotation lock: %v", err)
	}
	run()
	unlock()
	again, err := state.LockRotation(dir)
	if err != nil {
		t.Fatalf("after the first finished: %v", err)
	}
	again()
	if _, err := state.LockRotation(filepath.Join(dir, "missing", "deeper")); err == nil {
		t.Error("a lock was taken in a directory that is not there")
	}
}

func TestTheKeyIsTheKeyUnderAnyCaseAndAnyNameItHas(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Agent State")
	if err := state.Create(dir, cfg(), newKey(t)); err != nil {
		t.Fatal(err)
	}
	s, _ := state.Load(dir)

	// A hard link to the key is the key.
	hard := filepath.Join(t.TempDir(), "innocent")
	if err := os.Link(filepath.Join(dir, "agent.key"), hard); err == nil {
		if !s.Contains(hard) {
			t.Error("a hard link to the key was not taken for it")
		}
	}

	// On a filesystem that ignores case, another spelling of the directory is the directory.
	if _, err := os.Stat(strings.ToLower(dir)); err != nil {
		t.Log("this filesystem tells cases apart: the case test is skipped")
		return
	}
	for _, spelled := range []string{strings.ToLower(dir), strings.ToUpper(dir), filepath.Join(strings.ToUpper(dir), "AGENT.KEY")} {
		if !s.Contains(spelled) {
			t.Errorf("%s was not taken for the state directory", spelled)
		}
	}
	if s.Contains(strings.ToLower(dir) + "-sibling") {
		t.Error("a sibling was taken for the state directory")
	}
}
