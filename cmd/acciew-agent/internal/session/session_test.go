package session_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/fakeservice"
	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
	"go.acciew.io/collector/cmd/acciew-agent/internal/session"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
)

type rig struct {
	svc *fakeservice.Service
	c   *client.Client
	st  *state.State
	key ed25519.PrivateKey
}

// agent enrols a key, has it confirmed and stores it as the agent would.
func agent(t *testing.T) *rig {
	t.Helper()
	svc := fakeservice.New(t)
	c, err := client.New(svc.URL(), "test")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.GenerateKey()
	svc.AddEnrolment("t")
	got, err := c.Enroll(context.Background(), client.EnrollRequest{Token: "t", Name: "n", PublicKey: base64.StdEncoding.EncodeToString(identity.PublicKey(key))})
	if err != nil {
		t.Fatal(err)
	}
	svc.Confirm(got.AgentID)
	dir := filepath.Join(t.TempDir(), "state")
	if err := state.Create(dir, state.Config{URL: svc.URL(), AgentID: got.AgentID, Fingerprint: got.Fingerprint}, key); err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{svc: svc, c: c, st: st, key: key}
}

func (r *rig) session(t *testing.T) *session.Session {
	t.Helper()
	s, err := session.New(r.c, r.st)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestATokenIsKeptUntilJustBeforeItRunsOut(t *testing.T) {
	r := agent(t)
	r.svc.TokenLife = 10 * time.Minute
	s := r.session(t)
	now := time.Now()
	s.Now = func() time.Time { return now }
	first, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	again, _ := s.Token(context.Background())
	if again != first || r.svc.Hits("POST /agent/v1/token") != 1 {
		t.Fatalf("a second ask within the hour should reuse the token (%d requests)", r.svc.Hits("POST /agent/v1/token"))
	}
	now = now.Add(8 * time.Minute) // two minutes left
	if got, _ := s.Token(context.Background()); got != first {
		t.Error("renewed too early")
	}
	now = now.Add(90 * time.Second) // under a minute left
	renewed, err := s.Token(context.Background())
	if err != nil || renewed == first || r.svc.Hits("POST /agent/v1/token") != 2 {
		t.Errorf("not renewed a minute before the end: %v, %d requests", err, r.svc.Hits("POST /agent/v1/token"))
	}
}

func TestACallThatMeetsA401AsksForANewTokenOnceAndTriesAgain(t *testing.T) {
	r := agent(t)
	s := r.session(t)
	var calls atomic.Int32
	err := s.Do(context.Background(), func(tok string) error {
		calls.Add(1)
		_, err := r.c.Hello(context.Background(), tok)
		return err
	})
	if err != nil || calls.Load() != 1 {
		t.Fatalf("first: %v after %d calls", err, calls.Load())
	}
	r.svc.ForgetTokens()
	calls.Store(0)
	err = s.Do(context.Background(), func(tok string) error {
		calls.Add(1)
		_, err := r.c.Hello(context.Background(), tok)
		return err
	})
	if err != nil || calls.Load() != 2 || r.svc.Hits("POST /agent/v1/token") != 2 {
		t.Errorf("after the token was forgotten: %v after %d calls, %d token requests", err, calls.Load(), r.svc.Hits("POST /agent/v1/token"))
	}
}

func TestACallThatKeepsMeeting401IsNotRetriedForever(t *testing.T) {
	r := agent(t)
	s := r.session(t)
	var calls int
	err := s.Do(context.Background(), func(string) error { calls++; return &client.APIError{Status: http.StatusUnauthorized} })
	if calls != 2 || err == nil {
		t.Errorf("%d calls, err %v", calls, err)
	}
}

func TestACallThatFailsForAnotherReasonIsNotRetried(t *testing.T) {
	r := agent(t)
	s := r.session(t)
	want := &client.APIError{Status: http.StatusConflict, Code: "lease_lost"}
	var calls int
	err := s.Do(context.Background(), func(string) error { calls++; return want })
	if calls != 1 || !errors.Is(err, want) {
		t.Errorf("%d calls, err %v", calls, err)
	}
}

func TestAPendingOrRevokedAgentIsToldWhichBySessionToken(t *testing.T) {
	r := agent(t)
	s := r.session(t)
	r.svc.Revoke(r.st.AgentID)
	_, err := s.Token(context.Background())
	var e *client.APIError
	if !errors.As(err, &e) || e.State != "revoked" {
		t.Errorf("err = %v", err)
	}
}

// A rotation that was sent and whose answer was lost leaves the service holding the new key
// and the agent holding both. Whichever the service accepts is the truth.
func TestAKeyTheServiceTookAfterTheAnswerWasLostIsFoundAndKept(t *testing.T) {
	r := agent(t)
	next, _ := identity.GenerateKey()
	signer, _ := identity.NewSigner(r.st.AgentID, r.key)
	assertion, sig, _ := signer.RotationRequest(r.c.Base, next)
	if _, err := r.c.Rotate(context.Background(), assertion, sig); err != nil {
		t.Fatal(err) // the service took it
	}
	if err := r.st.BeginRotation(next); err != nil { // and the agent never heard
		t.Fatal(err)
	}
	s := r.session(t)
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatalf("the agent could not find its way back in: %v", err)
	}
	reloaded, err := state.Load(r.st.Dir)
	if err != nil || !reloaded.Key.Equal(next) || reloaded.Next != nil {
		t.Fatalf("the new key should now be the key: %v %v", reloaded, err)
	}
	if want := identity.Fingerprint(identity.PublicKey(next)); reloaded.Fingerprint != want {
		t.Errorf("the stored fingerprint is %q, the new key's is %q", reloaded.Fingerprint, want)
	}
}

func TestAPendingKeyTheServiceNeverTookIsDroppedOnceItIsTooOldToBeARotationUnderWay(t *testing.T) {
	r := agent(t)
	next, _ := identity.GenerateKey()
	if err := r.st.BeginRotation(next); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(r.st.Dir, "agent.key.next"), old, old); err != nil {
		t.Fatal(err)
	}
	s := r.session(t)
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	reloaded, err := state.Load(r.st.Dir)
	if err != nil || !reloaded.Key.Equal(r.key) || reloaded.Next != nil {
		t.Errorf("the old key should still be the key and nothing pending: %v %v", reloaded, err)
	}
}

// A rotation in another process is a pending key and a request in flight. The old key still
// works until the service takes the new one, and dropping the pending key then would leave the
// agent with a key the service has just replaced.
func TestAPendingKeyThatIsFreshIsKeptWhileTheOldKeyStillWorks(t *testing.T) {
	r := agent(t)
	next, _ := identity.GenerateKey()
	if err := r.st.BeginRotation(next); err != nil {
		t.Fatal(err)
	}
	s := r.session(t)
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := state.Load(r.st.Dir)
	if !reloaded.Next.Equal(next) {
		t.Error("a pending key was dropped though a rotation may be under way")
	}
}

// `acciew-agent rotate` run in another terminal while the agent runs: the key file changes
// under it, and its next token request meets a service that has forgotten the old key.
func TestAKeyRotatedByAnotherProcessIsFoundOnDiskWhenTheOldOneIsRefused(t *testing.T) {
	r := agent(t)
	s := r.session(t)
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The other process.
	other, _ := state.Load(r.st.Dir)
	next, _ := identity.GenerateKey()
	_ = other.BeginRotation(next)
	signer, _ := identity.NewSigner(other.AgentID, other.Key)
	assertion, sig, _ := signer.RotationRequest(r.c.Base, next)
	if _, err := r.c.Rotate(context.Background(), assertion, sig); err != nil {
		t.Fatal(err)
	}
	_ = other.CommitRotation(identity.Fingerprint(identity.PublicKey(next)))

	// The token the service gave the old key is dead, and this session has not heard.
	var calls int
	err := s.Do(context.Background(), func(tok string) error {
		calls++
		_, err := r.c.Hello(context.Background(), tok)
		return err
	})
	if err != nil {
		t.Fatalf("the agent did not find its way back in: %v", err)
	}
	if !s.State.Key.Equal(next) {
		t.Error("the session still holds the old key")
	}
}

func TestWhenNeitherKeyWorksTheRefusalIsReported(t *testing.T) {
	r := agent(t)
	other, _ := identity.GenerateKey()
	_ = r.st.BeginRotation(other)
	r.svc.Revoke(r.st.AgentID) // 403, not 401: no second try
	s := r.session(t)
	if _, err := s.Token(context.Background()); err == nil {
		t.Fatal("a token for a revoked agent")
	}

	// A state directory whose keys the service has never heard of, current and pending.
	strangers := filepath.Join(t.TempDir(), "state")
	k1, _ := identity.GenerateKey()
	if err := state.Create(strangers, state.Config{URL: r.svc.URL(), AgentID: r.st.AgentID}, k1); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(strangers)
	k2, _ := identity.GenerateKey()
	_ = st.BeginRotation(k2)
	r.svc.Confirm(r.st.AgentID)
	s2, err := session.New(r.c, st)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s2.Token(context.Background())
	var api *client.APIError
	if !errors.As(err, &api) || api.Status != http.StatusUnauthorized {
		t.Errorf("err = %v, want the 401 for the current key", err)
	}
}
