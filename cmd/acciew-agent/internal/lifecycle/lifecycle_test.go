package lifecycle_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/fakeservice"
	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
	"go.acciew.io/collector/cmd/acciew-agent/internal/lifecycle"
	"go.acciew.io/collector/cmd/acciew-agent/internal/session"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
)

func enrol(t *testing.T, svc *fakeservice.Service, dir string, out *bytes.Buffer) error {
	t.Helper()
	svc.AddEnrolment("acc_enr_good")
	return lifecycle.Enroll(context.Background(), lifecycle.Enrollment{
		URL: svc.URL(), Token: "acc_enr_good", Name: "plant-1 edge", StateDir: dir, Version: "9.9.9", Out: out,
	})
}

func TestEnrollingStoresAKeyAndPrintsTheFingerprintToGiveAnAdministrator(t *testing.T) {
	svc := fakeservice.New(t)
	dir := filepath.Join(t.TempDir(), "state")
	var out bytes.Buffer
	if err := enrol(t, svc, dir, &out); err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.URL != svc.URL() || st.Name != "plant-1 edge" {
		t.Errorf("stored %+v", st.Config)
	}
	agent := svc.Agent(st.AgentID)
	if agent == nil || agent.State != "pending" || agent.Name != "plant-1 edge" {
		t.Fatalf("the service knows %+v", agent)
	}
	if agent.Versions["agent"] != "9.9.9" || agent.Versions["protocol"] != "1" {
		t.Errorf("versions sent: %v", agent.Versions)
	}
	if !ed25519.PublicKey(agent.Key).Equal(st.Key.Public()) {
		t.Error("the service holds a key other than the one stored")
	}
	fp := identity.Fingerprint(identity.PublicKey(st.Key))
	for _, want := range []string{st.AgentID, fp, "administrator"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output should say %q:\n%s", want, out.String())
		}
	}
}

// A proxy that took the token first, or swapped the key, shows a fingerprint the agent
// never made. Continuing would store a key the service does not hold.
func TestAFingerprintThatIsNotThisKeysIsRefusedAndNothingIsStored(t *testing.T) {
	svc := fakeservice.New(t)
	svc.Fingerprint = "dead-beef-dead-beef-dead-beef-dead-beef"
	dir := filepath.Join(t.TempDir(), "state")
	var out bytes.Buffer
	err := enrol(t, svc, dir, &out)
	if err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("err = %v", err)
	}
	if _, lerr := state.Load(dir); !errors.Is(lerr, state.ErrNotEnrolled) {
		t.Errorf("something was stored: %v", lerr)
	}
	if strings.Contains(out.String(), "dead-beef") {
		t.Errorf("the service's fingerprint was shown as if it were ours:\n%s", out.String())
	}
}

func TestAnEnrolmentTokenTheServiceRefusesIsSaidPlainly(t *testing.T) {
	svc := fakeservice.New(t)
	dir := filepath.Join(t.TempDir(), "state")
	err := lifecycle.Enroll(context.Background(), lifecycle.Enrollment{URL: svc.URL(), Token: "acc_enr_wrong", StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "enrolment token") {
		t.Errorf("err = %v", err)
	}
	if _, lerr := state.Load(dir); !errors.Is(lerr, state.ErrNotEnrolled) {
		t.Errorf("something was stored: %v", lerr)
	}
}

// A single-use token must not be spent on a directory that would then refuse the key.
func TestAnEnrolledDirectoryIsRefusedBeforeTheTokenIsSpent(t *testing.T) {
	svc := fakeservice.New(t)
	dir := filepath.Join(t.TempDir(), "state")
	if err := enrol(t, svc, dir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	before := svc.Hits("POST /agent/v1/enroll")
	err := enrol(t, svc, dir, &bytes.Buffer{})
	if !errors.Is(err, state.ErrEnrolled) || svc.Hits("POST /agent/v1/enroll") != before {
		t.Errorf("err = %v, enrol requests %d -> %d", err, before, svc.Hits("POST /agent/v1/enroll"))
	}
}

func TestAnAddressThatIsNotHTTPSIsRefusedBeforeAnythingIsMade(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	err := lifecycle.Enroll(context.Background(), lifecycle.Enrollment{URL: "http://acciew.example.test", Token: "t", StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("plain http accepted")
	}
	if _, serr := state.Load(dir); !errors.Is(serr, state.ErrNotEnrolled) {
		t.Error("a key was made for a service that was never going to be asked")
	}
}

func TestWithoutANameTheHostNameIsUsed(t *testing.T) {
	svc := fakeservice.New(t)
	dir := filepath.Join(t.TempDir(), "state")
	svc.AddEnrolment("t")
	err := lifecycle.Enroll(context.Background(), lifecycle.Enrollment{URL: svc.URL(), Token: "t", StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(dir)
	if svc.Agent(st.AgentID).Name == "" {
		t.Error("the agent enrolled with no name")
	}
}

// confirmed enrols and has an administrator confirm.
func confirmed(t *testing.T) (*fakeservice.Service, string) {
	t.Helper()
	svc := fakeservice.New(t)
	dir := filepath.Join(t.TempDir(), "state")
	if err := enrol(t, svc, dir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(dir)
	svc.Confirm(st.AgentID)
	return svc, dir
}

func TestRotatingSwapsTheKeyAndTheOldTokenIsDead(t *testing.T) {
	svc, dir := confirmed(t)
	st, _ := state.Load(dir)
	old := st.Key
	c, _ := client.New(svc.URL(), "t")
	sess, _ := session.New(c, st)
	oldToken, err := sess.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := lifecycle.Rotate(context.Background(), lifecycle.RotationOf{StateDir: dir, Version: "1", Out: &out}); err != nil {
		t.Fatal(err)
	}
	after, err := state.Load(dir)
	if err != nil || after.Key.Equal(old) || after.Next != nil {
		t.Fatalf("after: %v, key replaced %v", err, !after.Key.Equal(old))
	}
	if !ed25519.PublicKey(svc.Agent(st.AgentID).Key).Equal(after.Key.Public()) {
		t.Error("the service holds a key other than the new one")
	}
	if _, err := c.Hello(context.Background(), oldToken); err == nil {
		t.Error("the access token the old key got still works")
	}
	fresh, _ := session.New(c, after)
	if _, err := fresh.Token(context.Background()); err != nil {
		t.Errorf("the new key could not get a token: %v", err)
	}
	if !strings.Contains(out.String(), identity.Fingerprint(identity.PublicKey(after.Key))) {
		t.Errorf("the new fingerprint was not printed:\n%s", out.String())
	}
}

func TestARotationTheServiceRefusesLeavesTheOldKey(t *testing.T) {
	svc, dir := confirmed(t)
	st, _ := state.Load(dir)
	svc.Revoke(st.AgentID)
	err := lifecycle.Rotate(context.Background(), lifecycle.RotationOf{StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("rotated a revoked agent")
	}
	after, lerr := state.Load(dir)
	if lerr != nil || !after.Key.Equal(st.Key) || after.Next != nil {
		t.Errorf("after a refusal: %v, next %v", lerr, after.Next != nil)
	}
}

func TestARotationWhoseAnswerIsLostKeepsBothKeysAndTheNextRunFindsTheRightOne(t *testing.T) {
	svc, dir := confirmed(t)
	svc.DropAnswers(fakeservice.Path("POST", "/agent/v1/rotate"), 1)
	err := lifecycle.Rotate(context.Background(), lifecycle.RotationOf{StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "not known") {
		t.Fatalf("err = %v, want it to say the outcome is not known", err)
	}
	mid, _ := state.Load(dir)
	if mid.Next == nil {
		t.Fatal("the new key was dropped while the service may hold it")
	}
	pending := mid.Next
	c, _ := client.New(svc.URL(), "t")
	sess, _ := session.New(c, mid)
	if _, err := sess.Token(context.Background()); err != nil {
		t.Fatalf("the agent could not get back in: %v", err)
	}
	end, _ := state.Load(dir)
	if end.Next != nil || !end.Key.Equal(pending) {
		t.Error("the key the service took did not become the key")
	}
}

func TestAFingerprintForTheNewKeyThatIsNotTheNewKeysIsNotCommitted(t *testing.T) {
	svc, dir := confirmed(t)
	svc.Fingerprint = "dead-beef-dead-beef-dead-beef-dead-beef"
	err := lifecycle.Rotate(context.Background(), lifecycle.RotationOf{StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("err = %v", err)
	}
	after, _ := state.Load(dir)
	if after.Next == nil {
		t.Error("the pending key was dropped though the service may have taken something")
	}
}

func TestAServiceThatFailsToEnrolIsReportedAndNothingIsStored(t *testing.T) {
	svc := fakeservice.New(t)
	svc.Fail(fakeservice.Path("POST", "/agent/v1/enroll"), 1, http.StatusInternalServerError, nil)
	dir := filepath.Join(t.TempDir(), "state")
	err := lifecycle.Enroll(context.Background(), lifecycle.Enrollment{URL: svc.URL(), Token: "t", StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "enrolling") {
		t.Errorf("err = %v", err)
	}
	if _, lerr := state.Load(dir); !errors.Is(lerr, state.ErrNotEnrolled) {
		t.Errorf("something was stored: %v", lerr)
	}
}

func TestAnAgentIdTheAgentCannotUseIsRefusedAndNothingIsStored(t *testing.T) {
	svc := fakeservice.New(t)
	svc.AgentID = "agent-1"
	dir := filepath.Join(t.TempDir(), "state")
	err := enrol(t, svc, dir, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "agent id") {
		t.Errorf("err = %v", err)
	}
	if _, lerr := state.Load(dir); !errors.Is(lerr, state.ErrNotEnrolled) {
		t.Errorf("something was stored: %v", lerr)
	}
}

// The service has the agent and the host cannot keep its key: the human is told which agent to delete.
func TestAKeyThatCannotBeStoredAfterTheServiceTookItNamesTheAgentToDelete(t *testing.T) {
	svc := fakeservice.New(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := enrol(t, svc, filepath.Join(blocker, "state"), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "registered this agent as") || !strings.Contains(err.Error(), "delete the agent") {
		t.Errorf("err = %v", err)
	}
}

func TestAnEnrolmentWhoseServiceAddressIsNoLongerUsableCannotBeRotated(t *testing.T) {
	svc, dir := confirmed(t)
	cfgPath := filepath.Join(dir, "agent.json")
	raw, _ := os.ReadFile(cfgPath)
	if err := os.WriteFile(cfgPath, bytes.ReplaceAll(raw, []byte(svc.URL()), []byte("http://acciew.example.test")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Rotate(context.Background(), lifecycle.RotationOf{StateDir: dir, Version: "1", Out: &bytes.Buffer{}}); err == nil {
		t.Error("rotated against plain http")
	}
}

// A refusal that is the service's answer to the new key (not an outage) is final: the pending key goes.
func TestARotationTheServiceAnswersWithARefusalDropsThePendingKey(t *testing.T) {
	svc, dir := confirmed(t)
	svc.Fail(fakeservice.Path("POST", "/agent/v1/rotate"), 1, http.StatusConflict, nil)
	err := lifecycle.Rotate(context.Background(), lifecycle.RotationOf{StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "old one is kept") {
		t.Fatalf("err = %v", err)
	}
	after, _ := state.Load(dir)
	if after.Next != nil {
		t.Error("a key the service refused is still pending")
	}
}

func TestAnOutageDuringARotationKeepsBothKeysAndSaysTheOutcomeIsNotKnown(t *testing.T) {
	svc, dir := confirmed(t)
	svc.Fail(fakeservice.Path("POST", "/agent/v1/rotate"), 1, http.StatusBadGateway, nil)
	err := lifecycle.Rotate(context.Background(), lifecycle.RotationOf{StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "not known") {
		t.Fatalf("err = %v", err)
	}
	if after, _ := state.Load(dir); after.Next == nil {
		t.Error("the pending key was dropped though the service may have taken it")
	}
}

func TestARotationIsRefusedWhileAnotherHoldsTheLockAndTouchesNothing(t *testing.T) {
	svc, dir := confirmed(t)
	before, _ := state.Load(dir)
	unlock, err := state.LockRotation(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	err = lifecycle.Rotate(context.Background(), lifecycle.RotationOf{StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "another acciew-agent rotate") {
		t.Fatalf("err = %v", err)
	}
	after, _ := state.Load(dir)
	if !after.Key.Equal(before.Key) || after.Next != nil || svc.Hits("POST /agent/v1/rotate") != 0 {
		t.Errorf("the refused rotation changed something (key same %v, pending %v, %d requests)", after.Key.Equal(before.Key), after.Next != nil, svc.Hits("POST /agent/v1/rotate"))
	}
}

// Without the lock: A writes the pending key, B overwrites it, A's key is registered, B (signed
// with the old key) is refused and removes the pending key, and the service holds A's key while
// the disk has only the old one. With it, whatever happens, the disk and the service agree.
func TestTwoRotationsAtOnceNeverLeaveTheDiskAndTheServiceHoldingDifferentKeys(t *testing.T) {
	for round := range 10 {
		svc, dir := confirmed(t)
		svc.RotateDelay = 60 * time.Millisecond // long enough for the second to begin
		st, _ := state.Load(dir)
		var wg sync.WaitGroup
		results := make([]error, 2)
		start := make(chan struct{})
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i] = lifecycle.Rotate(context.Background(), lifecycle.RotationOf{StateDir: dir, Version: "1", Out: &bytes.Buffer{}})
			}()
		}
		close(start)
		wg.Wait()
		if results[0] != nil && results[1] != nil {
			t.Fatalf("round %d: both failed: %v / %v", round, results[0], results[1])
		}
		if results[0] == nil && results[1] == nil {
			t.Fatalf("round %d: both rotated at once", round)
		}
		after, err := state.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		held := svc.Agent(st.AgentID).Key
		if !ed25519.PublicKey(held).Equal(identity.PublicKey(after.Key)) || after.Next != nil {
			t.Fatalf("round %d: the service holds a key the disk does not (pending %v); results %v / %v", round, after.Next != nil, results[0], results[1])
		}
		c, _ := client.New(svc.URL(), "t")
		sess, _ := session.New(c, after)
		if _, err := sess.Token(context.Background()); err != nil {
			t.Fatalf("round %d: the agent is locked out: %v", round, err)
		}
	}
}
