package loop_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/backoff"
	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/fakeservice"
	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
	"go.acciew.io/collector/cmd/acciew-agent/internal/job"
	"go.acciew.io/collector/cmd/acciew-agent/internal/loop"
	"go.acciew.io/collector/cmd/acciew-agent/internal/session"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
	"go.acciew.io/collector/cmd/acciew-agent/internal/testbin"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testbin.Cleanup()
	os.Exit(code)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type rig struct {
	svc   *fakeservice.Service
	st    *state.State
	agent *loop.Agent
	out   *syncBuffer
	logs  *syncBuffer
	id    string
}

func newRig(t *testing.T, confirm bool) *rig {
	t.Helper()
	svc := fakeservice.New(t)
	svc.Hold = 50 * time.Millisecond
	c, _ := client.New(svc.URL(), "test")
	key, _ := identity.GenerateKey()
	svc.AddEnrolment("t")
	got, err := c.Enroll(context.Background(), client.EnrollRequest{Token: "t", Name: "n", PublicKey: base64.StdEncoding.EncodeToString(identity.PublicKey(key))})
	if err != nil {
		t.Fatal(err)
	}
	if confirm {
		svc.Confirm(got.AgentID)
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := state.Create(dir, state.Config{URL: svc.URL(), AgentID: got.AgentID}, key); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(dir)
	sess, _ := session.New(c, st)
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	runner := job.New(job.Config{
		Client: c, Session: sess, CollectorsDir: testbin.Collectors(t), SpoolDir: st.SpoolDir(),
		Secrets:        job.SecretsPolicy{Dir: t.TempDir(), Forbidden: st.Contains, AllowAny: true},
		Backoff:        backoff.Policy{Min: time.Millisecond, Max: 5 * time.Millisecond},
		UploadPatience: 3 * time.Second,
		HeartbeatEvery: func(*client.Job) time.Duration { return 50 * time.Millisecond },
		Log:            log,
	})
	out := &syncBuffer{}
	return &rig{svc: svc, st: st, id: got.AgentID, out: out, logs: logs, agent: &loop.Agent{
		Client: c, Session: sess, Runner: runner, Log: log, Out: out,
		Backoff: backoff.Policy{Min: 10 * time.Millisecond, Max: 80 * time.Millisecond},
		MinPoll: 20 * time.Millisecond, SpoolDir: st.SpoolDir(),
	}}
}

// start runs the agent until the test ends or stop is called.
func (r *rig) start(t *testing.T) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.agent.Run(ctx) }()
	var once sync.Once
	var err error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Error("the agent did not stop within 10 seconds of being asked")
			}
		})
		return err
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s\nlogs:\n%s", what, "")
}

func okJob() fakeservice.Job {
	return fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":3}`}
}

func TestTheAgentTakesJobsOneAfterAnotherAndStopsWhenAskedWithoutError(t *testing.T) {
	r := newRig(t, true)
	a, b := r.svc.Queue(okJob()), r.svc.Queue(okJob())
	stop := r.start(t)
	waitFor(t, "both jobs to be uploaded", func() bool { return a.Final() && b.Final() })
	start := time.Now()
	if err := stop(); err != nil {
		t.Errorf("Run = %v after being asked to stop", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("stopping took %v: a held poll was not cut short", time.Since(start))
	}
}

func TestAnUnconfirmedAgentSaysItWaitsAndStartsWorkWhenConfirmed(t *testing.T) {
	r := newRig(t, false)
	run := r.svc.Queue(okJob())
	r.start(t)
	waitFor(t, "the waiting message", func() bool { return strings.Contains(r.out.String(), "waiting") })
	fp := identity.Fingerprint(identity.PublicKey(r.st.Key))
	if !strings.Contains(r.out.String(), fp) {
		t.Errorf("the message should carry the fingerprint %s:\n%s", fp, r.out.String())
	}
	time.Sleep(200 * time.Millisecond)
	if run.Final() || r.svc.Hits("GET /agent/v1/jobs") != 0 {
		t.Fatal("work was asked for before the fingerprint was confirmed")
	}
	if n := strings.Count(r.out.String(), "waiting for an administrator"); n != 1 {
		t.Errorf("the waiting message was printed %d times", n)
	}
	r.svc.Confirm(r.id)
	waitFor(t, "the job to be uploaded", run.Final)
}

func TestARevokedAgentStopsAndSaysItMustBeEnrolledAgain(t *testing.T) {
	r := newRig(t, true)
	r.svc.Revoke(r.id)
	err := r.agent.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "revoked") || !strings.Contains(err.Error(), "enrol") {
		t.Errorf("Run = %v", err)
	}
}

func TestAThrottleIsWaitedOutAsTheServiceAsked(t *testing.T) {
	r := newRig(t, true)
	r.svc.Fail(fakeservice.Path(http.MethodGet, "/agent/v1/jobs"), 1, http.StatusTooManyRequests, http.Header{"Retry-After": {"1"}})
	run := r.svc.Queue(okJob())
	start := time.Now()
	r.start(t)
	waitFor(t, "the job", run.Final)
	if time.Since(start) < time.Second {
		t.Errorf("the job was done after %v: Retry-After was not honoured", time.Since(start))
	}
}

func TestAnExpiredTokenIsReplacedAndWorkGoesOn(t *testing.T) {
	r := newRig(t, true)
	r.start(t)
	waitFor(t, "a first poll", func() bool { return r.svc.Hits("GET /agent/v1/jobs") > 0 })
	r.svc.ForgetTokens()
	run := r.svc.Queue(okJob())
	waitFor(t, "the job", run.Final)
	if r.svc.Hits("POST /agent/v1/token") < 2 {
		t.Error("no new token was asked for")
	}
}

// An answer that comes at once, again and again, must not become a loop with no pause in it.
func TestAServiceThatAnswersNoWorkAtOnceIsNotAskedInATightLoop(t *testing.T) {
	r := newRig(t, true)
	r.svc.Hold = 0
	r.agent.MinPoll = 200 * time.Millisecond
	r.start(t)
	time.Sleep(1100 * time.Millisecond)
	if n := r.svc.Hits("GET /agent/v1/jobs"); n > 7 || n < 3 {
		t.Errorf("%d polls in 1.1s at a floor of one per 200ms", n)
	}
}

func TestANetworkThatFailsIsRetriedWithGrowingPausesAndWorkResumes(t *testing.T) {
	r := newRig(t, true)
	r.svc.DropRequests(fakeservice.Path(http.MethodGet, "/agent/v1/jobs"), 4)
	run := r.svc.Queue(okJob())
	start := time.Now()
	r.start(t)
	waitFor(t, "the job", run.Final)
	// Four drops, though the HTTP client itself tries a dropped GET once more, so the agent saw at
	// least two failures: waits of at least half of 10 and 20ms between them.
	if el := time.Since(start); el < 15*time.Millisecond {
		t.Errorf("the job was done after %v: the retries were not paced", el)
	}
	if hits := r.svc.Hits("GET /agent/v1/jobs"); hits < 5 {
		t.Errorf("%d polls: the dropped ones were not asked again", hits)
	}
}

func TestAnAgentWithAClockMoreThanAMinuteOffSaysSo(t *testing.T) {
	r := newRig(t, true)
	future := time.Now().Add(10 * time.Minute).UTC().Format(http.TimeFormat)
	r.svc.Fail(fakeservice.Path(http.MethodPost, "/agent/v1/token"), 3, http.StatusUnauthorized, http.Header{"Date": {future}})
	r.start(t)
	waitFor(t, "the clock warning", func() bool { return strings.Contains(r.logs.String(), "clock") })
	if !strings.Contains(r.logs.String(), "ahead") {
		t.Errorf("the warning should say which way:\n%s", r.logs.String())
	}
}

func TestSpoolsACrashLeftBehindAreCleanedWhenTheAgentStarts(t *testing.T) {
	r := newRig(t, true)
	if err := os.MkdirAll(r.st.SpoolDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(r.st.SpoolDir(), "job-12345.frames")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.start(t)
	waitFor(t, "the stale spool to go", func() bool { _, err := os.Stat(stale); return errors.Is(err, os.ErrNotExist) })
}

func TestStoppingMidJobStopsTheCollectorAndTheAgentReturnsNil(t *testing.T) {
	r := newRig(t, true)
	pid := filepath.Join(t.TempDir(), "pid")
	run := r.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"slow","records":500,"delay_ms":40,"pid_file":"` + pid + `"}`})
	stop := r.start(t)
	waitFor(t, "the job to be taken", func() bool { _, err := os.Stat(pid); return err == nil })
	if err := stop(); err != nil {
		t.Errorf("Run = %v", err)
	}
	if run.Final() || run.Aborted() != "" {
		t.Errorf("a stopped agent finished (%v) or gave up (%q) a job it should leave to lapse", run.Final(), run.Aborted())
	}
}

func TestAnAgentThatCannotReachTheServiceForATokenKeepsTryingAndGetsInWhenItCan(t *testing.T) {
	r := newRig(t, true)
	r.agent.Backoff = backoff.Policy{} // the defaults: a second at first, which a test of this size can afford
	r.svc.DropRequests(fakeservice.Path(http.MethodPost, "/agent/v1/token"), 2)
	run := r.svc.Queue(okJob())
	r.start(t)
	waitFor(t, "the job", run.Final)
	if !strings.Contains(r.logs.String(), "could not reach the service for a token") {
		t.Errorf("the log does not say the service was unreachable:\n%s", r.logs.String())
	}
}

func TestARefusedAssertionWithNothingWrongWithTheClockIsNotBlamedOnIt(t *testing.T) {
	r := newRig(t, true)
	r.svc.Fail(fakeservice.Path(http.MethodPost, "/agent/v1/token"), 2, http.StatusUnauthorized, nil)
	run := r.svc.Queue(okJob())
	r.start(t)
	waitFor(t, "the job", run.Final)
	if !strings.Contains(r.logs.String(), "still registered") || strings.Contains(r.logs.String(), "ahead of") {
		t.Errorf("log:\n%s", r.logs.String())
	}
}

func TestAClockBehindTheServicesIsReportedAsBehind(t *testing.T) {
	r := newRig(t, true)
	past := time.Now().Add(-10 * time.Minute).UTC().Format(http.TimeFormat)
	r.svc.Fail(fakeservice.Path(http.MethodPost, "/agent/v1/token"), 2, http.StatusUnauthorized, http.Header{"Date": {past}})
	r.start(t)
	waitFor(t, "the clock warning", func() bool { return strings.Contains(r.logs.String(), "behind") })
}

func TestAnyOtherRefusalOfATokenIsLoggedAndRetried(t *testing.T) {
	r := newRig(t, true)
	r.svc.Fail(fakeservice.Path(http.MethodPost, "/agent/v1/token"), 2, http.StatusServiceUnavailable, nil)
	run := r.svc.Queue(okJob())
	r.start(t)
	waitFor(t, "the job", run.Final)
	if !strings.Contains(r.logs.String(), "refused a token request") {
		t.Errorf("log:\n%s", r.logs.String())
	}
}
