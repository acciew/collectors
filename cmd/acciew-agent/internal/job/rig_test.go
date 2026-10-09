package job_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/cmd/acciew-agent/internal/backoff"
	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/fakeservice"
	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
	"go.acciew.io/collector/cmd/acciew-agent/internal/job"
	"go.acciew.io/collector/cmd/acciew-agent/internal/session"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
	"go.acciew.io/collector/cmd/acciew-agent/internal/testbin"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testbin.Cleanup()
	os.Exit(code)
}

// rig is an enrolled, confirmed agent, a fake service, and a runner for jobs.
type rig struct {
	svc    *fakeservice.Service
	client *client.Client
	sess   *session.Session
	st     *state.State
	runner *job.Runner
	env    map[string]string
	key    ed25519.PrivateKey
	logs   *bytes.Buffer
}

func newRig(t *testing.T, tweak func(*job.Config)) *rig {
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
	if err := state.Create(dir, state.Config{URL: svc.URL(), AgentID: got.AgentID}, key); err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := session.New(c, st)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{svc: svc, client: c, sess: sess, st: st, env: map[string]string{}, key: key, logs: &bytes.Buffer{}}
	cfg := job.Config{
		Client: c, Session: sess,
		CollectorsDir: testbin.Collectors(t),
		SpoolDir:      st.SpoolDir(),
		Secrets: job.SecretsPolicy{
			LookupEnv: func(k string) (string, bool) { v, ok := r.env[k]; return v, ok },
			Dir:       t.TempDir(),
			Forbidden: st.Contains,
			AllowAny:  true,
		},
		Backoff:        backoff.Policy{Min: time.Millisecond, Max: 5 * time.Millisecond},
		UploadPatience: 3 * time.Second,
		HeartbeatEvery: func(*client.Job) time.Duration { return 50 * time.Millisecond },
		Log:            slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	r.runner = job.New(cfg)
	return r
}

// offer queues a job with the service and has the agent take it, as the loop would.
func (r *rig) offer(t *testing.T, j fakeservice.Job) (*client.Job, *fakeservice.Run) {
	t.Helper()
	run := r.svc.Queue(j)
	var got *client.Job
	err := r.sess.Do(context.Background(), func(tok string) error {
		var err error
		got, err = r.client.Jobs(context.Background(), tok)
		return err
	})
	if err != nil || got == nil {
		t.Fatalf("the job was not offered: %v", err)
	}
	return got, run
}

func (r *rig) run(t *testing.T, j fakeservice.Job) (job.Result, *fakeservice.Run) {
	t.Helper()
	offered, run := r.offer(t, j)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return r.runner.Run(ctx, offered), run
}

// collectorFile is the file the agent runs for a collector.
func (r *rig) collectorFile(name string) string {
	return filepath.Join(r.runner.CollectorsDir, "acciew-collector-"+name)
}

func ok(records int) fakeservice.Job {
	return fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":` + strconv.Itoa(records) + `}`}
}

func lastIsCompletion(events []*collectorv1.CollectResponse) *collectorv1.Completion {
	if len(events) == 0 {
		return nil
	}
	return events[len(events)-1].GetCompletion()
}

func spoolFiles(t *testing.T, st *state.State) []string {
	t.Helper()
	entries, err := os.ReadDir(st.SpoolDir())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
