// Package e2e runs the agent as a person would: enrol, have an administrator confirm, run, and
// let it take a job from a fake service and run a real collector, in this process's own time.
// Its tests are the agent's security properties, stated as searches of everything the service
// was ever sent.
package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/cmd/acciew-agent/internal/chunk"
	"go.acciew.io/collector/cmd/acciew-agent/internal/cli"
	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/fakeservice"
	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
	"go.acciew.io/collector/cmd/acciew-agent/internal/session"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
	"go.acciew.io/collector/cmd/acciew-agent/internal/testbin"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testbin.Cleanup()
	os.Exit(code)
}

type buf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *buf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *buf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// site is a customer's host: a state directory, an environment, and an agent that may be running.
type site struct {
	t      *testing.T
	svc    *fakeservice.Service
	dir    string
	env    map[string]string
	out    buf
	errs   buf
	cancel context.CancelFunc
	done   chan int
}

func newSite(t *testing.T, env map[string]string) *site {
	t.Helper()
	svc := fakeservice.New(t)
	svc.Hold = 50 * time.Millisecond
	return &site{t: t, svc: svc, dir: filepath.Join(t.TempDir(), "state"), env: env}
}

func (s *site) cmd(args ...string) int {
	s.t.Helper()
	return cli.Run(context.Background(), args, cli.Env{
		Version: "e2e", Stdout: &s.out, Stderr: &s.errs,
		LookupEnv: func(k string) (string, bool) { v, ok := s.env[k]; return v, ok },
	})
}

// enrol enrols and has the administrator confirm the fingerprint that was printed.
func (s *site) enrol() {
	s.t.Helper()
	s.svc.AddEnrolment("acc_enr_e2e")
	if code := s.cmd("enroll", "--url", s.svc.URL(), "--token", "acc_enr_e2e", "--name", "e2e", "--state-dir", s.dir); code != 0 {
		s.t.Fatalf("enroll: %d\n%s", code, s.errs.String())
	}
	st := s.load()
	agent := s.svc.Agent(st.AgentID)
	if !strings.Contains(s.out.String(), agent.Name) && !strings.Contains(s.out.String(), st.AgentID) {
		s.t.Fatalf("enroll printed no agent id:\n%s", s.out.String())
	}
	s.svc.Confirm(st.AgentID)
}

func (s *site) load() *state.State {
	s.t.Helper()
	st, err := state.Load(s.dir)
	if err != nil {
		s.t.Fatal(err)
	}
	return st
}

func (s *site) start(extra ...string) {
	s.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan int, 1)
	args := append([]string{"run", "--state-dir", s.dir, "--collectors-dir", testbin.Collectors(s.t), "--secrets-dir", privateDir(s.t)}, extra...)
	go func() {
		s.done <- cli.Run(ctx, args, cli.Env{
			Version: "e2e", Stdout: &s.out, Stderr: &s.errs,
			LookupEnv: func(k string) (string, bool) { v, ok := s.env[k]; return v, ok },
		})
	}()
	s.t.Cleanup(func() { s.stop() })
}

func (s *site) stop() int {
	if s.cancel == nil {
		return 0
	}
	s.cancel()
	s.cancel = nil
	select {
	case code := <-s.done:
		return code
	case <-time.After(15 * time.Second):
		s.t.Error("the agent did not stop")
		return -1
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 2000 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// encodings are the ways a value might be written into something that travels: as it is, in
// the two base64 alphabets with and without padding, in hex, and quoted as JSON would.
func encodings(v []byte) [][]byte {
	out := [][]byte{v}
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		out = append(out, []byte(e.EncodeToString(v)))
	}
	out = append(out, []byte(hex.EncodeToString(v)), []byte(strings.ToUpper(hex.EncodeToString(v))))
	return out
}

// absent fails the test for every encoding of v that is found in haystack.
func absent(t *testing.T, what string, haystack []byte, v []byte) {
	t.Helper()
	for _, enc := range encodings(v) {
		if len(enc) > 0 && bytes.Contains(haystack, enc) {
			t.Errorf("%s was sent to the service as %q...", what, truncate(enc))
		}
	}
}

func truncate(b []byte) string {
	if len(b) > 12 {
		return string(b[:12])
	}
	return string(b)
}

func privateKey(t *testing.T, dir string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "agent.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("not an Ed25519 key: %T", parsed)
	}
	return key
}

const secretValue = "kc-client-secret-7d3f9a61-not-for-the-service"

// The central property (ADR-0016): the service never has a source credential, and nothing it
// receives lets it act as the agent. The reference collector is told, as a real one would be,
// to read its credential from the agent's environment.
func TestNothingTheServiceIsEverSentHoldsTheSecretOrThePrivateKey(t *testing.T) {
	s := newSite(t, map[string]string{"E2E_CLIENT_SECRET": secretValue})
	s.enrol()
	key := privateKey(t, s.dir)
	pub := identity.PublicKey(key)

	cfg := `{"url":"https://keycloak.internal.example.test","client_id":"acciew","client_secret":"env:E2E_CLIENT_SECRET"}`
	collectors := testbin.Build(t, "go.acciew.io/collector/sdk/examples/minimal", "minimal")
	_ = collectors
	run := s.svc.Queue(fakeservice.Job{Collector: "minimal", Config: cfg})
	s.start("--secret-env", "E2E_CLIENT_SECRET")
	waitFor(t, "the job to be uploaded", func() bool { return run.Final() || run.Aborted() != "" })
	if run.Aborted() != "" {
		t.Fatalf("the job was given up: %s", run.Aborted())
	}
	events, err := run.Events()
	if err != nil {
		t.Fatal(err)
	}
	if done := events[len(events)-1].GetCompletion(); done == nil || done.GetVerdict() != collectorv1.Verdict_VERDICT_COMPLETE {
		t.Fatalf("the reference collector's collection did not arrive whole: %v", events[len(events)-1])
	}
	s.stop()

	sent := s.svc.Everything()
	// A search that finds nothing proves nothing unless it could have found something.
	if len(s.svc.Requests()) < 4 || !bytes.Contains(sent, []byte("svc-backup")) {
		t.Fatalf("the service was sent %d requests and not the collection (inflated, in the chunks): the search below would be empty", len(s.svc.Requests()))
	}
	if !bytes.Contains(sent, []byte(base64.StdEncoding.EncodeToString(pub))) {
		t.Fatal("the public key is not in what was sent, though it was enrolled: the search cannot see base64")
	}

	absent(t, "the source credential", sent, []byte(secretValue))
	absent(t, "the private key", sent, key)
	absent(t, "the private key's seed", sent, key.Seed())
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	absent(t, "the private key's PKCS#8 form", sent, der)
	pemFile, _ := os.ReadFile(filepath.Join(s.dir, "agent.key"))
	if bytes.Contains(sent, pemFile) || bytes.Contains(sent, []byte("PRIVATE KEY")) {
		t.Error("the key file was sent")
	}
	// Nor does the agent say either aloud.
	for name, text := range map[string]string{"stdout": s.out.String(), "stderr": s.errs.String()} {
		if strings.Contains(text, secretValue) || strings.Contains(text, base64.StdEncoding.EncodeToString(key.Seed())) {
			t.Errorf("the agent printed a secret on %s", name)
		}
	}
}

// The same search, with a collector that reads its credential through its file and does not give
// it away: the credential was really there to be found. And the search is not blind: given a
// request that does hold the credential, inside a compressed chunk, it finds it.
func TestTheCollectorCanReadItsCredentialAndTheSearchCanFindOneInAChunk(t *testing.T) {
	s := newSite(t, map[string]string{"E2E_CLIENT_SECRET": secretValue})
	s.enrol()
	honest := s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":2,"secret_file":"env:E2E_CLIENT_SECRET"}`})
	s.start("--secret-env", "E2E_CLIENT_SECRET")
	waitFor(t, "the honest job", honest.Final)
	events, _ := honest.Events()
	var read bool
	for _, e := range events {
		if d := e.GetDiagnostic(); d.GetCode() == "test.secret_read" && strings.Contains(d.GetMessage(), "read 45 bytes") {
			read = true
		}
	}
	if !read {
		t.Fatal("the collector did not read the credential through its file: nothing was proved")
	}
	s.stop()
	if bytes.Contains(s.svc.Everything(), []byte(secretValue)) {
		t.Error("an honest collector's credential reached the service")
	}

	// An agent that did not check what it sends, played by hand, with the same service.
	st := s.load()
	c, err := client.New(st.URL, "e2e")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := session.New(c, st)
	if err != nil {
		t.Fatal(err)
	}
	s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{}`})
	var offered *client.Job
	if err := sess.Do(context.Background(), func(tok string) (err error) { offered, err = c.Jobs(context.Background(), tok); return err }); err != nil || offered == nil {
		t.Fatalf("no job: %v", err)
	}
	leak, _ := proto.Marshal(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Diagnostic{Diagnostic: &collectorv1.Diagnostic{
		Severity: collectorv1.Severity_SEVERITY_INFO, Code: "test.leak", Message: "token " + secretValue,
	}}})
	frame, _ := chunk.Frame(leak)
	body, _ := chunk.Seal(frame, chunk.MaxChunk)
	if bytes.Contains(body[0], []byte(secretValue)) {
		t.Fatal("the chunk is not compressed: the control would prove nothing about compression")
	}
	err = sess.Do(context.Background(), func(tok string) error {
		_, err := c.PutChunk(context.Background(), tok, offered.Stream, 0, body[0], false)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(s.svc.Everything(), []byte(secretValue)) {
		t.Error("a credential inside a compressed chunk was not found by the search: the search is blind")
	}
}

// A collector that writes the credential into an event gets the job given up: nothing of it is
// uploaded, in any form, and the agent says why without the value.
func TestACollectorThatEchoesTheCredentialGetsTheJobGivenUpThroughTheCommandLine(t *testing.T) {
	s := newSite(t, map[string]string{"E2E_CLIENT_SECRET": secretValue})
	s.enrol()
	run := s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":3,"secret_file":"env:E2E_CLIENT_SECRET","leak_as":"b64embedded"}`})
	s.start("--secret-env", "E2E_CLIENT_SECRET")
	waitFor(t, "the abort", func() bool { return run.Aborted() != "" })
	s.stop()
	if run.Final() || strings.Contains(run.Aborted(), secretValue) || !strings.Contains(run.Aborted(), "echoed a credential") {
		t.Errorf("final %v, aborted %q", run.Final(), run.Aborted())
	}
	sent := s.svc.Everything()
	absent(t, "the credential", sent, []byte(secretValue))
	absent(t, "the credential's base64 in text", sent, []byte("user:"+secretValue+":x"))
	for name, text := range map[string]string{"stdout": s.out.String(), "stderr": s.errs.String()} {
		if strings.Contains(text, secretValue) {
			t.Errorf("the agent printed the credential on %s", name)
		}
	}
}

// Rotation by a second process while the agent runs: the agent's token dies with the old key,
// and it finds the new one on disk.
func TestARunningAgentSurvivesItsKeyBeingRotatedFromAnotherTerminal(t *testing.T) {
	s := newSite(t, nil)
	s.enrol()
	first := s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1}`})
	s.start()
	waitFor(t, "the first job", first.Final)
	old := privateKey(t, s.dir)

	if code := s.cmd("rotate", "--state-dir", s.dir); code != 0 {
		t.Fatalf("rotate: %d\n%s", code, s.errs.String())
	}
	if privateKey(t, s.dir).Equal(old) {
		t.Fatal("the key did not change")
	}
	second := s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1}`})
	waitFor(t, "a job after the rotation", second.Final)
	if code := s.stop(); code != 0 {
		t.Errorf("the agent exited %d\n%s", code, s.errs.String())
	}
	// And nothing the service was sent along the way carried either private key.
	sent := s.svc.Everything()
	absent(t, "the old private key", sent, old.Seed())
	absent(t, "the new private key", sent, privateKey(t, s.dir).Seed())
}

func TestOnlyTheOwnerCanReadWhatTheAgentKeepsAndTheSpoolIsGoneAfterwards(t *testing.T) {
	s := newSite(t, nil)
	s.enrol()
	run := s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":3}`})
	s.start()
	waitFor(t, "the job", run.Final)
	s.stop()
	for _, name := range []string{"agent.key", "agent.json"} {
		info, err := os.Stat(filepath.Join(s.dir, name))
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s: %v %v", name, info, err)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(s.dir, "spool")); len(entries) != 0 {
		t.Errorf("spool: %v", entries)
	}
}

// ---- the other properties, through the same entry point a person uses

func TestALostAnswerToTheLastChunkIsRetriedAndTheStreamIsStillOneCollection(t *testing.T) {
	s := newSite(t, nil)
	s.enrol()
	testbin.Build(t, "go.acciew.io/collector/sdk/examples/minimal", "minimal")
	s.svc.DropAnswers(fakeservice.Chunk(0), 2)
	run := s.svc.Queue(fakeservice.Job{Collector: "minimal", Config: `{}`})
	s.start()
	waitFor(t, "the chunk to be sent three times", func() bool { return s.svc.Hits("PUT /agent/v1/streams/{stream}/chunks/{n}") >= 3 })
	s.stop()
	if puts := s.svc.Hits("PUT /agent/v1/streams/{stream}/chunks/{n}"); puts != 3 || run.Chunks() != 1 || !run.Final() {
		t.Errorf("%d PUTs for %d chunks: want the one chunk sent three times (two answers lost)", puts, run.Chunks())
	}
	events, err := run.Events()
	if err != nil || events[len(events)-1].GetCompletion() == nil {
		t.Errorf("the stream: %v, %v", len(events), err)
	}
}

func TestTheServiceMovingTheJobStopsTheCollectorProcess(t *testing.T) {
	s := newSite(t, nil)
	s.svc.HeartbeatSeconds = 1
	s.enrol()
	pidFile := filepath.Join(t.TempDir(), "pid")
	run := s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"slow","records":500,"delay_ms":40,"pid_file":"` + pidFile + `"}`})
	s.start("--verbose")
	var pid int
	waitFor(t, "the collector to start", func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		_, err = fmtSscan(string(b), &pid)
		return err == nil
	})
	start := time.Now()
	run.LoseLease()
	waitFor(t, "the collector to be stopped", func() bool { return syscallKill(pid) != nil })
	t.Logf("collector stopped %v after the lease was lost", time.Since(start))
	if time.Since(start) > 5*time.Second {
		t.Errorf("the collector ran on for %v after the lease was lost; it would have finished by itself in 20s", time.Since(start))
	}
	if run.Final() || run.Aborted() != "" {
		t.Errorf("final %v aborted %q", run.Final(), run.Aborted())
	}
	// And the agent goes on: the next job is taken.
	next := s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1}`})
	waitFor(t, "the next job", next.Final)
}

func TestACollectorThatBreaksTheContractGetsTheJobAbortedAndNothingOfItUploadedAsFine(t *testing.T) {
	s := newSite(t, nil)
	s.enrol()
	run := s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"violate","records":5}`})
	s.start()
	waitFor(t, "the abort", func() bool { return run.Aborted() != "" })
	if !strings.Contains(run.Aborted(), "broke the contract") || run.Final() {
		t.Errorf("aborted %q, final %v", run.Aborted(), run.Final())
	}
	s.stop()
	if entries, _ := os.ReadDir(filepath.Join(s.dir, "spool")); len(entries) != 0 {
		t.Errorf("spool: %v", entries)
	}
}

func fmtSscan(s string, pid *int) (int, error) { return fmt.Sscan(s, pid) }

func syscallKill(pid int) error { return syscall.Kill(pid, 0) }

// ---- resuming

func identityIDs(events []*collectorv1.CollectResponse) (ids []string) {
	for _, e := range events {
		if e.GetNode().GetKey().GetType() == collectorv1.NodeType_NODE_TYPE_IDENTITY {
			ids = append(ids, e.GetNode().GetKey().GetId())
		}
	}
	return ids
}

// The service hands a job back with the cursor of the last checkpoint the earlier stream
// carried. The reference collector resumes from it, and says, as the contract requires, that its
// stream is only the rest. The agent sends that as it is.
func TestTheReferenceCollectorResumesFromTheCursorAndSaysItsStreamIsOnlyTheRest(t *testing.T) {
	s := newSite(t, nil)
	s.enrol()
	testbin.Build(t, "go.acciew.io/collector/sdk/examples/minimal", "minimal")
	cursor := `{"token": "` + base64.StdEncoding.EncodeToString([]byte("5")) + `"}`
	run := s.svc.Queue(fakeservice.Job{Collector: "minimal", Config: `{}`, ResumeCursor: cursor})
	s.start()
	waitFor(t, "the job", func() bool { return run.Final() || run.Aborted() != "" })
	if run.Aborted() != "" {
		t.Fatalf("the job was given up: %s", run.Aborted())
	}
	events, err := run.Events()
	if err != nil {
		t.Fatal(err)
	}
	done := events[len(events)-1].GetCompletion()
	if done == nil || done.GetVerdict() != collectorv1.Verdict_VERDICT_INCOMPLETE || done.GetCause() != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM {
		t.Fatalf("a resumed stream should end INCOMPLETE with PARTIAL_STREAM: %v", events[len(events)-1])
	}
	if got := done.GetError().GetMessage(); !strings.Contains(got, "resumed after record 5") {
		t.Errorf("the completion's own words were changed: %q", got)
	}
	if run.EndedEarly() {
		t.Error("a stream with its completion ended early")
	}
}

// A collection too big for the spool is cut at a checkpoint and sent as a stream that ends early;
// the service offers the job again with the cursor, again and again until the collector finishes.
// Each stream is on its own id, with chunks numbered from 0, and between them they hold every
// identity once.
func TestACollectionTooBigForTheSpoolArrivesAsStreamsThatTogetherAreTheWhole(t *testing.T) {
	s := newSite(t, nil)
	s.enrol()
	// 25 identities of about 100 KB each against a spool of 1 MiB: three streams.
	run := s.svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":25,"payload":100000}`})
	s.start("--spool-mib", "1")
	waitFor(t, "the run to finish", func() bool { return chanClosed(run.Done()) })
	if run.Failed() != "" || run.Aborted() != "" {
		t.Fatalf("failed %q, aborted %q", run.Failed(), run.Aborted())
	}
	if run.Attempts() != 3 {
		t.Fatalf("%d attempts, want 3", run.Attempts())
	}
	seen := map[string]int{}
	for i := range run.Attempts() {
		events, err := run.StreamEvents(i)
		if err != nil {
			t.Fatal(err)
		}
		last := events[len(events)-1]
		if i < run.Attempts()-1 && (last.GetCheckpoint() == nil || events[len(events)-1].GetCompletion() != nil) {
			t.Errorf("stream %d should end early, at a checkpoint: %T", i, last.GetEvent())
		}
		if i == run.Attempts()-1 && last.GetCompletion().GetCause() != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM {
			t.Errorf("the last stream: %T", last.GetEvent())
		}
		for _, id := range identityIDs(events) {
			seen[id]++
		}
	}
	if len(seen) != 25 {
		t.Errorf("%d identities between the streams, want 25", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("%s arrived %d times", id, n)
		}
	}
}

func chanClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
