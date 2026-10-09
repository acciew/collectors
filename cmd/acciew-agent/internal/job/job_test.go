package job_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/cmd/acciew-agent/internal/backoff"
	"go.acciew.io/collector/cmd/acciew-agent/internal/chunk"
	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/fakeservice"
	"go.acciew.io/collector/cmd/acciew-agent/internal/job"
	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
	"go.acciew.io/collector/cmd/acciew-agent/internal/testbin"
)

func TestAWholeCollectionIsUploadedAndEndsWithItsCompletion(t *testing.T) {
	r := newRig(t, nil)
	res, run := r.run(t, ok(5))
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if !run.Final() || run.Aborted() != "" {
		t.Fatalf("final %v, aborted %q", run.Final(), run.Aborted())
	}
	events, err := run.Events()
	if err != nil {
		t.Fatalf("the service cannot read the stream: %v", err)
	}
	done := lastIsCompletion(events)
	if done == nil || done.GetVerdict() != collectorv1.Verdict_VERDICT_COMPLETE {
		t.Fatalf("last event %v", events[len(events)-1])
	}
	if done.GetCounts().GetIdentities() != 5 || done.GetCounts().GetScopes() != 1 {
		t.Errorf("counts %v", done.GetCounts())
	}
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("the spool was left behind: %v", files)
	}
}

// Chunks are cut by size. A collection of random bytes cannot be compressed, so a small limit
// makes many chunks, and the service must still be able to read them as one stream.
func TestALargeCollectionGoesUpAsManyChunksInOrderAndTheLastIsFinal(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.RawTarget = 64 << 10 })
	big := fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":40,"payload":20000}`}
	res, run := r.run(t, big)
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if run.Chunks() < 5 || res.Chunks != run.Chunks() {
		t.Errorf("%d chunks stored, %d reported", run.Chunks(), res.Chunks)
	}
	if finals := run.FinalChunks(); len(finals) != 1 || finals[0] != run.Chunks()-1 {
		t.Errorf("chunks marked final: %v of %d", finals, run.Chunks())
	}
	events, err := run.Events()
	if err != nil {
		t.Fatal(err)
	}
	done := lastIsCompletion(events)
	if done == nil || done.GetCounts().GetIdentities() != 40 {
		t.Fatalf("completion %v", done)
	}
	var identities uint64
	for _, e := range events {
		if e.GetNode().GetKey().GetType() == collectorv1.NodeType_NODE_TYPE_IDENTITY {
			identities++
		}
	}
	if identities != 40 {
		t.Errorf("%d identities arrived in the chunks, want 40", identities)
	}
}

// The agent hashes the collector's file just before it starts it, and says so on every chunk with
// the version the collector gave in its handshake: the service has nothing else to go by.
func TestEveryChunkSaysWhichCollectorFileWasRunAndWhatItCalledItself(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.RawTarget = 64 << 10 })
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":40,"payload":20000}`})
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	want := fakeservice.Report{SHA256: fileDigest(t, r.collectorFile("testcollector")), Version: "0.0.1"}
	reports := run.Reports()
	if run.Chunks() < 5 || len(reports) != run.Chunks() {
		t.Fatalf("%d chunks stored and %d reports", run.Chunks(), len(reports))
	}
	for n, got := range reports {
		if got != want {
			t.Errorf("chunk %d said %+v, want %+v", n, got, want)
		}
	}
}

// The file is read for each job, so a collector that was replaced between two is the one reported.
func TestTheDigestIsOfTheFileThatWasStartedForThisJobAndNotOfAnotherCollector(t *testing.T) {
	r := newRig(t, nil)
	_, first := r.run(t, ok(2))
	_, second := r.run(t, fakeservice.Job{Collector: "minimal"})
	a, b := first.Reports(), second.Reports()
	if len(a) == 0 || len(b) == 0 {
		t.Fatalf("%d and %d reports", len(a), len(b))
	}
	if a[0].SHA256 != fileDigest(t, r.collectorFile("testcollector")) || b[0].SHA256 != fileDigest(t, r.collectorFile("minimal")) {
		t.Errorf("digests %q and %q are not those of the two files", a[0].SHA256, b[0].SHA256)
	}
	if a[0].SHA256 == b[0].SHA256 {
		t.Error("two different collectors were reported as the same file")
	}
}

// The chunk that ends a stream early is a chunk like the others, and so is every one of the stream
// that picks the job up again.
func TestTheChunkThatEndsAStreamEarlyAndTheStreamThatResumesSayWhichFileRanToo(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.RawTarget = 48 << 10
		c.StreamChunks = 3
	})
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":14,"payload":20000,"checkpoint_every":2}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("outcome %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	r.finish(t, run)
	want := fakeservice.Report{SHA256: fileDigest(t, r.collectorFile("testcollector")), Version: "0.0.1"}
	if run.Attempts() < 2 {
		t.Fatalf("%d attempts", run.Attempts())
	}
	for i := range run.Attempts() {
		reports := run.StreamReports(i)
		if len(reports) == 0 {
			t.Errorf("stream %d has no chunks", i)
		}
		for n, got := range reports {
			if got != want {
				t.Errorf("stream %d chunk %d said %+v, want %+v", i, n, got, want)
			}
		}
	}
}

// A file the agent can run and cannot read has no digest to give. The job goes on, and the service is
// told nothing of the file: it is not told something untrue, and a label is not worth a collection.
func TestACollectorTheAgentCanRunButNotReadIsRunAndReportedWithoutADigest(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(testbin.Collectors(t), "acciew-collector-testcollector"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "acciew-collector-testcollector"), src, 0o111); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *job.Config) { c.CollectorsDir = dir })
	res, run := r.run(t, ok(3))
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	for n, got := range run.Reports() {
		if got.SHA256 != "" || got.Version != "0.0.1" {
			t.Errorf("chunk %d said %+v, want a version and no digest", n, got)
		}
	}
	if !strings.Contains(r.logs.String(), "could not read the collector") {
		t.Errorf("the agent's log does not say the file could not be read:\n%s", r.logs)
	}
}

func TestEveryChunkIsWithinTheLimitTheJobNamed(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.RawTarget = 1 << 20 })
	r.svc.ChunkBytes = 100 << 10
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":30,"payload":20000}`})
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	for n := range run.Chunks() {
		if got := len(run.ChunkBytes(n)); got > 100<<10 {
			t.Errorf("chunk %d is %d bytes, over the 102400 the job allowed", n, got)
		}
	}
}

// The answer to a chunk was lost on the way. The chunk is sent again, byte for byte, and
// the service says duplicate; the stream is not doubled and nothing is abandoned.
func TestAChunkWhoseAnswerWasLostIsSentAgainAndAcceptedAsADuplicate(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.RawTarget = 64 << 10 })
	r.svc.DropAnswers(fakeservice.Chunk(0), 1)
	r.svc.DropAnswers(fakeservice.Chunk(2), 2)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":40,"payload":20000}`})
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if puts := r.svc.Hits("PUT /agent/v1/streams/{stream}/chunks/{n}"); puts != run.Chunks()+3 {
		t.Errorf("%d PUTs for %d chunks: expected exactly three repeats", puts, run.Chunks())
	}
	events, err := run.Events()
	if err != nil {
		t.Fatal(err)
	}
	if done := lastIsCompletion(events); done == nil || done.GetCounts().GetIdentities() != 40 {
		t.Errorf("the stream is not the collection: %v", done)
	}
}

func TestATransientFailureIsRetriedAndAThrottleIsWaitedOut(t *testing.T) {
	r := newRig(t, nil)
	r.svc.Fail(fakeservice.Chunk(0), 3, http.StatusServiceUnavailable, nil)
	r.svc.Fail(fakeservice.Chunk(0), 1, http.StatusTooManyRequests, http.Header{"Retry-After": {"1"}})
	start := time.Now()
	res, run := r.run(t, ok(3))
	if res.Outcome != job.Uploaded || !run.Final() {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if time.Since(start) < time.Second {
		t.Errorf("a Retry-After of one second was not honoured (%v)", time.Since(start))
	}
}

func TestAChunkThatCannotBeDeliveredForTooLongEndsTheJobAndTheCollectorsWorkIsDropped(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.UploadPatience = 200 * time.Millisecond })
	r.svc.Fail(fakeservice.Chunk(0), -1, http.StatusBadGateway, nil)
	res, run := r.run(t, ok(3))
	if res.Outcome != job.Aborted || !strings.Contains(res.Reason, "could not be delivered") {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if run.Final() || run.Chunks() != 0 {
		t.Error("something was stored")
	}
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("the spool was left behind: %v", files)
	}
}

func TestAnAbortTheServiceRefusesAsAlreadyOverIsALostLease(t *testing.T) {
	r := newRig(t, nil)
	// The service ends the run (lease moved) at the moment the agent decides to give up.
	offered, run := r.offer(t, fakeservice.Job{Collector: "no-such-collector", Config: `{}`})
	run.LoseLease()
	res := r.runner.Run(context.Background(), offered)
	if res.Outcome != job.LeaseLost {
		t.Errorf("outcome %v: %s", res.Outcome, res.Reason)
	}
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func waitForPID(t *testing.T, file string) int {
	t.Helper()
	for range 250 {
		if b, err := os.ReadFile(file); err == nil {
			if pid, err := strconv.Atoi(string(b)); err == nil {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the collector never started")
	return 0
}

func waitDead(t *testing.T, pid int) {
	t.Helper()
	for range 250 {
		if !alive(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("process %d is still running", pid)
}

func slowJob(pidFile string) fakeservice.Job {
	return fakeservice.Job{Collector: "testcollector", Config: `{"mode":"slow","records":500,"delay_ms":40,"pid_file":"` + pidFile + `"}`}
}

// The job's heartbeat is what holds the lease while a collector works.
func TestTheLeaseIsHeldWithHeartbeatsWhileTheCollectorWorks(t *testing.T) {
	r := newRig(t, nil)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"slow","records":15,"delay_ms":40}`})
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if n := run.Heartbeats(); n < 5 {
		t.Errorf("%d heartbeats in a job that took over half a second at one every 50ms", n)
	}
}

func TestWhenTheServiceMovesTheJobTheCollectorIsStoppedAtOnceAndNothingMoreIsSent(t *testing.T) {
	r := newRig(t, nil)
	pidFile := filepath.Join(t.TempDir(), "pid")
	offered, run := r.offer(t, slowJob(pidFile))
	done := make(chan job.Result, 1)
	go func() { done <- r.runner.Run(context.Background(), offered) }()

	pid := waitForPID(t, pidFile)
	if !alive(pid) {
		t.Fatal("the collector is not running")
	}
	run.LoseLease()
	select {
	case res := <-done:
		if res.Outcome != job.LeaseLost {
			t.Errorf("outcome %v: %s", res.Outcome, res.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the job is still running after the lease was lost")
	}
	waitDead(t, pid)
	if run.Final() || run.Aborted() != "" {
		t.Errorf("final %v, aborted %q: a job that is no longer ours is neither finished nor given up", run.Final(), run.Aborted())
	}
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("the spool was left behind: %v", files)
	}
}

// The same, found by a chunk and not a heartbeat: heartbeats are slow in the field.
func TestALeaseLostAnswerToAChunkStopsTheCollectorToo(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.RawTarget = 1
		c.HeartbeatEvery = func(*client.Job) time.Duration { return time.Hour }
	})
	pidFile := filepath.Join(t.TempDir(), "pid")
	offered, run := r.offer(t, slowJob(pidFile))
	done := make(chan job.Result, 1)
	go func() { done <- r.runner.Run(context.Background(), offered) }()
	pid := waitForPID(t, pidFile)
	for run.Chunks() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	run.LoseLease()
	select {
	case res := <-done:
		if res.Outcome != job.LeaseLost {
			t.Errorf("outcome %v: %s", res.Outcome, res.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the job is still running")
	}
	waitDead(t, pid)
}

func TestAskedToStopTheAgentStopsTheCollectorDeletesTheSpoolAndGivesNothingUp(t *testing.T) {
	r := newRig(t, nil)
	pidFile := filepath.Join(t.TempDir(), "pid")
	offered, run := r.offer(t, slowJob(pidFile))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan job.Result, 1)
	go func() { done <- r.runner.Run(ctx, offered) }()
	pid := waitForPID(t, pidFile)
	cancel()
	select {
	case res := <-done:
		if res.Outcome != job.Cancelled {
			t.Errorf("outcome %v: %s", res.Outcome, res.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the job is still running")
	}
	waitDead(t, pid)
	// Shutting down is not giving up: the lease lapses and the service offers the job again.
	if run.Aborted() != "" {
		t.Errorf("the job was aborted on shutdown: %q", run.Aborted())
	}
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("the spool was left behind: %v", files)
	}
}

func TestAnAgentTheServiceRevokedMidJobStopsWithoutBeingAbleToSayWhy(t *testing.T) {
	r := newRig(t, nil)
	pidFile := filepath.Join(t.TempDir(), "pid")
	offered, run := r.offer(t, slowJob(pidFile))
	done := make(chan job.Result, 1)
	go func() { done <- r.runner.Run(context.Background(), offered) }()
	pid := waitForPID(t, pidFile)
	r.svc.Revoke(r.st.AgentID)
	r.svc.ForgetTokens()
	select {
	case res := <-done:
		if res.Outcome != job.Failed || !strings.Contains(res.Reason, "no longer accepts") {
			t.Errorf("outcome %v: %s", res.Outcome, res.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the job is still running after the agent was revoked")
	}
	waitDead(t, pid)
	if run.Final() {
		t.Error("a revoked agent finished a job")
	}
}

// aborted runs a job that cannot be done and returns what the service was told.
func aborted(t *testing.T, r *rig, j fakeservice.Job) (job.Result, string) {
	t.Helper()
	res, run := r.run(t, j)
	if res.Outcome != job.Aborted {
		t.Fatalf("outcome %v (%s), want aborted", res.Outcome, res.Reason)
	}
	if run.Final() || run.Chunks() != 0 {
		t.Errorf("a job that was given up stored %d chunks (final %v)", run.Chunks(), run.Final())
	}
	if got := run.Aborted(); got == "" {
		t.Fatal("the service was not told why")
	} else {
		return res, got
	}
	return res, ""
}

func TestAJobThatNamesAPathOrABadNameIsGivenUpNotRun(t *testing.T) {
	for _, name := range []string{"../../bin/sh", "/bin/sh", "Upper", "a b", "x;y", strings.Repeat("a", 65), "-lead"} {
		r := newRig(t, nil)
		_, why := aborted(t, r, fakeservice.Job{Collector: name, Config: `{}`})
		if !strings.Contains(why, "not the name of a collector") {
			t.Errorf("%q: %q", name, why)
		}
	}
}

func TestACollectorThatIsNotInstalledIsSaidSo(t *testing.T) {
	r := newRig(t, nil)
	_, why := aborted(t, r, fakeservice.Job{Collector: "oracle", Config: `{}`})
	if !strings.Contains(why, `no collector called "oracle" is installed`) {
		t.Errorf("reason %q", why)
	}
}

func TestAFileInTheCollectorsDirectoryThatIsNotExecutableIsNotACollector(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "acciew-collector-plain"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *job.Config) { c.CollectorsDir = dir })
	_, why := aborted(t, r, fakeservice.Job{Collector: "plain", Config: `{}`})
	if !strings.Contains(why, "is installed") {
		t.Errorf("reason %q", why)
	}
}

func TestAnExecutableThatIsNotACollectorIsGivenUpWithAReason(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "acciew-collector-fake"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *job.Config) { c.CollectorsDir = dir })
	_, why := aborted(t, r, fakeservice.Job{Collector: "fake", Config: `{}`})
	if !strings.Contains(why, `"fake" could not be started`) {
		t.Errorf("reason %q", why)
	}
}

func TestAReferenceThatDoesNotResolveIsNamedAndTheJobIsGivenUp(t *testing.T) {
	r := newRig(t, nil)
	_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","token":"env:KC_SECRET"}`})
	if !strings.Contains(why, "KC_SECRET") || !strings.Contains(why, "empty or unset") {
		t.Errorf("reason %q", why)
	}
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("spool: %v", files)
	}
}

// A collector that puts the credential it was handed into its complaint must not get it
// sent to the service in the reason.
func TestWhatTheCollectorSaysBackIsScrubbedOfTheSecretBeforeItLeaves(t *testing.T) {
	r := newRig(t, nil)
	r.env["KC_SECRET"] = "the-actual-secret-value-9f3a"
	res, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"issue":"echo","secret_file":"env:KC_SECRET"}`})
	_ = res
	if strings.Contains(why, "the-actual-secret-value-9f3a") {
		t.Fatalf("the secret reached the service in the reason: %q", why)
	}
	if !strings.Contains(why, "rejected the configuration") {
		t.Errorf("reason %q", why)
	}
	if strings.Contains(why, "acciew-run-") || strings.Contains(why, "credential") {
		t.Errorf("the collector's sentence reached the reason: %q", why)
	}
	// The sentence is in the agent's own log, with the value taken out.
	logged := r.logs.String()
	if strings.Contains(logged, "the-actual-secret-value-9f3a") || !strings.Contains(logged, "[redacted]") {
		t.Errorf("the agent's log:\n%s", logged)
	}
}

func TestAConfigurationThePluginRefusesIsGivenUpWithItsIssue(t *testing.T) {
	r := newRig(t, nil)
	_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"issue":"the realm is missing"}`})
	if !strings.Contains(why, "/token") || !strings.Contains(why, "test.issue") {
		t.Errorf("reason %q", why)
	}
	// What the collector wrote in a sentence is not copied into a reason: it can hold anything.
	if strings.Contains(why, "the realm is missing") {
		t.Errorf("the collector's sentence reached the reason: %q", why)
	}
}

func TestAJobWithABudgetIsGivenUpUntilTheProtocolSaysWhatOneIs(t *testing.T) {
	r := newRig(t, nil)
	_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{}`, Budget: `{"max_records": 100}`})
	if !strings.Contains(why, "budget") {
		t.Errorf("reason %q", why)
	}
}

// A cursor that cannot be read must not become a fresh start: the service would take the
// stream for a resume, and the collection would be wrong without anybody knowing.
func TestAResumeCursorThatCannotBeReadIsGivenUpNotIgnored(t *testing.T) {
	for _, cursor := range []string{`"MQ=="`, `{"token":"***"}`, `{"token":""}`, `{"cursor":"MQ=="}`} {
		r := newRig(t, nil)
		_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":2}`, ResumeCursor: cursor})
		if !strings.Contains(why, "resume cursor cannot be used") {
			t.Errorf("%s: reason %q", cursor, why)
		}
	}
}

// The job's cursor is the collector's CollectRequest.resume_from, and what the collector then
// says of its stream is not the agent's to change.
func TestAResumeCursorIsHandedToTheCollectorAndItsCompletionIsSentAsItIs(t *testing.T) {
	r := newRig(t, nil)
	cursor := `{"token":"` + base64.StdEncoding.EncodeToString([]byte("3")) + `"}`
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":5}`, ResumeCursor: cursor})
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	events, err := run.Events()
	if err != nil {
		t.Fatal(err)
	}
	var resumed bool
	identities := 0
	for _, e := range events {
		if e.GetDiagnostic().GetCode() == "test.resumed" && strings.Contains(e.GetDiagnostic().GetMessage(), "item 3") {
			resumed = true
		}
		if e.GetNode().GetKey().GetType() == collectorv1.NodeType_NODE_TYPE_IDENTITY {
			identities++
		}
	}
	if !resumed {
		t.Error("the collector was not given the cursor")
	}
	// Six items (the scope and five identities), three already sent: three identities remain.
	if identities != 3 {
		t.Errorf("%d identities in the resumed stream, want 3", identities)
	}
	done := lastIsCompletion(events)
	if done == nil || done.GetVerdict() != collectorv1.Verdict_VERDICT_INCOMPLETE || done.GetCause() != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM {
		t.Errorf("a resumed stream ends INCOMPLETE with PARTIAL_STREAM, as its collector said: %v", done)
	}
	if res.EndedEarly {
		t.Error("a stream with its completion did not end early")
	}
}

// ---- what the collector sends

func TestAnEventTheContractForbidsGivesUpTheJobAndIsNeverUploadedAsIfFine(t *testing.T) {
	r := newRig(t, nil)
	res, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"violate","records":5}`})
	if !strings.Contains(why, "broke the contract") || !strings.Contains(why, "testcollector") {
		t.Errorf("reason %q", why)
	}
	if res.Chunks != 0 {
		t.Errorf("%d chunks were sent", res.Chunks)
	}
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("the spool was left behind: %v", files)
	}
}

// With chunks small enough to leave before the bad event arrives, nothing may carry the
// stream's end: the service reads a stream that has no last chunk as one that is not whole.
func TestAViolationAfterEarlierChunksWentUpStillNeverSendsALastChunk(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.RawTarget = 1 })
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"violate","records":5}`})
	if res.Outcome != job.Aborted || run.Final() || run.Aborted() == "" {
		t.Errorf("outcome %v, final %v, aborted %q", res.Outcome, run.Final(), run.Aborted())
	}
}

// The service refuses a chunk with a checkpoint that cannot be resumed from; the agent says so first,
// naming the rule, and does not send the chunk three times to be told.
func TestACheckpointWithNoCursorOrAnImpossibleOneIsAViolation(t *testing.T) {
	for mode, rule := range map[string]string{"bare_checkpoint": "checkpoint-cursor-required", "huge_checkpoint": "checkpoint-cursor-too-large"} {
		r := newRig(t, nil)
		_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"` + mode + `","records":5}`})
		if !strings.Contains(why, rule) {
			t.Errorf("%s: reason %q", mode, why)
		}
	}
}

func TestACompletionWhoseCountsDisagreeWithWhatWasSentIsAViolation(t *testing.T) {
	r := newRig(t, nil)
	_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"miscount","records":3}`})
	if !strings.Contains(why, "counts-must-match-what-was-sent") {
		t.Errorf("reason %q", why)
	}
}

// A clean close is not success. What arrived is sent, and the service records a collection
// that is not whole.
func TestAStreamThatEndsWithoutACompletionIsSentAsItIsForTheServiceToRecordNotWhole(t *testing.T) {
	r := newRig(t, nil)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"no_completion","records":4}`})
	if res.Outcome != job.Uploaded || !run.Final() || !res.EndedEarly || !run.EndedEarly() {
		t.Fatalf("outcome %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	events, err := run.Events()
	if err != nil || lastIsCompletion(events) != nil || len(events) == 0 {
		t.Errorf("events %d, completion %v, err %v", len(events), lastIsCompletion(events), err)
	}
}

func TestAnIncompleteVerdictIsTheCollectorsToGiveAndTheServicesToRead(t *testing.T) {
	r := newRig(t, nil)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"incomplete","records":2}`})
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	events, _ := run.Events()
	if done := lastIsCompletion(events); done == nil || done.GetVerdict() != collectorv1.Verdict_VERDICT_INCOMPLETE {
		t.Errorf("last event %v", events[len(events)-1])
	}
}

// next takes the job the service offers again, as the loop would.
func (r *rig) next(t *testing.T) *client.Job {
	t.Helper()
	for range 200 {
		var got *client.Job
		err := r.sess.Do(context.Background(), func(tok string) error {
			var err error
			got, err = r.client.Jobs(context.Background(), tok)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			return got
		}
	}
	t.Fatal("the job was not offered again")
	return nil
}

func identitiesIn(events []*collectorv1.CollectResponse) (names []string) {
	for _, e := range events {
		if e.GetNode().GetKey().GetType() == collectorv1.NodeType_NODE_TYPE_IDENTITY {
			names = append(names, e.GetNode().GetKey().GetId())
		}
	}
	return names
}

// At the cap the collector is stopped and the stream ends at its last checkpoint, with no
// Completion: the service takes it for a stream that ended early and offers the job again,
// resumed from that checkpoint. The second stream is the rest, and the two together are the
// collection.
func TestAtTheSpoolCapTheStreamEndsAtItsLastCheckpointAndTheResumedJobFinishesTheRest(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.SpoolLimit = 40 << 10
		c.RawTarget = 1 << 30 // nothing leaves until the end, so the spool fills
	})
	pidFile := filepath.Join(t.TempDir(), "pid")
	cfg := `{"mode":"ok","records":12,"payload":4000,"delay_ms":5,"checkpoint_every":3,"pid_file":"` + pidFile + `"}`
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: cfg})
	if res.Outcome != job.Uploaded || !res.EndedEarly || !run.Final() {
		t.Fatalf("outcome %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	first, err := run.Events()
	if err != nil {
		t.Fatal(err)
	}
	if lastIsCompletion(first) != nil {
		t.Error("a stream cut at the cap carries a completion")
	}
	if first[len(first)-1].GetCheckpoint() == nil {
		t.Errorf("the stream does not end at a checkpoint: %T", first[len(first)-1].GetEvent())
	}
	if n := len(identitiesIn(first)); n == 0 || n >= 12 {
		t.Errorf("%d identities: the cap should have cut a collection of 12 short", n)
	}
	waitDead(t, waitForPID(t, pidFile))
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("the spool was left behind: %v", files)
	}

	// The job comes back with a cursor, on a stream of its own, and finishes.
	again := r.next(t)
	cur, err := again.Resume()
	if err != nil || len(cur) == 0 || again.Stream == run.StreamOf(0) || again.Attempt != 2 {
		t.Fatalf("second offer: cursor %q (%v), stream %q, attempt %d", cur, err, again.Stream, again.Attempt)
	}
	res = r.runner.Run(context.Background(), again)
	if res.Outcome != job.Uploaded || res.EndedEarly {
		t.Fatalf("second attempt: %v (ended early %v): %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	second, err := run.Events()
	if err != nil {
		t.Fatal(err)
	}
	done := lastIsCompletion(second)
	if done == nil || done.GetCause() != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM {
		t.Errorf("the resumed stream's last event: %v", second[len(second)-1])
	}
	together := append(identitiesIn(first), identitiesIn(second)...)
	if len(together) != 12 {
		t.Errorf("the two streams hold %d identities between them (%d + %d), want the 12 there are, each once", len(together), len(identitiesIn(first)), len(identitiesIn(second)))
	}
	seen := map[string]bool{}
	for _, id := range together {
		if seen[id] {
			t.Errorf("%s is in both streams", id)
		}
		seen[id] = true
	}
}

func TestTheSpoolIsGoneAfterASuccessAndAfterAFailure(t *testing.T) {
	r := newRig(t, nil)
	if res, _ := r.run(t, ok(3)); res.Outcome != job.Uploaded {
		t.Fatal(res.Reason)
	}
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("after a success: %v", files)
	}
	if res, _ := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"violate","records":5}`}); res.Outcome != job.Aborted {
		t.Fatal(res.Reason)
	}
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("after a failure: %v", files)
	}
}

func TestTheSecretFilesAreGoneWhenTheJobIs(t *testing.T) {
	r := newRig(t, nil)
	r.env["KC_SECRET"] = "a-secret-the-collector-reads"
	cfg := `{"mode":"ok","records":2,"secret_file":"env:KC_SECRET"}`
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: cfg})
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	events, _ := run.Events()
	read := false
	for _, e := range events {
		if e.GetDiagnostic().GetCode() == "test.secret_read" {
			read = true
			if want := "read " + strconv.Itoa(len("a-secret-the-collector-reads")) + " bytes"; !strings.Contains(e.GetDiagnostic().GetMessage(), want) {
				t.Errorf("diagnostic %q, want %q", e.GetDiagnostic().GetMessage(), want)
			}
		}
	}
	if !read {
		t.Error("the collector could not read its secret: the test shows nothing")
	}
	entries, _ := os.ReadDir(r.runner.Secrets.Dir)
	if len(entries) != 0 {
		t.Errorf("secret files survive the job: %v", entries)
	}
}

// A 422 is either damage on the way (send it again) or a chunk the service finds not well
// formed (sending it again changes nothing). The first clears at once; the second is given up
// after a few tries and not after ten minutes.
func TestAChunkTheServiceFindsMalformedIsGivenUpAfterAFewTries(t *testing.T) {
	r := newRig(t, nil)
	r.svc.Fail(fakeservice.Chunk(0), -1, http.StatusUnprocessableEntity, nil)
	start := time.Now()
	res, run := r.run(t, ok(2))
	if res.Outcome != job.Aborted || !strings.Contains(res.Reason, "refused chunk 0") {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if got := r.svc.Hits("PUT /agent/v1/streams/{stream}/chunks/{n}"); got != 3 {
		t.Errorf("%d PUTs, want 3", got)
	}
	if run.Final() || time.Since(start) > 5*time.Second {
		t.Errorf("final %v after %v", run.Final(), time.Since(start))
	}
}

func TestADigestMismatchOnTheWayIsSentAgainAndGoesThrough(t *testing.T) {
	r := newRig(t, nil)
	r.svc.Fail(fakeservice.Chunk(0), 2, http.StatusUnprocessableEntity, nil)
	res, run := r.run(t, ok(2))
	if res.Outcome != job.Uploaded || !run.Final() {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
}

// The runner is built by the command line with no backoff of its own; its retries are then the
// service-facing schedule, not a one-second ceiling.
func TestARunnerWithNoBackoffRetriesOnTheDefaultSchedule(t *testing.T) {
	r := job.New(job.Config{})
	if r.Backoff != backoff.Defaults {
		t.Errorf("Backoff = %+v, want %+v", r.Backoff, backoff.Defaults)
	}
	custom := backoff.Policy{Min: time.Millisecond, Max: time.Second}
	if got := job.New(job.Config{Backoff: custom}).Backoff; got != custom {
		t.Errorf("a policy that was given was replaced: %+v", got)
	}
}

// A chunk limit the service names that is smaller than one ordinary event would give every job up.
func TestAChunkLimitTooSmallToBeUsedIsRaisedAndTheJobGoesThrough(t *testing.T) {
	r := newRig(t, nil)
	r.svc.ChunkBytes = 10
	res, run := r.run(t, ok(3))
	if res.Outcome != job.Uploaded || !run.Final() {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
}

// A frame the limit cannot hold is the job's end with a reason, not an endless sealing.
func TestAnEventThatCannotFitTheChunkLimitGivesTheJobUpWithAReason(t *testing.T) {
	r := newRig(t, nil)
	r.svc.ChunkBytes = chunk.MinChunk
	_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":2,"payload":400000}`})
	if !strings.Contains(why, "chunk") || !strings.Contains(why, "limit") {
		t.Errorf("reason %q", why)
	}
}

// ---- a collector that echoes what it was handed

// The agent holds the values it resolved. A collector that writes one into an event, in any of
// the forms a library might, gets the job given up before the event can be uploaded.
func TestACollectorThatEchoesItsCredentialInAnyFormGetsTheJobGivenUpAndNothingOfItUploaded(t *testing.T) {
	const secret = "kc-s3cret/with+odd=chars-9f3a7d61"
	for _, how := range []string{"raw", "json", "quoted", "b64std", "b64url", "b64rawstd", "b64rawurl", "b64embedded", "hex", "query"} {
		t.Run(how, func(t *testing.T) {
			r := newRig(t, func(c *job.Config) { c.RawTarget = 1 }) // every frame leaves at once: earlier ones are uploaded
			r.env["KC_SECRET"] = secret
			pidFile := filepath.Join(t.TempDir(), "pid")
			cfg := `{"mode":"slow","records":200,"delay_ms":30,"pid_file":"` + pidFile + `","secret_file":"env:KC_SECRET","leak_as":"` + how + `"}`
			res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: cfg})
			if res.Outcome != job.Aborted {
				t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
			}
			if !strings.Contains(res.Reason, "echoed a credential") || strings.Contains(res.Reason, secret) {
				t.Errorf("reason %q", res.Reason)
			}
			// Which credential, so that an operator can tell a leak from a coincidence; never its value.
			if !strings.Contains(res.Reason, "env:KC_SECRET") || !strings.Contains(r.logs.String(), "reference=env:KC_SECRET") {
				t.Errorf("the reference is not named:\nreason %q\nlog %s", res.Reason, r.logs.String())
			}
			if run.Final() || run.Aborted() == "" || strings.Contains(run.Aborted(), secret) {
				t.Errorf("final %v, the service was told %q", run.Final(), run.Aborted())
			}
			for _, enc := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)), hex.EncodeToString([]byte(secret))} {
				if bytes.Contains(r.svc.Everything(), []byte(enc)) {
					t.Errorf("%q reached the service", enc)
				}
			}
			waitDead(t, waitForPID(t, pidFile))
			if files := spoolFiles(t, r.st); len(files) != 0 {
				t.Errorf("the spool was left behind: %v", files)
			}
			if strings.Contains(r.logs.String(), secret) {
				t.Errorf("the agent's log holds the value:\n%s", r.logs.String())
			}
		})
	}
}

// A value of seven bytes is in ordinary data by chance, so it is not enforced; eight is.
func TestAShortCredentialIsNotEnforcedInEventsAndALongerOneIs(t *testing.T) {
	r := newRig(t, nil)
	r.env["SHORT"] = "abcdefg"
	res, _ := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"secret_file":"env:SHORT","leak_as":"raw"}`})
	if res.Outcome != job.Uploaded {
		t.Errorf("a 7-byte credential: %v: %s", res.Outcome, res.Reason)
	}
	r.env["EIGHT"] = "abcdefgh"
	res, _ = r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"secret_file":"env:EIGHT","leak_as":"raw"}`})
	if res.Outcome != job.Aborted {
		t.Errorf("an 8-byte credential: %v: %s", res.Outcome, res.Reason)
	}
}

// ---- how a stream ends early

func chanClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// finish runs the job again, as the loop would, for as long as the service offers it.
func (r *rig) finish(t *testing.T, run *fakeservice.Run) (results []job.Result) {
	t.Helper()
	for range 12 {
		if chanClosed(run.Done()) {
			return results
		}
		again := r.next(t)
		results = append(results, r.runner.Run(context.Background(), again))
	}
	t.Fatal("the run did not finish")
	return nil
}

// upToLastCheckpoint is what the service keeps of a stream that is continued: the events to its
// last checkpoint, and not the ones after.
func upToLastCheckpoint(events []*collectorv1.CollectResponse) []*collectorv1.CollectResponse {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].GetCheckpoint() != nil {
			return events[:i+1]
		}
	}
	return nil
}

// The whole collection once: each stream to its last checkpoint but the last, which whole.
func identitiesOfTheRun(t *testing.T, run *fakeservice.Run) []string {
	t.Helper()
	var ids []string
	for i := range run.Attempts() {
		events, err := run.StreamEvents(i)
		if err != nil {
			t.Fatal(err)
		}
		if i < run.Attempts()-1 {
			events = upToLastCheckpoint(events)
		}
		ids = append(ids, identitiesIn(events)...)
	}
	return ids
}

func eachOnce(t *testing.T, ids []string, want int) {
	t.Helper()
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Errorf("%s arrived twice", id)
		}
		seen[id] = true
	}
	if len(seen) != want {
		t.Errorf("%d identities, want %d", len(seen), want)
	}
}

// The answer to the last chunk was lost. The chunk is sent again and the service says "duplicate",
// which says nothing of the stream ending early: the agent knows that from what it sent.
func TestAnEarlyEndIsKnownFromWhatWasSentAndNotFromTheAnswer(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.SpoolLimit = 30 << 10
		c.RawTarget = 1 << 30
	})
	r.svc.DropAnswers(fakeservice.Chunk(0), 1)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":12,"payload":4000,"checkpoint_every":3}`})
	if res.Outcome != job.Uploaded || !run.EndedEarly() {
		t.Fatalf("outcome %v (ended early at the service: %v): %s", res.Outcome, run.EndedEarly(), res.Reason)
	}
	if !res.EndedEarly {
		t.Error("the stream ended early and the answer that said so was lost: the job is reported as not ended early")
	}
	if got := r.svc.Hits("PUT /agent/v1/streams/{stream}/chunks/{n}"); got != 2 {
		t.Errorf("%d PUTs, want the one chunk twice", got)
	}
}

// A collector that closes its stream without the completion has ended early like one that was
// stopped: the service resumes from the last checkpoint, so that is where the stream ends, and
// not with the events after it.
func TestACollectorThatClosesWithoutACompletionHasItsStreamCutAtItsLastCheckpoint(t *testing.T) {
	r := newRig(t, nil)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"no_completion","records":7,"checkpoint_every":3}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("outcome %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	events, err := run.Events()
	if err != nil {
		t.Fatal(err)
	}
	if events[len(events)-1].GetCheckpoint() == nil {
		t.Errorf("the stream does not end at a checkpoint: %T", events[len(events)-1].GetEvent())
	}
	// Eight items were sent (the scope and seven identities) and checkpoints fall after the third
	// and the sixth: the identities after the sixth item are not in the stream.
	if n := len(identitiesIn(events)); n != 5 {
		t.Errorf("%d identities in the stream, want the 5 before the last checkpoint", n)
	}
}

func TestAStreamThatWouldPassTheChunkCountTheServiceAllowsEndsEarlyAndTheRestGoesOnTheNext(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.RawTarget = 48 << 10
		c.StreamChunks = 3
	})
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":14,"payload":20000,"checkpoint_every":2}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly || run.Chunks() != 3 {
		t.Fatalf("outcome %v, ended early %v, %d chunks: %s", res.Outcome, res.EndedEarly, run.Chunks(), res.Reason)
	}
	first, _ := run.Events()
	if lastIsCompletion(first) != nil {
		t.Error("the first stream carries a completion")
	}
	r.finish(t, run)
	if run.Failed() != "" || run.Aborted() != "" {
		t.Fatalf("failed %q, aborted %q", run.Failed(), run.Aborted())
	}
	for i := range run.Attempts() {
		if events, _ := run.StreamEvents(i); len(events) == 0 {
			t.Errorf("stream %d is empty", i)
		}
	}
	eachOnce(t, identitiesOfTheRun(t, run), 14)
}

func TestAStreamThatWouldPassTheByteLimitEndsEarlyToo(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.RawTarget = 48 << 10
		c.StreamBytes = 60 << 10
	})
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":14,"payload":20000,"checkpoint_every":2}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("outcome %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	var sent int
	for n := range run.Chunks() {
		sent += len(run.ChunkBytes(n))
	}
	if sent > 60<<10+64 {
		t.Errorf("%d bytes went up on a stream that was to stop at %d", sent, 60<<10)
	}
	r.finish(t, run)
	eachOnce(t, identitiesOfTheRun(t, run), 14)
}

// With nothing to resume from, ending the stream early only repeats it.
func TestAStreamThatFillsUpBeforeAnyCheckpointGivesTheJobUpInsteadOfLooping(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.RawTarget = 48 << 10
		c.StreamChunks = 3
	})
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":14,"payload":20000,"checkpoint_every":12}`})
	if res.Outcome != job.Aborted || !strings.Contains(run.Aborted(), "checkpoint") || run.Final() {
		t.Errorf("outcome %v, final %v, the service was told %q", res.Outcome, run.Final(), run.Aborted())
	}
}

// A 413 is the service's own limit, which the agent only guesses at. With a checkpoint already
// sent the stream ends there; without one there is nothing to resume.
func TestAChunkTheServiceRefusesAsTooLargeEndsTheStreamAtTheCheckpointBeforeIt(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.RawTarget = 48 << 10 })
	r.svc.Fail(fakeservice.Chunk(1), 1, http.StatusRequestEntityTooLarge, nil)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":14,"payload":20000,"checkpoint_every":2}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly || run.Chunks() != 2 {
		t.Fatalf("outcome %v, ended early %v, %d chunks: %s", res.Outcome, res.EndedEarly, run.Chunks(), res.Reason)
	}
	r.finish(t, run)
	eachOnce(t, identitiesOfTheRun(t, run), 14)
}

func TestAChunkRefusedAsTooLargeBeforeAnyCheckpointWentUpGivesTheJobUp(t *testing.T) {
	r := newRig(t, nil)
	r.svc.Fail(fakeservice.Chunk(0), 1, http.StatusRequestEntityTooLarge, nil)
	_, why := aborted(t, r, ok(3))
	if !strings.Contains(why, "chunk 0") || !strings.Contains(why, "checkpoint") {
		t.Errorf("reason %q", why)
	}
}

// ---- what the service asks for in return

// A 503 with Retry-After is the service reading as many chunks as it will at once. It is not
// trouble: the chunk stays in the spool, the agent waits as asked, and it is not counted against the
// ten minutes a chunk may fail for.
func TestAServiceBusyReadingChunksIsWaitedForAndIsNotCountedAsFailing(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.UploadPatience = 300 * time.Millisecond })
	r.svc.Fail(fakeservice.Chunk(0), 3, http.StatusServiceUnavailable, http.Header{"Retry-After": {"1"}})
	start := time.Now()
	res, run := r.run(t, ok(3))
	if res.Outcome != job.Uploaded || !run.Final() {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if time.Since(start) < 3*time.Second {
		t.Errorf("done after %v: three Retry-Afters of a second were not waited out", time.Since(start))
	}
	if got := r.svc.Hits("PUT /agent/v1/streams/{stream}/chunks/{n}"); got != 4 {
		t.Errorf("%d PUTs, want the one chunk four times", got)
	}
}

// A 503 with no Retry-After is an outage, and counts.
func TestAServiceThatFailsWithNoRetryAfterStillRunsOutOfPatience(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.UploadPatience = 200 * time.Millisecond })
	r.svc.Fail(fakeservice.Chunk(0), -1, http.StatusServiceUnavailable, nil)
	res, _ := r.run(t, ok(3))
	if res.Outcome != job.Aborted || !strings.Contains(res.Reason, "could not be delivered") {
		t.Errorf("outcome %v: %s", res.Outcome, res.Reason)
	}
}

// A chunk goes again with the bytes it had. The service never reads a number twice: the same
// bytes are a duplicate and other bytes under an old number would fail the run.
func TestAChunkIsNeverSentAgainWithDifferentBytesUnderTheSameNumber(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.RawTarget = 48 << 10 })
	r.svc.Fail(fakeservice.Chunk(1), 2, http.StatusServiceUnavailable, nil)
	r.svc.DropAnswers(fakeservice.Chunk(2), 2)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":14,"payload":20000}`})
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if conflicts := r.svc.Conflicts(); conflicts != 0 {
		t.Errorf("%d chunks arrived with other bytes under a number that had arrived", conflicts)
	}
	if run.Chunks() < 4 {
		t.Errorf("%d chunks: the test needs several", run.Chunks())
	}
}

// A collector that dies mid-stream ends the stream early, like a spool that fills: the service
// offers the job again from the last checkpoint, up to eight starts, and the stream was only the
// events before it.
func TestACollectorThatDiesMidStreamEndsItsStreamAtItsLastCheckpointAndTheJobResumes(t *testing.T) {
	r := newRig(t, nil)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"crash","records":5}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("outcome %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	first, _ := run.Events()
	if lastIsCompletion(first) != nil || first[len(first)-1].GetCheckpoint() == nil {
		t.Errorf("the first stream should end at a checkpoint, with no completion: %T", first[len(first)-1].GetEvent())
	}
	if !strings.Contains(r.logs.String(), "ending the stream at its last checkpoint") {
		t.Errorf("the log does not say why:\n%s", r.logs.String())
	}
	// The second attempt starts past the point the collector dies at, and finishes.
	r.finish(t, run)
	if run.Failed() != "" || run.Aborted() != "" {
		t.Fatalf("failed %q, aborted %q", run.Failed(), run.Aborted())
	}
	eachOnce(t, identitiesOfTheRun(t, run), 5)
}

// An event too big for the agent to receive is not a crash that a second start would cure.
func TestAnEventTooBigToBeReceivedGivesTheJobUpInsteadOfBeingRetried(t *testing.T) {
	r := newRig(t, nil)
	_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":2,"payload":9000000}`})
	if !strings.Contains(why, "ResourceExhausted") && !strings.Contains(why, "over the limit") {
		t.Errorf("reason %q", why)
	}
}

// ---- a stream that resumed

// A stream that resumed is the rest of the collection and cannot say it is the whole of it,
// unless the collector could not use the cursor and says so.
func TestAResumedStreamThatSaysItIsCompleteIsAViolationUnlessTheCursorWasRejected(t *testing.T) {
	cursor := `{"token":"` + base64.StdEncoding.EncodeToString([]byte("3")) + `"}`
	r := newRig(t, nil)
	_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"resume_complete","records":5}`, ResumeCursor: cursor})
	if !strings.Contains(why, "resumed-stream-must-not-be-complete") {
		t.Errorf("reason %q", why)
	}

	// A cursor the collector cannot read: it starts over, says so, and its stream stands alone.
	bad := `{"token":"` + base64.StdEncoding.EncodeToString([]byte("not a position")) + `"}`
	res, run := newRig(t, nil).run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":3}`, ResumeCursor: bad})
	if res.Outcome != job.Uploaded {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	events, _ := run.Events()
	done := lastIsCompletion(events)
	var said bool
	for _, e := range events {
		said = said || e.GetDiagnostic().GetCode() == "cursor.rejected"
	}
	if !said || done == nil || done.GetVerdict() != collectorv1.Verdict_VERDICT_COMPLETE {
		t.Errorf("said %v, completion %v", said, done)
	}
}

// ---- the service's other limits on a stream

// The service holds a whole collection in memory while it reads it, and refuses one of more than a
// million events, however many streams it came in. Ending a stream early cannot help: the next one
// would only add to what is already too much. So the job is given up, and says why.
func TestASourceWithMoreEventsThanACollectionMayHoldIsGivenUpAndNotEndedEarly(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.RawTarget = 1 // a chunk a frame, so that the count is the agent's to keep
		c.StreamEvents = 40
	})
	pidFile := filepath.Join(t.TempDir(), "pid")
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"slow","records":60,"delay_ms":10,"checkpoint_every":3,"pid_file":"` + pidFile + `"}`})
	if res.Outcome != job.Aborted || run.Final() || run.EndedEarly() || run.Attempts() != 1 {
		t.Fatalf("outcome %v, final %v, ended early %v, %d attempts: %s", res.Outcome, run.Final(), run.EndedEarly(), run.Attempts(), res.Reason)
	}
	for _, want := range []string{"this source holds more than 40 events", "the most one collection may hold"} {
		if !strings.Contains(run.Aborted(), want) {
			t.Errorf("the service was told %q, which does not say %q", run.Aborted(), want)
		}
	}
	waitDead(t, waitForPID(t, pidFile))
	if files := spoolFiles(t, r.st); len(files) != 0 {
		t.Errorf("the spool was left behind: %v", files)
	}
}

// The limit is the whole collection's: what the earlier streams of the run contribute is spent.
func TestTheEventsTheEarlierStreamsContributeAreSpentFromTheBudget(t *testing.T) {
	cfg := `{"mode":"ok","records":12,"checkpoint_every":1}` // 1 + 12 + 13 checkpoints: 26 events before the completion
	job40 := func(c *job.Config) { c.RawTarget = 1; c.StreamEvents = 40 }

	res, run := newRig(t, job40).run(t, fakeservice.Job{Collector: "testcollector", Config: cfg})
	if res.Outcome != job.Uploaded || !run.Final() {
		t.Fatalf("with nothing spent: %v: %s", res.Outcome, res.Reason)
	}
	res, run = newRig(t, job40).run(t, fakeservice.Job{Collector: "testcollector", Config: cfg, ResumeEvents: 15})
	if res.Outcome != job.Aborted || !strings.Contains(run.Aborted(), "events") {
		t.Errorf("with 15 spent of 40: %v, told %q", res.Outcome, run.Aborted())
	}
	// Spent right up to the budget leaves nothing.
	res, _ = newRig(t, job40).run(t, fakeservice.Job{Collector: "testcollector", Config: cfg, ResumeEvents: 40})
	if res.Outcome != job.Aborted {
		t.Errorf("with 40 spent of 40: %v", res.Outcome)
	}
}

// A collection that came in several streams is one collection: the second stream's budget is what
// the first left, as the service says in resume_events.
func TestACollectionSplitBySpaceThatIsStillTooManyEventsIsGivenUpOnTheLaterStream(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.SpoolLimit = 90 << 10
		c.RawTarget = 1
		c.StreamEvents = 12
	})
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":14,"payload":20000,"checkpoint_every":1}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("the first stream: %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	again := r.next(t)
	if again.ResumeEvents == 0 || again.ResumeEvents >= 12 {
		t.Fatalf("resume_events = %d: the first stream should have contributed some of the 12", again.ResumeEvents)
	}
	res = r.runner.Run(context.Background(), again)
	if res.Outcome != job.Aborted || !strings.Contains(run.Aborted(), "events") || run.Attempts() != 2 {
		t.Errorf("the second stream: %v after %d attempts, told %q", res.Outcome, run.Attempts(), run.Aborted())
	}
}

// The chunk that carries the completion may go as far as the service's own limit: a collection that
// is whole is not thrown away for passing a limit that has room above it.
func TestTheChunkThatCarriesTheCompletionMayGoPastTheBudgetButNotPastTheLimit(t *testing.T) {
	tight := func(c *job.Config) {
		c.RawTarget = 1 << 30 // one chunk, which carries the completion
		c.StreamEvents = 10
		c.MaxStreamEvents = 20
	}
	res, run := newRig(t, tight).run(t, ok(8)) // 1 + 8 + 9 checkpoints + the completion: 19 events
	if res.Outcome != job.Uploaded || res.EndedEarly || !run.Final() {
		t.Fatalf("19 events with a budget of 10 and a limit of 20: %v: %s", res.Outcome, res.Reason)
	}
	// 27 events is past the limit, and past the limit and the budget together would be 30.
	res, run = newRig(t, tight).run(t, ok(12))
	if res.Outcome != job.Aborted || run.Final() || !strings.Contains(run.Aborted(), "events") {
		t.Errorf("27 events with a limit of 20: %v, told %q", res.Outcome, run.Aborted())
	}
	// The limit is the collection's, too: 19 events and 5 already spent is 24.
	res, _ = newRig(t, tight).run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":8}`, ResumeEvents: 5})
	if res.Outcome != job.Aborted {
		t.Errorf("19 events and 5 spent against a limit of 20: %v", res.Outcome)
	}
}

// The service refuses a collection that inflates to more than 2 GiB. The same: the budget is the
// stream's, the completion may go to the limit.
func TestASourceWithMoreDataThanACollectionMayHoldIsGivenUp(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.RawTarget = 48 << 10
		c.StreamInflated = 100 << 10
	})
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":14,"payload":20000,"checkpoint_every":2}`})
	if res.Outcome != job.Aborted || run.Final() || run.EndedEarly() {
		t.Fatalf("outcome %v, final %v, ended early %v: %s", res.Outcome, run.Final(), run.EndedEarly(), res.Reason)
	}
	if !strings.Contains(run.Aborted(), "this source holds more than") || !strings.Contains(run.Aborted(), "of data") {
		t.Errorf("the service was told %q", run.Aborted())
	}
}

func TestTheChunkThatCarriesTheCompletionMayGoPastTheDataBudgetButNotPastTheLimit(t *testing.T) {
	tight := func(c *job.Config) {
		c.RawTarget = 1 << 30
		c.StreamInflated = 30 << 10
		c.MaxStreamInflated = 70 << 10
	}
	small := `{"mode":"ok","records":3,"payload":20000}`  // about 62 KB: over the budget, under the limit
	middle := `{"mode":"ok","records":4,"payload":20000}` // about 82 KB: over the limit, under the two together
	res, run := newRig(t, tight).run(t, fakeservice.Job{Collector: "testcollector", Config: small})
	if res.Outcome != job.Uploaded || !run.Final() {
		t.Fatalf("62 KB with a budget of 30 and a limit of 70: %v: %s", res.Outcome, res.Reason)
	}
	res, run = newRig(t, tight).run(t, fakeservice.Job{Collector: "testcollector", Config: middle})
	if res.Outcome != job.Aborted || run.Final() {
		t.Errorf("82 KB with a limit of 70: %v: %s", res.Outcome, res.Reason)
	}
}

// What an earlier stream of the run sent counts against the data budget too. The service does not
// say how much that was, so the agent keeps the account itself, for as long as it is running.
func TestWhatTheEarlierStreamsOfARunSentIsSpentFromTheDataBudget(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.SpoolLimit = 90 << 10
		c.RawTarget = 48 << 10
		c.StreamInflated = 120 << 10
	})
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":14,"payload":20000,"checkpoint_every":1}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("the first stream: %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	res = r.runner.Run(context.Background(), r.next(t))
	if res.Outcome != job.Aborted || !strings.Contains(run.Aborted(), "of data") {
		t.Errorf("the second stream: %v, told %q: with 120 KB for the whole collection and 60 KB gone, 60 KB is not room for 48 KB batches that go on", res.Outcome, run.Aborted())
	}
}

// A completion that the full spool has no room for is not let past it: the stream is cut at its
// last checkpoint and the tail is collected again.
func TestACompletionThatThereIsNoRoomForInTheSpoolEndsTheStreamEarlyInstead(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.SpoolLimit = 16 << 10
		c.RawTarget = 1 << 30
	})
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"incomplete","records":5,"payload":1500,"checkpoint_every":1,"completion_pad":9000}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("outcome %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	first, _ := run.Events()
	if lastIsCompletion(first) != nil {
		t.Error("the completion was let past a full spool")
	}
	r.finish(t, run)
	eachOnce(t, identitiesOfTheRun(t, run), 5)
}

// What a collector writes in a field of its complaint is cut to a length, and the cut must come
// after the value is taken out of it, not before: twenty characters of a credential are a lot.
func TestAComplaintWhoseFieldEndsInTheCredentialDoesNotLetAnyOfItReachTheServiceOrTheLog(t *testing.T) {
	const secret = "Zq8vN3mT7xK2pR9wL5cB1dF6hJ4sG0aY8uE3iO7t"
	r := newRig(t, nil)
	r.env["KC_SECRET"] = secret
	_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: `{"issue":"x","issue_field_from_secret":true,"secret_file":"env:KC_SECRET"}`})
	for n := 6; n <= len(secret); n += 6 {
		for _, piece := range []string{secret[:n], secret[len(secret)-n:]} {
			if strings.Contains(why, piece) || strings.Contains(r.logs.String(), piece) {
				t.Fatalf("%d characters of the credential got out:\nreason %q\nlog %s", n, why, r.logs.String())
			}
		}
	}
	if !strings.Contains(why, "test.issue") {
		t.Errorf("reason %q", why)
	}
}

// A proxy address with a password is in the agent's environment and handed on; if a collector
// repeats it, it is neither uploaded nor logged.
func TestAProxyPasswordInTheAgentsEnvironmentIsNotLetThroughInAnEvent(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.PassEnv = []string{"HTTPS_PROXY"} })
	r.env["HTTPS_PROXY"] = "http://svc:pr0xy-Pa55word-9z@proxy.corp.example:3128"
	r.env["KC_SECRET"] = "an-unrelated-credential-1"
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"env_probe":["HTTPS_PROXY"],"secret_file":"env:KC_SECRET","leak_env":"HTTPS_PROXY"}`})
	if res.Outcome != job.Aborted || run.Final() {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if strings.Contains(run.Aborted(), "pr0xy-Pa55word-9z") || bytes.Contains(r.svc.Everything(), []byte("pr0xy-Pa55word-9z")) {
		t.Error("the proxy password reached the service")
	}
}

// The AWS IAM collector takes its keys from its environment: the secret key an operator passes it is a
// credential like a reference's, and is neither uploaded nor logged. The key id beside it is a setting.
func TestAnAWSSecretKeyPassedToACollectorIsNotLetThroughInAnEvent(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	for _, leak := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		r := newRig(t, func(c *job.Config) {
			c.PassEnv = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}
		})
		r.env["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"
		r.env["AWS_SECRET_ACCESS_KEY"] = secret
		r.env["AWS_SESSION_TOKEN"] = "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQD"
		res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"leak_env":"` + leak + `"}`})
		if res.Outcome != job.Aborted || run.Final() {
			t.Fatalf("%s: outcome %v: %s", leak, res.Outcome, res.Reason)
		}
		if !strings.Contains(run.Aborted(), "env:"+leak) {
			t.Errorf("%s: told %q, which does not name the variable", leak, run.Aborted())
		}
		if bytes.Contains(r.svc.Everything(), []byte(secret)) || bytes.Contains(r.svc.Everything(), []byte(r.env["AWS_SESSION_TOKEN"])) {
			t.Errorf("%s: the secret reached the service", leak)
		}
		if logged := r.logs.String(); strings.Contains(logged, secret) {
			t.Errorf("%s: the secret is in the agent's log", leak)
		}
	}
	r := newRig(t, func(c *job.Config) { c.PassEnv = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} })
	r.env["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"
	r.env["AWS_SECRET_ACCESS_KEY"] = secret
	if res, _ := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"leak_env":"AWS_ACCESS_KEY_ID"}`}); res.Outcome != job.Uploaded {
		t.Errorf("the key id was taken for the secret: %v: %s", res.Outcome, res.Reason)
	}
}

// And when the keys are in a file the operator points the collector at.
func TestTheKeysInAnAWSFilePassedToACollectorAreNotLetThroughInAnEvent(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *job.Config) { c.PassEnv = []string{"AWS_SHARED_CREDENTIALS_FILE"} })
	r.env["AWS_SHARED_CREDENTIALS_FILE"] = path
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"leak_file_of_env":"AWS_SHARED_CREDENTIALS_FILE"}`})
	if res.Outcome != job.Aborted || run.Final() || bytes.Contains(r.svc.Everything(), []byte(secret)) {
		t.Fatalf("outcome %v: %s", res.Outcome, res.Reason)
	}
	if !strings.Contains(run.Aborted(), "file:"+path) {
		t.Errorf("told %q, which does not name the file", run.Aborted())
	}
	// A file too big to watch for is a file the collector might read: the job is not run.
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("# comment\n"), 200_000), 0o600); err != nil {
		t.Fatal(err)
	}
	r = newRig(t, func(c *job.Config) { c.PassEnv = []string{"AWS_SHARED_CREDENTIALS_FILE"} })
	r.env["AWS_SHARED_CREDENTIALS_FILE"] = big
	res, run = r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1}`})
	if res.Outcome != job.Aborted || !strings.Contains(run.Aborted(), "AWS_SHARED_CREDENTIALS_FILE") {
		t.Errorf("outcome %v, told %q", res.Outcome, run.Aborted())
	}
	// One that is not a file is skipped, with a line in the log, and the job runs.
	r = newRig(t, func(c *job.Config) { c.PassEnv = []string{"AWS_SHARED_CREDENTIALS_FILE"} })
	r.env["AWS_SHARED_CREDENTIALS_FILE"] = t.TempDir()
	res, _ = r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1}`})
	if res.Outcome != job.Uploaded || !strings.Contains(r.logs.String(), "was not read") {
		t.Errorf("outcome %v: %s\n%s", res.Outcome, res.Reason, r.logs.String())
	}
}

func TestAProxyAddressWithNoPasswordIsNotACredentialAndMayBeMentioned(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.PassEnv = []string{"HTTPS_PROXY"} })
	r.env["HTTPS_PROXY"] = "http://proxy.corp.example:3128"
	r.env["KC_SECRET"] = "an-unrelated-credential-1"
	res, _ := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"secret_file":"env:KC_SECRET","leak_env":"HTTPS_PROXY"}`})
	if res.Outcome != job.Uploaded {
		t.Errorf("outcome %v: %s", res.Outcome, res.Reason)
	}
}

// The same for a collector that dies: the stream ends where the last checkpoint is, and not after
// the events the collector sent since. Ended any other way, the resumed attempt sends them again.
func TestACollectorThatDiesAfterEventsPastItsLastCheckpointHasThemLeftOutOfItsStream(t *testing.T) {
	r := newRig(t, nil)
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"crash","records":8,"checkpoint_every":3,"crash_after":4}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("outcome %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	first, _ := run.Events()
	if first[len(first)-1].GetCheckpoint() == nil {
		t.Errorf("the stream does not end at a checkpoint: %T", first[len(first)-1].GetEvent())
	}
	// Items sent: the scope and identities u0..u3; the one checkpoint falls after the third item.
	if n := len(identitiesIn(first)); n != 2 {
		t.Errorf("%d identities in the stream, want the 2 before the checkpoint", n)
	}
	r.finish(t, run)
	eachOnce(t, identitiesOfTheRun(t, run), 8)
}

// The account of what a run's streams sent is kept while the run goes on and dropped when it ends,
// whichever way.
func TestTheAccountOfWhatARunSentIsKeptWhileItGoesOnAndDroppedWhenItEnds(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.SpoolLimit = 90 << 10; c.RawTarget = 48 << 10 })
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":6,"payload":20000,"checkpoint_every":1}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("%v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	runID := run.ID()
	if r.runner.Spent(runID) < 40<<10 {
		t.Errorf("spent = %d after a stream of three 20 KB events", r.runner.Spent(runID))
	}
	r.finish(t, run)
	if got := r.runner.Spent(runID); got != 0 {
		t.Errorf("spent = %d after the run ended: the account should be dropped", got)
	}
}

// The service keeps a stream that ended early to its last checkpoint and drops the rest, which the
// next stream sends again. The account of what has been sent counts only what is kept.
func TestTheDataAccountCountsOnlyWhatIsKeptToTheLastCheckpoint(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.RawTarget = 1
		c.StreamInflated = 170 << 10
		c.MaxStreamInflated = 180 << 10
	})
	// Eight 20 KB events, a checkpoint every third item, and a death after the seventh: about 137 KB are
	// sent and about 100 KB of them are before the last checkpoint.
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"crash","records":8,"payload":20000,"checkpoint_every":3,"crash_after":7}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("the first stream: %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	kept := r.runner.Spent(run.ID())
	if kept < 55<<10 || kept > 125<<10 {
		t.Errorf("spent = %d: about 100 KB of the 137 KB sent are before the last checkpoint", kept)
	}
	res = r.runner.Run(context.Background(), r.next(t))
	if res.Outcome != job.Uploaded || res.EndedEarly || run.Aborted() != "" {
		t.Errorf("the second stream: %v, told %q: %s", res.Outcome, run.Aborted(), res.Reason)
	}
	// The same source that does not die is no different.
	res, _ = newRig(t, func(c *job.Config) {
		c.RawTarget = 1
		c.StreamInflated = 170 << 10
		c.MaxStreamInflated = 180 << 10
	}).run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":8,"payload":20000,"checkpoint_every":3}`})
	if res.Outcome != job.Uploaded {
		t.Errorf("without a death: %v: %s", res.Outcome, res.Reason)
	}
}

// A resumed stream that dies before a checkpoint of its own has nothing the service keeps.
func TestAResumedStreamThatDiesBeforeACheckpointAddsNothingToTheAccount(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.RawTarget = 1 })
	cursor := `{"token":"` + base64.StdEncoding.EncodeToString([]byte("2")) + `"}`
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"crash","records":8,"payload":20000,"checkpoint_every":50,"crash_after":6,"crash_on_resume":true}`, ResumeCursor: cursor})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("%v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	if got := r.runner.Spent(run.ID()); got != 0 {
		t.Errorf("spent = %d for a stream with no checkpoint after its cursor", got)
	}
}

// ---- the account of what a run sent: kept for a run that goes on, dropped when its job ends

func TestTheAccountsOfRunsThatGoOnAreNeverWipedToMakeRoomAndTheOldestGoesFirst(t *testing.T) {
	now := time.Now()
	r := job.New(job.Config{Now: func() time.Time { return now }})
	r.Spend("first", 100)
	for i := range 1100 {
		now = now.Add(time.Second)
		r.Spend(fmt.Sprintf("run-%d", i), 1)
	}
	if got := r.Accounts(); got != 1024 {
		t.Errorf("%d accounts after 1101 runs: the bound is 1024", got)
	}
	if r.Spent("first") != 0 || r.Spent("run-0") != 0 {
		t.Error("the oldest accounts were kept past the bound")
	}
	// The newest are all there: nothing was wiped.
	for i := 1100 - 1024; i < 1100; i += 97 {
		if r.Spent(fmt.Sprintf("run-%d", i)) != 1 {
			t.Errorf("the account of run-%d is gone though it is among the newest 1024", i)
		}
	}
	// A run that is already in the map does not push another out when it spends again.
	before := r.Accounts()
	r.Spend("run-1099", 5)
	if r.Accounts() != before || r.Spent("run-1099") != 6 {
		t.Errorf("a second spend: %d accounts, spent %d", r.Accounts(), r.Spent("run-1099"))
	}
}

func TestAnAccountIsNotKeptPastAFewHours(t *testing.T) {
	now := time.Now()
	r := job.New(job.Config{Now: func() time.Time { return now }})
	r.Spend("old", 1000)
	r.Spend("fresh", 7)
	now = now.Add(35 * time.Hour)
	if r.Spent("old") != 1000 {
		t.Error("an account of 35 hours was dropped")
	}
	now = now.Add(2 * time.Hour)
	if r.Spent("old") != 0 {
		t.Error("an account of 37 hours is still read")
	}
	r.Spend("newer", 1)
	if r.Accounts() != 1 {
		t.Errorf("%d accounts after the old ones were due: the old ones should be dropped on the next spend", r.Accounts())
	}
}

// The account is the run's, and the run goes on until it is finished, given up on by the agent, or
// gone from the service: a lost lease, or the agent being stopped, is the service offering the run
// again with the earlier streams kept, and it counts from where it was.
func TestTheAccountOfARunIsDroppedWhenTheRunEndsAndKeptWhenOnlyTheJobDoes(t *testing.T) {
	for name, c := range map[string]struct {
		finish  func(t *testing.T, r *rig, run *fakeservice.Run, again *client.Job)
		dropped bool
	}{
		"it is given up": {dropped: true, finish: func(t *testing.T, r *rig, run *fakeservice.Run, again *client.Job) {
			r.runner.StreamEvents = 3 // far fewer events than the second stream holds
			r.runner.Run(context.Background(), again)
		}},
		"it finishes": {dropped: true, finish: func(t *testing.T, r *rig, run *fakeservice.Run, again *client.Job) {
			r.runner.Run(context.Background(), again)
		}},
		"the service says the stream is closed": {dropped: true, finish: func(t *testing.T, r *rig, run *fakeservice.Run, again *client.Job) {
			r.svc.Reply(fakeservice.Chunk(0), -1, http.StatusConflict, `{"code":"stream_closed","status":409}`)
			r.svc.Reply(fakeservice.Path(http.MethodPost, "/heartbeat"), -1, http.StatusConflict, `{"code":"stream_closed","status":409}`)
			if out := r.runner.Run(context.Background(), again).Outcome; out != job.LeaseLost {
				t.Fatalf("outcome %v", out)
			}
		}},
		"the service does not know the stream": {dropped: true, finish: func(t *testing.T, r *rig, run *fakeservice.Run, again *client.Job) {
			r.svc.Reply(fakeservice.Chunk(0), -1, http.StatusNotFound, `{"status":404}`)
			r.svc.Reply(fakeservice.Path(http.MethodPost, "/heartbeat"), -1, http.StatusNotFound, `{"status":404}`)
			r.runner.Run(context.Background(), again)
		}},
		"the service no longer accepts the agent": {dropped: true, finish: func(t *testing.T, r *rig, run *fakeservice.Run, again *client.Job) {
			r.svc.Reply(fakeservice.Chunk(0), -1, http.StatusForbidden, `{"status":403,"state":"revoked"}`)
			r.svc.Reply(fakeservice.Path(http.MethodPost, "/heartbeat"), -1, http.StatusForbidden, `{"status":403,"state":"revoked"}`)
			if out := r.runner.Run(context.Background(), again).Outcome; out != job.Failed {
				t.Fatalf("outcome %v", out)
			}
		}},
		"the lease is lost": {dropped: false, finish: func(t *testing.T, r *rig, run *fakeservice.Run, again *client.Job) {
			run.LoseLease()
			if out := r.runner.Run(context.Background(), again).Outcome; out != job.LeaseLost {
				t.Fatalf("outcome %v", out)
			}
		}},
		"the agent is stopped": {dropped: false, finish: func(t *testing.T, r *rig, run *fakeservice.Run, again *client.Job) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if out := r.runner.Run(ctx, again).Outcome; out != job.Cancelled {
				t.Fatalf("outcome %v", out)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(c *job.Config) { c.SpoolLimit = 90 << 10; c.RawTarget = 1 })
			res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":8,"payload":20000,"checkpoint_every":1}`})
			if res.Outcome != job.Uploaded || !res.EndedEarly || r.runner.Spent(run.ID()) == 0 {
				t.Fatalf("the first stream: %v, ended early %v, spent %d: %s", res.Outcome, res.EndedEarly, r.runner.Spent(run.ID()), res.Reason)
			}
			kept := r.runner.Spent(run.ID())
			c.finish(t, r, run, r.next(t))
			got := r.runner.Spent(run.ID())
			switch {
			case c.dropped && got != 0:
				t.Errorf("spent = %d: the run is over and the account should be dropped", got)
			case !c.dropped && got != kept:
				t.Errorf("spent = %d, was %d: the run goes on, with the earlier streams kept, and its account should stay", got, kept)
			}
		})
	}
}

// After a lost lease the service offers the run again and keeps what the earlier streams held. A source
// that is too big for the collection is still too big, and is given up on the third stream.
func TestARunThatLostALeaseIsStillCountedFromWhereItWas(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.SpoolLimit = 90 << 10
		c.RawTarget = 1
		c.StreamInflated = 100 << 10
	})
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":8,"payload":20000,"checkpoint_every":1}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("the first stream: %v: %s", res.Outcome, res.Reason)
	}
	kept := r.runner.Spent(run.ID())
	if kept < 40<<10 || kept > 95<<10 {
		t.Fatalf("spent = %d after the first stream", kept)
	}
	second := r.next(t)
	run.LoseLease()
	if out := r.runner.Run(context.Background(), second).Outcome; out != job.LeaseLost {
		t.Fatalf("the second stream: %v", out)
	}
	run.Reoffer()
	third := r.next(t)
	res = r.runner.Run(context.Background(), third)
	if res.Outcome != job.Aborted || !strings.Contains(run.Aborted(), "of data") {
		t.Errorf("the third stream: %v, told %q: with %d of 100 KB gone and 20 KB events, the budget runs out", res.Outcome, run.Aborted(), kept)
	}
}

// A stream that loses its lease, or whose agent is stopped, after it has sent some of its data: the
// service resumes the run from that stream's last checkpoint, so what it kept is spent as well.
func TestAStreamThatEndsInALostLeaseAfterSendingIsSpentToItsLastCheckpoint(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.SpoolLimit = 90 << 10; c.RawTarget = 1 })
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":8,"payload":20000,"checkpoint_every":1}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("the first stream: %v: %s", res.Outcome, res.Reason)
	}
	before := r.runner.Spent(run.ID())
	second := r.next(t)
	r.svc.Reply(fakeservice.Chunk(4), -1, http.StatusConflict, `{"code":"lease_lost","status":409}`)
	if out := r.runner.Run(context.Background(), second).Outcome; out != job.LeaseLost {
		t.Fatalf("the second stream: %v", out)
	}
	if got := r.runner.Spent(run.ID()); got < before+(19<<10) {
		t.Errorf("spent = %d after the second stream sent four chunks with 20 KB events and checkpoints, was %d", got, before)
	}
}

// A stream whose collector could not use the cursor stands alone, and the service lets the earlier
// streams go: what they held is not spent from it.
func TestAStreamThatRejectedItsCursorIsCountedAloneAndNotAfterTheEarlierOnes(t *testing.T) {
	r := newRig(t, func(c *job.Config) {
		c.RawTarget = 1
		c.StreamInflated = 200 << 10
		c.MaxStreamInflated = 210 << 10
		c.StreamEvents = 25
	})
	// The first start dies after about 100 KB and 12 events are kept; the second one starts over, as it
	// says, with 160 KB and 19 events of its own: it fits alone, and not after the first.
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"crash","records":8,"payload":20000,"checkpoint_every":1,"crash_after":5,"reject_cursor":true}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("the first stream: %v, ended early %v: %s", res.Outcome, res.EndedEarly, res.Reason)
	}
	again := r.next(t)
	if again.ResumeEvents < 8 || r.runner.Spent(run.ID()) < 60<<10 {
		t.Fatalf("resume_events = %d, spent = %d: the first stream should have contributed", again.ResumeEvents, r.runner.Spent(run.ID()))
	}
	res = r.runner.Run(context.Background(), again)
	if res.Outcome != job.Uploaded || res.EndedEarly || !run.Final() || run.Aborted() != "" {
		t.Fatalf("the second stream: %v, told %q: %s", res.Outcome, run.Aborted(), res.Reason)
	}
	// And a cursor that is used is spent as before.
	r2 := newRig(t, func(c *job.Config) {
		c.RawTarget = 1
		c.StreamInflated = 200 << 10
		c.MaxStreamInflated = 210 << 10
		c.StreamEvents = 25
	})
	res, run2 := r2.run(t, fakeservice.Job{Collector: "testcollector", Config: `{"mode":"crash","records":8,"payload":20000,"checkpoint_every":1,"crash_after":5}`})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("%v: %s", res.Outcome, res.Reason)
	}
	res = r2.runner.Run(context.Background(), r2.next(t))
	_ = run2
	if res.Outcome != job.Uploaded {
		t.Errorf("a stream that resumed holds only the rest and fits: %v: %s", res.Outcome, res.Reason)
	}
}

// ---- the limits are met exactly: a collection of exactly the limit is a collection that fits

func frameLen(t *testing.T, e *collectorv1.CollectResponse) int {
	t.Helper()
	b, err := proto.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return len(b) + len(binary.AppendUvarint(nil, uint64(len(b))))
}

func TestACollectionOfExactlyTheEventLimitFitsAndOneEventMoreDoesNot(t *testing.T) {
	cfg := fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":8}`}
	res, run := newRig(t, nil).run(t, cfg)
	if res.Outcome != job.Uploaded {
		t.Fatal(res.Reason)
	}
	events, _ := run.Events()
	total := len(events) // the last of them is the completion

	// The chunk that carries the completion, against the limit of the whole.
	whole := func(limit, spent int) job.Outcome {
		c := cfg
		c.ResumeEvents = spent
		res, _ := newRig(t, func(c *job.Config) { c.RawTarget = 1 << 30; c.StreamEvents = 1; c.MaxStreamEvents = limit }).run(t, c)
		return res.Outcome
	}
	if whole(total, 0) != job.Uploaded || whole(total-1, 0) != job.Aborted {
		t.Errorf("a limit of exactly %d events: %v, and of %d: %v", total, whole(total, 0), total-1, whole(total-1, 0))
	}
	if whole(total+5, 5) != job.Uploaded || whole(total+4, 5) != job.Aborted {
		t.Errorf("with 5 spent, a limit of %d: %v, and of %d: %v", total+5, whole(total+5, 5), total+4, whole(total+4, 5))
	}

	// The events before the completion, one to a chunk, against the budget.
	before := func(budget, spent int) job.Outcome {
		c := cfg
		c.ResumeEvents = spent
		res, _ := newRig(t, func(c *job.Config) { c.RawTarget = 1; c.StreamEvents = budget }).run(t, c)
		return res.Outcome
	}
	if before(total-1, 0) != job.Uploaded || before(total-2, 0) != job.Aborted {
		t.Errorf("a budget of exactly %d events: %v, and of %d: %v", total-1, before(total-1, 0), total-2, before(total-2, 0))
	}
	if before(total+2, 3) != job.Uploaded || before(total+1, 3) != job.Aborted {
		t.Errorf("with 3 spent, a budget of %d: %v, and of %d: %v", total+2, before(total+2, 3), total+1, before(total+1, 3))
	}
}

func TestACollectionOfExactlyTheDataLimitFitsAndOneByteMoreDoesNot(t *testing.T) {
	cfg := fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":3,"payload":2000}`}
	res, run := newRig(t, nil).run(t, cfg)
	if res.Outcome != job.Uploaded {
		t.Fatal(res.Reason)
	}
	total := run.Inflated()
	events, _ := run.Events()
	last := frameLen(t, events[len(events)-1]) // the completion

	whole := func(limit int64) job.Outcome {
		res, _ := newRig(t, func(c *job.Config) { c.RawTarget = 1 << 30; c.StreamInflated = 1; c.MaxStreamInflated = limit }).run(t, cfg)
		return res.Outcome
	}
	if whole(int64(total)) != job.Uploaded || whole(int64(total)-1) != job.Aborted {
		t.Errorf("a limit of exactly %d bytes: %v, and of %d: %v", total, whole(int64(total)), total-1, whole(int64(total)-1))
	}
	before := func(budget int64) job.Outcome {
		res, _ := newRig(t, func(c *job.Config) { c.RawTarget = 1; c.StreamInflated = budget }).run(t, cfg)
		return res.Outcome
	}
	if before(int64(total-last)) != job.Uploaded || before(int64(total-last)-1) != job.Aborted {
		t.Errorf("a budget of exactly %d bytes: %v, and of %d: %v", total-last, before(int64(total-last)), total-last-1, before(int64(total-last)-1))
	}
}

// ---- what leaves the agent is cleaned in the right order

const phrase = "horse battery st4ple" // 20 bytes: no head or tail rule, only the whole of it

func redactorOf(t *testing.T, value string) *secrets.Redactor {
	t.Helper()
	p := secrets.Policy{LookupEnv: func(string) (string, bool) { return value, true }, Dir: t.TempDir(), AllowAny: true}
	b, err := p.Bind([]byte(`{"p":"env:P"}`))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b.Redact
}

// Whitespace is collapsed and the text cut to length before the credential is looked for, or the
// agent rebuilds the credential out of what a collector wrote with a tab in it.
func TestAReasonHasNoCredentialInItWhateverWhitespaceOrLengthTheCollectorGaveIt(t *testing.T) {
	r := redactorOf(t, phrase)
	for name, text := range map[string]string{
		"a tab":           "horse\tbattery st4ple",
		"a newline":       "horse\nbattery st4ple",
		"two spaces":      "horse  battery   st4ple",
		"a carriage":      "horse\r\nbattery\tst4ple",
		"a no-break":      "horse battery st4ple",
		"as it is":        phrase,
		"inside a word":   "x" + phrase + "y",
		"in the middle":   "the field /a/b horse\tbattery st4ple was refused",
		"in two pieces":   "horse " + "battery st4ple",
		"leading spaces":  "   horse\tbattery st4ple   ",
		"doubled between": "horse \t battery \n st4ple",
	} {
		got := job.CleanReason(r, text)
		if strings.Contains(got, phrase) {
			t.Errorf("%s: the credential is in the reason: %q", name, got)
		}
		if strings.Contains(got, "\t") || strings.Contains(got, "\n") || strings.Contains(got, "  ") {
			t.Errorf("%s: the reason is not one tidy line: %q", name, got)
		}
	}
	// At every place the text can be cut, the credential or a long piece of it is not left: the cut is
	// made after the credential is gone, so no half of it is kept.
	for pad := 0; pad < 520; pad++ {
		for _, sep := range []string{" ", "\t", "\n", "  "} {
			text := strings.Repeat("a", pad) + strings.ReplaceAll(phrase, " ", sep) + " end"
			got := job.CleanReason(r, text)
			if strings.Contains(got, "horse b") || strings.Contains(got, "st4ple") || strings.Contains(got, "battery") {
				t.Fatalf("pad %d, %q: a piece of the credential is in the reason: %q", pad, sep, got)
			}
			if n := len([]rune(got)); n > 500 {
				t.Fatalf("pad %d: the reason is %d characters", pad, n)
			}
		}
	}
}

// A value with whitespace in it is found as it is, before the whitespace is collapsed: collapsed, it
// is no longer the value and would go through as a tidier copy of it.
func TestAValueWithWhitespaceInItIsScrubbedFromAReasonAsItIs(t *testing.T) {
	const value = "correct\thorse  battery\nstaple"
	r := redactorOf(t, value)
	got := job.CleanReason(r, "the field "+value+" was refused")
	if strings.Contains(got, "horse") || strings.Contains(got, "battery") || !strings.Contains(got, "[redacted]") {
		t.Errorf("reason = %q", got)
	}
}

// The same on the way a collector's own words take: a configuration issue's field and code.
func TestAConfigurationIssueWhoseFieldOrCodeIsTheCredentialInPiecesNeverReachesTheService(t *testing.T) {
	for _, sep := range []string{"\t", "\n", "  ", " "} {
		for _, where := range []string{`"issue_field_from_secret":true`, `"issue_code_from_secret":true`, `"issue_field_from_secret":true,"issue_code_from_secret":true`} {
			for _, pad := range []int{0, 60, 70, 75, 78, 79, 80, 81, 90} {
				r := newRig(t, nil)
				r.env["P"] = phrase
				cfg := fmt.Sprintf(`{"issue":"x","secret_file":"env:P",%s,"issue_sep":%q,"issue_pad":%d}`, where, sep, pad)
				_, why := aborted(t, r, fakeservice.Job{Collector: "testcollector", Config: cfg})
				for _, leak := range []string{phrase, "horse b", "st4ple", "battery"} {
					if strings.Contains(why, leak) {
						t.Fatalf("sep %q, %s, pad %d: %q is in what the service was told: %q", sep, where, pad, leak, why)
					}
				}
				for _, kind := range []string{phrase, strings.ReplaceAll(phrase, " ", sep)} {
					if bytes.Contains(r.svc.Everything(), []byte(kind)) {
						t.Fatalf("sep %q, %s, pad %d: %q reached the service", sep, where, pad, kind)
					}
				}
				if logged := r.logs.String(); strings.Contains(logged, phrase) || strings.Contains(logged, "st4ple") {
					t.Fatalf("sep %q, %s, pad %d: the credential is in the agent's log:\n%s", sep, where, pad, logged)
				}
			}
		}
	}
}

// The account of a stream that stood alone is its own: the earlier ones were let go by the service.
func TestTheAccountAfterAStreamThatRejectedItsCursorIsThatStreamsAlone(t *testing.T) {
	r := newRig(t, func(c *job.Config) { c.SpoolLimit = 90 << 10; c.RawTarget = 1 })
	cfg := `{"mode":"ok","records":8,"payload":20000,"checkpoint_every":1,"reject_cursor":true}`
	res, run := r.run(t, fakeservice.Job{Collector: "testcollector", Config: cfg})
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("the first stream: %v: %s", res.Outcome, res.Reason)
	}
	first := r.runner.Spent(run.ID())
	res = r.runner.Run(context.Background(), r.next(t))
	if res.Outcome != job.Uploaded || !res.EndedEarly {
		t.Fatalf("the second stream: %v: %s", res.Outcome, res.Reason)
	}
	// Each cut by the spool at about the same place: the account is one stream's worth, not two.
	if got := r.runner.Spent(run.ID()); got < 40<<10 || got > first+10<<10 {
		t.Errorf("spent = %d after two streams of about %d each, the second of which stood alone", got, first)
	}
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
