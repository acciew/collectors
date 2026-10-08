package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/cli"
	"go.acciew.io/collector/cmd/acciew-agent/internal/fakeservice"
	"go.acciew.io/collector/cmd/acciew-agent/internal/pathid"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
	"go.acciew.io/collector/cmd/acciew-agent/internal/testbin"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testbin.Cleanup()
	os.Exit(code)
}

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = cli.Run(context.Background(), args, cli.Env{Version: "9.9.9", Stdout: &out, Stderr: &errb})
	return code, out.String(), errb.String()
}

// A downloaded agent has to say which build it is without a service to talk to,
// in the form the collectors use: "<name> <version>".
func TestAskedForItsVersionTheAgentSaysWhichBuildItIs(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		code, out, _ := run(t, args...)
		if code != 0 || out != "acciew-agent 9.9.9\n" {
			t.Errorf("%v: exit %d, printed %q", args, code, out)
		}
	}
}

func TestAnUnknownCommandIsRefusedWithUsage(t *testing.T) {
	code, out, errOut := run(t, "frobnicate")
	if code == 0 || out != "" || !strings.Contains(errOut, "frobnicate") || !strings.Contains(errOut, "enroll") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func runWith(t *testing.T, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = cli.Run(context.Background(), args, cli.Env{
		Version: "9.9.9", Stdout: &out, Stderr: &errb,
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
	})
	return code, out.String(), errb.String()
}

func TestEnrollThenRotateFromTheCommandLine(t *testing.T) {
	svc := fakeservice.New(t)
	svc.AddEnrolment("acc_enr_cli")
	dir := filepath.Join(t.TempDir(), "state")

	code, out, errOut := runWith(t, nil, "enroll", "--url", svc.URL(), "--token", "acc_enr_cli", "--name", "edge", "--state-dir", dir)
	if code != 0 || !strings.Contains(out, "Fingerprint:") {
		t.Fatalf("enroll: exit %d\n%s\n%s", code, out, errOut)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc.Confirm(st.AgentID)
	old := st.Key

	code, out, errOut = runWith(t, nil, "rotate", "--state-dir", dir)
	if code != 0 || !strings.Contains(out, "key is changed") {
		t.Fatalf("rotate: exit %d\n%s\n%s", code, out, errOut)
	}
	after, _ := state.Load(dir)
	if after.Key.Equal(old) {
		t.Error("the key was not replaced")
	}
}

func TestTheEnrolmentTokenMayComeFromTheEnvironmentSoItStaysOutOfTheProcessList(t *testing.T) {
	svc := fakeservice.New(t)
	svc.AddEnrolment("acc_enr_env")
	dir := filepath.Join(t.TempDir(), "state")
	code, _, errOut := runWith(t, map[string]string{"ACCIEW_ENROLMENT_TOKEN": "acc_enr_env"}, "enroll", "--url", svc.URL(), "--state-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestTheStateDirectoryMayComeFromTheEnvironment(t *testing.T) {
	svc := fakeservice.New(t)
	svc.AddEnrolment("t")
	dir := filepath.Join(t.TempDir(), "state")
	code, _, errOut := runWith(t, map[string]string{"ACCIEW_AGENT_STATE_DIR": dir}, "enroll", "--url", svc.URL(), "--token", "t")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if _, err := state.Load(dir); err != nil {
		t.Error(err)
	}
}

func TestMissingFlagsAreSaidBeforeAnythingIsDone(t *testing.T) {
	for _, args := range [][]string{
		{"enroll"},
		{"enroll", "--url", "https://acciew.example.test"},
		{"enroll", "--token", "t"},
		{"enroll", "--url", "https://x", "--token", "t", "extra"},
		{"rotate", "--bogus"},
	} {
		code, _, errOut := runWith(t, nil, args...)
		if code != 2 || errOut == "" {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
}

func TestAFailureIsPrintedWithoutAStackAndExitsNonZero(t *testing.T) {
	svc := fakeservice.New(t)
	code, out, errOut := runWith(t, nil, "enroll", "--url", svc.URL(), "--token", "wrong", "--state-dir", filepath.Join(t.TempDir(), "s"))
	if code != 1 || out != "" || !strings.Contains(errOut, "enrolment token") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestRotatingWithoutAnEnrolmentSaysToEnrolFirst(t *testing.T) {
	code, _, errOut := runWith(t, nil, "rotate", "--state-dir", filepath.Join(t.TempDir(), "nothing"))
	if code != 1 || !strings.Contains(errOut, "enroll") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

// ---- run

func enrolled(t *testing.T) (*fakeservice.Service, string) {
	t.Helper()
	svc := fakeservice.New(t)
	svc.Hold = 50 * time.Millisecond
	svc.AddEnrolment("t")
	dir := filepath.Join(t.TempDir(), "state")
	if code, _, errOut := runWith(t, nil, "enroll", "--url", svc.URL(), "--token", "t", "--state-dir", dir); code != 0 {
		t.Fatalf("enroll: %s", errOut)
	}
	st, _ := state.Load(dir)
	svc.Confirm(st.AgentID)
	return svc, dir
}

type running struct {
	cancel context.CancelFunc
	done   chan int
	out    *syncBuf
	err    *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func startRun(t *testing.T, env map[string]string, args ...string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan int, 1), out: &syncBuf{}, err: &syncBuf{}}
	go func() {
		r.done <- cli.Run(ctx, append([]string{"run"}, args...), cli.Env{
			Version: "9.9.9", Stdout: r.out, Stderr: r.err,
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		})
	}()
	t.Cleanup(cancel)
	return r
}

func (r *running) stop(t *testing.T) int {
	t.Helper()
	r.cancel()
	select {
	case code := <-r.done:
		return code
	case <-time.After(15 * time.Second):
		t.Fatal("run did not stop")
		return -1
	}
}

func until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 1500 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunTakesAJobFromTheServiceAndStopsCleanlyOnSIGINT(t *testing.T) {
	svc, dir := enrolled(t)
	run := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":3}`})
	r := startRun(t, nil, "--state-dir", dir, "--collectors-dir", testbin.Collectors(t), "--secrets-dir", privateDir(t))
	until(t, "the job", run.Final)
	if code := r.stop(t); code != 0 {
		t.Errorf("exit %d\n%s", code, r.err.String())
	}
	if !strings.Contains(r.out.String(), "acciew-agent 9.9.9") {
		t.Errorf("run should say what it is:\n%s", r.out.String())
	}
}

func TestRunRefusesAKeyOthersCanRead(t *testing.T) {
	_, dir := enrolled(t)
	if err := os.Chmod(filepath.Join(dir, "agent.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runWith(t, nil, "run", "--state-dir", dir, "--collectors-dir", t.TempDir())
	if code != 1 || !strings.Contains(errOut, "chmod 600") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestRunRefusesASecondAgentOnTheSameStateDirectory(t *testing.T) {
	_, dir := enrolled(t)
	first := startRun(t, nil, "--state-dir", dir, "--collectors-dir", t.TempDir())
	until(t, "the first to start", func() bool { return strings.Contains(first.out.String(), "acciew-agent") })
	code, _, errOut := runWith(t, nil, "run", "--state-dir", dir, "--collectors-dir", t.TempDir())
	if code != 1 || !strings.Contains(errOut, "another acciew-agent") {
		t.Errorf("exit %d: %s", code, errOut)
	}
	first.stop(t)
}

func TestRunNeedsACollectorsDirectoryThatIsOne(t *testing.T) {
	_, dir := enrolled(t)
	code, _, errOut := runWith(t, nil, "run", "--state-dir", dir, "--collectors-dir", filepath.Join(t.TempDir(), "missing"))
	if code != 1 || !strings.Contains(errOut, "collectors") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestRunPassesOnlyTheNamedVariablesAndOnlyTheNamedSecretsToCollectors(t *testing.T) {
	svc, dir := enrolled(t)
	env := map[string]string{"KC_SECRET": "v-for-the-collector", "OTHER_SECRET": "not-allowed", "MY_PROXY_SETTING": "x"}
	allowed := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"secret_file":"env:KC_SECRET","env_probe":["MY_PROXY_SETTING","OTHER_SECRET"]}`})
	refused := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","secret_file":"env:OTHER_SECRET"}`})
	r := startRun(t, env, "--state-dir", dir, "--collectors-dir", testbin.Collectors(t), "--secrets-dir", privateDir(t),
		"--pass-env", "MY_PROXY_SETTING", "--secret-env", "KC_SECRET")
	until(t, "both jobs", func() bool { return allowed.Final() && refused.Aborted() != "" })
	if !strings.Contains(refused.Aborted(), "OTHER_SECRET") || strings.Contains(refused.Aborted(), "not-allowed") {
		t.Errorf("reason %q", refused.Aborted())
	}
	events, _ := allowed.Events()
	seen := map[string]string{}
	for _, e := range events {
		if d := e.GetDiagnostic(); d.GetCode() == "test.env" {
			k, v, _ := strings.Cut(d.GetMessage(), "=")
			seen[k] = v
		}
	}
	if seen["MY_PROXY_SETTING"] != "present" || seen["OTHER_SECRET"] != "absent" {
		t.Errorf("collector environment: %v", seen)
	}
	r.stop(t)
}

func TestNoCommandAndHelpPrintUsage(t *testing.T) {
	if code, out, errOut := run(t); code != 2 || out != "" || !strings.Contains(errOut, "usage:") {
		t.Errorf("no command: exit %d, %q, %q", code, out, errOut)
	}
	for _, arg := range []string{"help", "-h", "--help"} {
		if code, out, _ := run(t, arg); code != 0 || !strings.Contains(out, "enroll") {
			t.Errorf("%s: exit %d, %q", arg, code, out)
		}
	}
	if code, _, errOut := run(t, "enroll", "-h"); code != 0 || !strings.Contains(errOut, "-url") {
		t.Errorf("enroll -h: exit %d, %q", code, errOut)
	}
}

func TestACommandThatNeedsAStateDirectoryAndHasNoneSaysSo(t *testing.T) {
	for _, args := range [][]string{
		{"enroll", "--url", "https://x", "--token", "t", "--state-dir", ""},
		{"rotate", "--state-dir", ""},
		{"run", "--state-dir", ""},
	} {
		code, _, errOut := runWith(t, nil, args...)
		if code != 2 || !strings.Contains(errOut, "--state-dir is required") {
			t.Errorf("%v: exit %d, %q", args, code, errOut)
		}
	}
	if code, _, errOut := runWith(t, nil, "run", "--state-dir", t.TempDir(), "--spool-mib", "0"); code != 2 || !strings.Contains(errOut, "--spool-mib") {
		t.Errorf("--spool-mib 0: exit %d, %q", code, errOut)
	}
}

func TestRunWithoutAnEnrolmentSaysToEnrolFirst(t *testing.T) {
	code, _, errOut := runWith(t, nil, "run", "--state-dir", filepath.Join(t.TempDir(), "nothing"), "--collectors-dir", t.TempDir())
	if code != 1 || !strings.Contains(errOut, "enroll") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestRunTellsOfACollectorsDirectoryOthersCanWrite(t *testing.T) {
	_, dir := enrolled(t)
	collectors := t.TempDir()
	if err := os.Chmod(collectors, 0o777); err != nil {
		t.Fatal(err)
	}
	r := startRun(t, nil, "--state-dir", dir, "--collectors-dir", collectors, "--secrets-dir", privateDir(t))
	until(t, "the warning", func() bool { return strings.Contains(r.err.String(), "can be written by others") })
	r.stop(t)
}

func TestRunWithNoCollectorsDirectoryUsesTheOneItsProgramIsIn(t *testing.T) {
	_, dir := enrolled(t)
	r := startRun(t, nil, "--state-dir", dir, "--secrets-dir", privateDir(t))
	exe, _ := os.Executable()
	if linked, err := filepath.EvalSymlinks(exe); err == nil {
		exe = linked
	}
	until(t, "the start line", func() bool { return strings.Contains(r.out.String(), "collectors in "+filepath.Dir(exe)) })
	r.stop(t)
}

func TestRunWithNoSecretsDirectoryMakesAPrivateOne(t *testing.T) {
	_, dir := enrolled(t)
	r := startRun(t, nil, "--state-dir", dir, "--collectors-dir", t.TempDir())
	until(t, "the start line", func() bool { return strings.Contains(r.out.String(), "running as") })
	r.stop(t)
	if _, err := os.Stat("/dev/shm"); err != nil {
		if info, err := os.Stat(filepath.Join(dir, "run")); err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Errorf("the run directory: %v %v", info, err)
		}
	}
}

func TestRunThatCannotMakeItsSecretsDirectoryOrCleanItSaysSo(t *testing.T) {
	_, dir := enrolled(t)
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	code, _, errOut := runWith(t, nil, "run", "--state-dir", dir, "--collectors-dir", t.TempDir(), "--secrets-dir", filepath.Join(blocker, "x"))
	if code != 1 || !strings.Contains(errOut, "secrets directory") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestARevokedAgentRunExitsNonZeroAndSaysWhy(t *testing.T) {
	svc, dir := enrolled(t)
	st, _ := state.Load(dir)
	svc.Revoke(st.AgentID)
	code, _, errOut := runWith(t, nil, "run", "--state-dir", dir, "--collectors-dir", t.TempDir(), "--secrets-dir", privateDir(t))
	if code != 1 || !strings.Contains(errOut, "revoked") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestACollectorsDirectoryThatIsAFileIsRefused(t *testing.T) {
	_, dir := enrolled(t)
	file := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(file, []byte("x"), 0o600)
	code, _, errOut := runWith(t, nil, "run", "--state-dir", dir, "--collectors-dir", file)
	if code != 1 || !strings.Contains(errOut, "is not a directory") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestTheRepeatableFlagsTakeCommaSeparatedValuesToo(t *testing.T) {
	svc, dir := enrolled(t)
	env := map[string]string{"A_ONE": "1", "B_TWO": "2"}
	run := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"env_probe":["A_ONE","B_TWO"]}`})
	r := startRun(t, env, "--state-dir", dir, "--collectors-dir", testbin.Collectors(t), "--secrets-dir", privateDir(t), "--pass-env", "A_ONE, B_TWO,,")
	until(t, "the job", run.Final)
	events, _ := run.Events()
	seen := map[string]string{}
	for _, e := range events {
		if d := e.GetDiagnostic(); d.GetCode() == "test.env" {
			k, v, _ := strings.Cut(d.GetMessage(), "=")
			seen[k] = v
		}
	}
	if seen["A_ONE"] != "present" || seen["B_TWO"] != "present" {
		t.Errorf("collector environment: %v", seen)
	}
	r.stop(t)
}

// Nobody has said what a job may name, so it may name nothing: the agent starts, says so, and
// gives up a job that names a credential, naming the reference and the flag that would allow it.
func TestWithNoListOfWhatAJobMayNameAJobThatNamesACredentialIsGivenUp(t *testing.T) {
	svc, dir := enrolled(t)
	env := map[string]string{"KC_SECRET": "a-credential-value-1234"}
	run := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","token":"env:KC_SECRET"}`})
	r := startRun(t, env, "--state-dir", dir, "--collectors-dir", testbin.Collectors(t), "--secrets-dir", privateDir(t))
	until(t, "the abort", func() bool { return run.Aborted() != "" })
	if !strings.Contains(run.Aborted(), "env:KC_SECRET") || !strings.Contains(run.Aborted(), "--secret-env KC_SECRET") || strings.Contains(run.Aborted(), "a-credential-value-1234") {
		t.Errorf("reason %q", run.Aborted())
	}
	if !strings.Contains(r.out.String(), "No --secret-env or --secret-path") {
		t.Errorf("the agent should say at the start that jobs may name nothing:\n%s", r.out.String())
	}
	r.stop(t)
}

func TestTheOptOutIsNamedForWhatItDoesAndTheAgentSaysItIsOn(t *testing.T) {
	svc, dir := enrolled(t)
	env := map[string]string{"KC_SECRET": "a-credential-value-1234"}
	run := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"secret_file":"env:KC_SECRET"}`})
	r := startRun(t, env, "--state-dir", dir, "--collectors-dir", testbin.Collectors(t), "--secrets-dir", privateDir(t), "--allow-any-secret-reference")
	until(t, "the job", run.Final)
	until(t, "the warning", func() bool { return strings.Contains(r.err.String(), "--allow-any-secret-reference") })
	r.stop(t)
}

func TestAListThatCannotMeanWhatItSaysIsRefusedAtStart(t *testing.T) {
	_, dir := enrolled(t)
	for _, args := range [][]string{
		{"--secret-path", "relative/dir"},
		{"--secret-env", "NOT A NAME"},
	} {
		code, _, errOut := runWith(t, nil, append([]string{"run", "--state-dir", dir, "--collectors-dir", t.TempDir()}, args...)...)
		if code != 2 || errOut == "" {
			t.Errorf("%v: exit %d, %q", args, code, errOut)
		}
	}
}

// A path listed as one file or a directory, and /proc/self/environ named by a job that has only
// been allowed variables.
func TestAFileOutsideTheListedPathsAndProcSelfEnvironAreGivenUp(t *testing.T) {
	svc, dir := enrolled(t)
	listed := t.TempDir()
	good := filepath.Join(listed, "kc")
	_ = os.WriteFile(good, []byte("a-credential-value-1234"), 0o600)
	elsewhere := filepath.Join(t.TempDir(), "other")
	_ = os.WriteFile(elsewhere, []byte("another-credential-98765"), 0o600)
	ok := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1,"secret_file":"file:` + good + `"}`})
	outside := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","secret_file":"file:` + elsewhere + `"}`})
	proc := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","secret_file":"file:/proc/self/environ"}`})
	r := startRun(t, nil, "--state-dir", dir, "--collectors-dir", testbin.Collectors(t), "--secrets-dir", privateDir(t),
		"--secret-path", listed, "--secret-env", "KC_SECRET")
	until(t, "the three jobs", func() bool { return ok.Final() && outside.Aborted() != "" && proc.Aborted() != "" })
	if !strings.Contains(outside.Aborted(), "--secret-path") || strings.Contains(outside.Aborted(), "another-credential-98765") {
		t.Errorf("reason %q", outside.Aborted())
	}
	if !strings.Contains(proc.Aborted(), "never") {
		t.Errorf("reason %q", proc.Aborted())
	}
	r.stop(t)
}

// privateDir is a temporary directory only its owner can enter, as an agent's secrets directory must be.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestASecretsDirectoryOthersCanEnterOrThatIsALinkIsRefusedAtStart(t *testing.T) {
	_, dir := enrolled(t)
	root := t.TempDir()
	open := filepath.Join(root, "open")
	_ = os.Mkdir(open, 0o755)
	_ = os.Chmod(open, 0o755)
	good := privateDir(t)
	link := filepath.Join(root, "link")
	_ = os.Symlink(good, link)
	for name, c := range map[string]struct{ path, want string }{"open": {open, "chmod 700"}, "link": {link, "is a link"}} {
		code, _, errOut := runWith(t, nil, "run", "--state-dir", dir, "--collectors-dir", t.TempDir(), "--secrets-dir", c.path)
		if code != 1 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: exit %d: %s", name, code, errOut)
		}
	}
}

func TestASecretsDirectoryThatIsNotThereIsMadePrivateAndOldRunDirectoriesOfThisAgentInItAreRemoved(t *testing.T) {
	svc, dir := enrolled(t)
	secretsDir := filepath.Join(t.TempDir(), "made", "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(dir)
	stale := filepath.Join(secretsDir, "acciew-run-"+cliTag(st.Dir)+"-left")
	_ = os.Mkdir(stale, 0o700)
	_ = os.WriteFile(filepath.Join(stale, "s0"), []byte("a-secret-a-crash-left"), 0o600)
	other := filepath.Join(secretsDir, "acciew-run-ffffffff-theirs")
	_ = os.Mkdir(other, 0o700)

	run := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","records":1}`})
	r := startRun(t, nil, "--state-dir", dir, "--collectors-dir", testbin.Collectors(t), "--secrets-dir", secretsDir)
	until(t, "the job", run.Final)
	r.stop(t)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("what a crash left was kept")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("another agent's directory was removed")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(secretsDir), "secrets")); err != nil {
		t.Error(err)
	}
}

// cliTag is the tag the command line gives an agent's run directories.
func cliTag(stateDir string) string { return pathid.Tag(stateDir) }

// The agent's key, named in another case on a filesystem that ignores case, is still the key,
// even for an operator who has turned the lists off.
func TestTheKeyIsNotHandedOverUnderAnotherSpellingOfItsPath(t *testing.T) {
	svc := fakeservice.New(t)
	svc.Hold = 50 * time.Millisecond
	svc.AddEnrolment("t")
	dir := filepath.Join(t.TempDir(), "Agent State")
	if code, _, errOut := runWith(t, nil, "enroll", "--url", svc.URL(), "--token", "t", "--state-dir", dir); code != 0 {
		t.Fatal(errOut)
	}
	st, _ := state.Load(dir)
	svc.Confirm(st.AgentID)
	respelled := filepath.Join(strings.ToUpper(dir), "AGENT.KEY")
	if _, err := os.Stat(respelled); err != nil {
		t.Skip("this filesystem tells cases apart")
	}
	run := svc.Queue(fakeservice.Job{Collector: "testcollector", Config: `{"mode":"ok","secret_file":"file:` + respelled + `"}`})
	r := startRun(t, nil, "--state-dir", dir, "--collectors-dir", testbin.Collectors(t), "--secrets-dir", privateDir(t), "--allow-any-secret-reference")
	until(t, "the abort", func() bool { return run.Aborted() != "" })
	if !strings.Contains(run.Aborted(), "never") {
		t.Errorf("reason %q", run.Aborted())
	}
	r.stop(t)
}

// A crash leaves the run's secret files in a directory tagged by the agent's state directory. The
// state directory spelled differently the next time (relative, through a link) is the same one.
func TestLeftoversAreFoundAgainWhenTheStateDirectoryIsSpelledDifferently(t *testing.T) {
	svc := fakeservice.New(t)
	svc.Hold = 50 * time.Millisecond
	svc.AddEnrolment("t")
	collectors := testbin.Collectors(t) // built from the module, before the working directory moves
	home := t.TempDir()
	t.Chdir(home)
	if code, _, errOut := runWith(t, nil, "enroll", "--url", svc.URL(), "--token", "t", "--state-dir", "state"); code != 0 {
		t.Fatal(errOut)
	}
	abs := filepath.Join(home, "state")
	st, _ := state.Load(abs)
	svc.Confirm(st.AgentID)
	secretsDir := privateDir(t)
	stale := filepath.Join(secretsDir, "acciew-run-"+cliTag(abs)+"-crashed")
	_ = os.Mkdir(stale, 0o700)
	_ = os.WriteFile(filepath.Join(stale, "s0"), []byte("left by a crash"), 0o600)

	// Started again, by a relative name.
	r := startRun(t, nil, "--state-dir", "state", "--collectors-dir", collectors, "--secrets-dir", secretsDir)
	until(t, "the leftover to go", func() bool { _, err := os.Stat(stale); return os.IsNotExist(err) })
	r.stop(t)
}

// On a filesystem that ignores case, the same directory in another case is the same directory, and
// the secrets a crash left are still found.
func TestLeftoversAreFoundAgainWhenTheStateDirectoryIsSpelledInAnotherCase(t *testing.T) {
	svc := fakeservice.New(t)
	svc.Hold = 50 * time.Millisecond
	svc.AddEnrolment("t")
	dir := filepath.Join(t.TempDir(), "Agent State")
	if code, _, errOut := runWith(t, nil, "enroll", "--url", svc.URL(), "--token", "t", "--state-dir", dir); code != 0 {
		t.Fatal(errOut)
	}
	respelled := filepath.Join(filepath.Dir(dir), "agent state")
	if _, err := os.Stat(respelled); err != nil {
		t.Skip("this filesystem tells cases apart")
	}
	st, _ := state.Load(dir)
	svc.Confirm(st.AgentID)
	secretsDir := privateDir(t)
	stale := filepath.Join(secretsDir, "acciew-run-"+cliTag(dir)+"-crashed")
	_ = os.Mkdir(stale, 0o700)
	_ = os.WriteFile(filepath.Join(stale, "s0"), []byte("left by a crash"), 0o600)

	r := startRun(t, nil, "--state-dir", respelled, "--collectors-dir", testbin.Collectors(t), "--secrets-dir", secretsDir)
	until(t, "the leftover to go", func() bool { _, err := os.Stat(stale); return os.IsNotExist(err) })
	r.stop(t)
}
