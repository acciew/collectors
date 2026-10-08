package host_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	pluginv1 "go.acciew.io/collector/api/plugin/v1"
	"go.acciew.io/collector/cmd/acciew-agent/internal/host"
	"go.acciew.io/collector/cmd/acciew-agent/internal/testbin"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testbin.Cleanup()
	os.Exit(code)
}

func launch(t *testing.T, env []string) *host.Plugin {
	t.Helper()
	dir := testbin.Collectors(t)
	p, err := host.Launch(context.Background(), filepath.Join(dir, "acciew-collector-testcollector"), host.Options{Env: env, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func drain(t *testing.T, s collectorv1.CollectorService_CollectClient) []*collectorv1.CollectResponse {
	t.Helper()
	var out []*collectorv1.CollectResponse
	for {
		e, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		out = append(out, e)
	}
}

func TestACollectorIsLaunchedNamedAndAskedForItsInventory(t *testing.T) {
	p := launch(t, host.ChildEnv(nil, nil))
	if p.Name != "testcollector" || p.Version != "0.0.1" {
		t.Errorf("%q %q", p.Name, p.Version)
	}
	issues, err := p.ValidateConfig(context.Background(), []byte(`{"mode":"ok"}`))
	if err != nil || len(issues) != 0 {
		t.Fatalf("ValidateConfig: %v %v", issues, err)
	}
	issues, err = p.ValidateConfig(context.Background(), []byte(`{"issue":"nope"}`))
	if err != nil || len(issues) != 1 || issues[0].GetCode() != "test.issue" {
		t.Errorf("ValidateConfig with an issue: %v %v", issues, err)
	}
	s, err := p.Collect(context.Background(), &collectorv1.CollectRequest{Config: []byte(`{"mode":"ok","records":3}`)})
	if err != nil {
		t.Fatal(err)
	}
	events := drain(t, s)
	last := events[len(events)-1].GetCompletion()
	if last == nil || last.GetVerdict() != collectorv1.Verdict_VERDICT_COMPLETE || last.GetCounts().GetIdentities() != 3 {
		t.Errorf("last event = %v", events[len(events)-1])
	}
}

// The collector gets none of the agent's environment: what the agent holds is not the
// collector's to read.
func TestACollectorIsStartedWithTheEnvironmentItIsGivenAndNoMore(t *testing.T) {
	t.Setenv("AGENT_ONLY_SECRET", "x")
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
	p := launch(t, host.ChildEnv([]string{"HTTPS_PROXY", "NOT_SET_HERE"}, nil))
	s, err := p.Collect(context.Background(), &collectorv1.CollectRequest{
		Config: []byte(`{"mode":"ok","env_probe":["AGENT_ONLY_SECRET","HTTPS_PROXY","NOT_SET_HERE","PATH","HOME"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, e := range drain(t, s) {
		if d := e.GetDiagnostic(); d.GetCode() == "test.env" {
			k, v, _ := strings.Cut(d.GetMessage(), "=")
			seen[k] = v
		}
	}
	for k, want := range map[string]string{"AGENT_ONLY_SECRET": "absent", "HTTPS_PROXY": "present", "NOT_SET_HERE": "absent", "PATH": "present", "HOME": "absent"} {
		if seen[k] != want {
			t.Errorf("%s is %q in the collector, want %q", k, seen[k], want)
		}
	}
}

func TestChildEnvIsAPathAndTheNamesThatAreSet(t *testing.T) {
	lookup := func(k string) (string, bool) { v, ok := map[string]string{"A": "1", "B": ""}[k]; return v, ok }
	got := host.ChildEnv([]string{"A", "B", "C"}, lookup)
	want := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "A=1", "B="}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("ChildEnv = %v, want %v", got, want)
	}
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func TestClosingStopsTheCollectorProcess(t *testing.T) {
	dir := testbin.Collectors(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	p, err := host.Launch(context.Background(), filepath.Join(dir, "acciew-collector-testcollector"), host.Options{Env: host.ChildEnv(nil, nil), Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{"mode":"slow","records":1000,"delay_ms":50,"pid_file":"` + pidFile + `"}`
	if _, err := p.Collect(context.Background(), &collectorv1.CollectRequest{Config: []byte(cfg)}); err != nil {
		t.Fatal(err)
	}
	var pid int
	for range 100 {
		if b, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(string(b))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid == 0 || !alive(pid) {
		t.Fatalf("the collector is not running (pid %d)", pid)
	}
	p.Close()
	for range 100 {
		if !alive(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("process %d is still running after Close", pid)
}

func TestSomethingThatIsNotACollectorIsRefusedWithAReason(t *testing.T) {
	for _, bin := range []string{"/usr/bin/true", "/bin/true", "/usr/bin/false", "/bin/echo"} {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		start := time.Now()
		_, err := host.Launch(context.Background(), bin, host.Options{Env: host.ChildEnv(nil, nil), StartTimeout: 10 * time.Second})
		if err == nil {
			t.Errorf("%s was accepted as a collector", bin)
		}
		if time.Since(start) > 9*time.Second {
			t.Errorf("%s took %v to refuse", bin, time.Since(start))
		}
		return
	}
	t.Skip("no simple executable to try")
}

func TestABinaryThatOffersAnotherKindIsRefusedNamingBothSides(t *testing.T) {
	err := host.CheckOffering(&pluginv1.HelloResponse{
		PluginName: "exporter-x",
		Offerings:  []*pluginv1.Offering{{Kind: "exporter", ProtocolVersion: 1}, {Kind: "collector", ProtocolVersion: 2}},
	})
	if err == nil || !strings.Contains(err.Error(), "exporter/1") || !strings.Contains(err.Error(), "collector/2") || !strings.Contains(err.Error(), "collector/1") {
		t.Errorf("err = %v", err)
	}
	if err := host.CheckOffering(&pluginv1.HelloResponse{Offerings: []*pluginv1.Offering{{Kind: "collector", ProtocolVersion: 1}}}); err != nil {
		t.Errorf("a collector/1 was refused: %v", err)
	}
}

func TestAnIssueThatBreaksTheContractIsAViolationNotAnIssue(t *testing.T) {
	if vs := host.ConfigIssueViolations([]*collectorv1.ConfigIssue{{Severity: collectorv1.Severity_SEVERITY_ERROR}}); len(vs) == 0 {
		t.Error("an issue with no code and no message passed")
	}
}

func TestAValidatorThatFailsOrBreaksTheContractIsReportedAsThat(t *testing.T) {
	p := launch(t, host.ChildEnv(nil, nil))
	if _, err := p.ValidateConfig(context.Background(), []byte(`{"fail_validate":true}`)); err == nil || !strings.Contains(err.Error(), "the validator is broken") || strings.Contains(err.Error(), "rpc error") {
		t.Errorf("a failing validator: %v (the collector's own words, without the transport's envelope)", err)
	}
	if _, err := p.ValidateConfig(context.Background(), []byte(`{"bad_issue":true}`)); err == nil || !strings.Contains(err.Error(), "broke the contract") {
		t.Errorf("an issue with no code or message: %v", err)
	}
}

func TestACollectionThatCannotStartSaysSo(t *testing.T) {
	p := launch(t, host.ChildEnv(nil, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, err := p.Collect(ctx, &collectorv1.CollectRequest{Config: []byte(`{}`)})
	if err == nil {
		_, err = s.Recv()
	}
	if err == nil {
		t.Error("a collection was started on a context that was already over")
	}
	if got := host.Plain(errors.New("x")); got.Error() != "x" {
		t.Errorf("Plain changed a plain error: %v", got)
	}
}

func TestABinaryThatOffersAnotherContractIsRefusedAtLaunch(t *testing.T) {
	dir := testbin.Collectors(t)
	env := append(host.ChildEnv(nil, nil), "TESTCOLLECTOR_OFFER=error")
	if _, err := host.Launch(context.Background(), filepath.Join(dir, "acciew-collector-testcollector"), host.Options{Env: env, Dir: dir}); err == nil || !strings.Contains(err.Error(), "the handshake is broken") {
		t.Errorf("a handshake that fails: %v", err)
	}
	for _, offer := range []string{"exporter", "nothing"} {
		env := append(host.ChildEnv(nil, nil), "TESTCOLLECTOR_OFFER="+offer)
		_, err := host.Launch(context.Background(), filepath.Join(dir, "acciew-collector-testcollector"), host.Options{Env: env, Dir: dir})
		if err == nil || !strings.Contains(err.Error(), "this agent speaks collector/1") {
			t.Errorf("%s: %v", offer, err)
		}
	}
}
