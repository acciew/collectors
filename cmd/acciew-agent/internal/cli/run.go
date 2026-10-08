package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/job"
	"go.acciew.io/collector/cmd/acciew-agent/internal/loop"
	"go.acciew.io/collector/cmd/acciew-agent/internal/pathid"
	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
	"go.acciew.io/collector/cmd/acciew-agent/internal/session"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
)

// defaultPassEnv is what a collector inherits of the agent's environment: how to reach the
// network and whom to trust there. Nothing else, and in particular no credential.
var defaultPassEnv = []string{
	"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// list is a repeatable flag that also takes a comma-separated list.
type list []string

func (l *list) String() string { return strings.Join(*l, ",") }
func (l *list) Set(v string) error {
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			*l = append(*l, item)
		}
	}
	return nil
}

func run(ctx context.Context, e Env) func(*flag.FlagSet) func() error {
	return func(fs *flag.FlagSet) func() error {
		dir := stateDirFlag(fs, e)
		collectors := fs.String("collectors-dir", "", "where acciew-collector-<name> programs are (default: the directory this program is in)")
		secretsDir := fs.String("secrets-dir", "", "where each run's secret files are made, dedicated to this agent (default: memory-backed /dev/shm where there is one)")
		var passEnv, secretEnv, secretPath list
		fs.Var(&passEnv, "pass-env", "an environment variable a collector may inherit, in addition to the proxy and certificate settings (repeatable)")
		fs.Var(&secretEnv, "secret-env", "an environment variable a job may name as env:NAME; once any is given, no other may be (repeatable)")
		fs.Var(&secretPath, "secret-path", "a directory a job may name files in as file:/path; once any is given, no other may be (repeatable)")
		allowAny := fs.Bool("allow-any-secret-reference", false,
			"DANGEROUS: let a job name any environment variable and any file this agent's user can read. The service writes the job, "+
				"and a collector sends its credential to the address the job names: with this, a compromised service can have your ssh key or "+
				"cloud credentials read and sent to a host it chooses. /proc, /sys, /dev and the agent's own directory stay refused")
		spoolMiB := fs.Int("spool-mib", job.DefaultSpoolLimit>>20, "the most one job's events may take on disk before the collection is cut at its last checkpoint")
		verbose := fs.Bool("verbose", false, "log each chunk and each heartbeat")
		return func() error {
			if *dir == "" {
				return usageError{"--state-dir is required: this host has no default"}
			}
			if *spoolMiB < 1 {
				return usageError{"--spool-mib is at least 1"}
			}
			policy := job.SecretsPolicy{
				LookupEnv: e.lookup, AllowEnv: secretEnv, AllowPaths: secretPath, AllowAny: *allowAny,
			}
			if err := policy.Validate(); err != nil {
				return usageError{err.Error()}
			}
			st, err := state.Load(*dir)
			if err != nil {
				return err
			}
			unlock, err := state.Lock(*dir)
			if err != nil {
				return err
			}
			defer unlock()

			collectorsDir, err := collectorsDirectory(*collectors)
			if err != nil {
				return err
			}
			secretsHome, err := secretsDirectory(*secretsDir, st)
			if err != nil {
				return err
			}
			policy.Tag = tagOf(st.Dir)
			if err := secrets.CleanStale(secretsHome, policy.Tag); err != nil {
				return fmt.Errorf("cleaning old secret files from %s: %w", secretsHome, err)
			}

			level := slog.LevelInfo
			if *verbose {
				level = slog.LevelDebug
			}
			log := slog.New(slog.NewTextHandler(e.Stderr, &slog.HandlerOptions{Level: level}))
			if info, err := os.Stat(collectorsDir); err == nil && info.Mode().Perm()&0o022 != 0 {
				log.Warn("the collectors directory can be written by others; whoever can write there can run code as this agent", "dir", collectorsDir)
			}

			c, err := client.New(st.URL, e.Version)
			if err != nil {
				return err
			}
			sess, err := session.New(c, st)
			if err != nil {
				return err
			}
			policy.Dir, policy.Forbidden = secretsHome, st.Contains
			switch {
			case *allowAny:
				log.Warn("--allow-any-secret-reference: a job may name any environment variable and any file this agent's user can read")
			case len(secretEnv) == 0 && len(secretPath) == 0:
				_, _ = fmt.Fprintln(e.Stdout, "No --secret-env or --secret-path was given, so a job that names a credential is given up: list what jobs may name.")
			}
			runner := job.New(job.Config{
				Client: c, Session: sess, CollectorsDir: collectorsDir, SpoolDir: st.SpoolDir(),
				Secrets:    policy,
				PassEnv:    append(append([]string{}, defaultPassEnv...), passEnv...),
				SpoolLimit: int64(*spoolMiB) << 20,
				Log:        log,
			})
			_, _ = fmt.Fprintf(e.Stdout, "acciew-agent %s running as %s against %s; collectors in %s\n", e.Version, st.AgentID, st.URL, collectorsDir)
			agent := &loop.Agent{Client: c, Session: sess, Runner: runner, SpoolDir: st.SpoolDir(), Out: e.Stdout, Log: log}
			if err := agent.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		}
	}
}

// collectorsDirectory is the flag, or the directory this program is in: an unpacked release
// holds the agent beside the collectors it runs.
func collectorsDirectory(flagValue string) (string, error) {
	dir := flagValue
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("finding the collectors directory: %w (give --collectors-dir)", err)
		}
		if linked, err := filepath.EvalSymlinks(exe); err == nil {
			exe = linked
		}
		dir = filepath.Dir(exe)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("the collectors directory %s is not a directory (--collectors-dir)", dir)
	}
	return filepath.Abs(dir)
}

// tagOf marks one agent's run directories, so that one agent's cleaning up after a crash leaves
// another's alone. It is of the state directory itself and not of its name, so that a restart
// that spells it another way (relative, through a link, in another case on a filesystem that
// ignores case) finds what the crash left.
func tagOf(stateDir string) string { return pathid.Tag(stateDir) }

// secretsDirectory is the directory each run's own directory is made in. A directory that is
// named must be the agent's own and private (it is made, if it is not there). Without one it is
// /dev/shm, memory, where nothing is made but a directory with a random name that the agent
// creates itself, or, where there is none, a directory in the state directory.
func secretsDirectory(flagValue string, st *state.State) (string, error) {
	switch {
	case flagValue != "":
		return flagValue, secrets.PrepareDir(flagValue)
	default:
		if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
			return "/dev/shm", nil
		}
		return st.RunDir(), secrets.PrepareDir(st.RunDir())
	}
}
