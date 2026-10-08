// Package cli is the agent's command line: enroll, run, rotate and version.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.acciew.io/collector/cmd/acciew-agent/internal/lifecycle"
)

// Env is what the commands are given, so that a test can run them without a terminal.
type Env struct {
	Version        string
	Stdout, Stderr io.Writer
	// LookupEnv reads the environment; nil is os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

func (e Env) lookup(k string) (string, bool) {
	if e.LookupEnv != nil {
		return e.LookupEnv(k)
	}
	return os.LookupEnv(k)
}

func (e Env) getenv(k string) string {
	v, _ := e.lookup(k)
	return v
}

const usage = `usage: acciew-agent <command> [flags]

  enroll   register this agent with the service (--url, --token)
  run      ask the service for work, run collectors, upload what they find
  rotate   change this agent's key
  version  print the version

Run "acciew-agent <command> -h" for a command's flags.
`

// Run runs one command and returns the process's exit code: 0 done, 1 failed, 2 misused.
func Run(ctx context.Context, args []string, e Env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(e.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		_, _ = fmt.Fprintf(e.Stdout, "acciew-agent %s\n", e.Version)
		return 0
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(e.Stdout, usage)
		return 0
	case "enroll":
		return command(e, "enroll", args[1:], enroll(ctx, e))
	case "rotate":
		return command(e, "rotate", args[1:], rotate(ctx, e))
	case "run":
		return command(e, "run", args[1:], run(ctx, e))
	}
	_, _ = fmt.Fprintf(e.Stderr, "acciew-agent: %q is not a command\n\n%s", args[0], usage)
	return 2
}

// errUsage is a mistake in how the command was called, as opposed to a failure of what it did.
var errUsage = errors.New("usage")

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }
func (usageError) Is(t error) bool { return t == errUsage }

// command parses a command's flags and runs it.
func command(e Env, name string, args []string, c func(fs *flag.FlagSet) func() error) int {
	fs := flag.NewFlagSet("acciew-agent "+name, flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	run := c(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(e.Stderr, "acciew-agent %s: unexpected argument %q\n", name, fs.Arg(0))
		return 2
	}
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(e.Stderr, "acciew-agent %s: %v\n", name, err)
		if errors.Is(err, errUsage) {
			return 2
		}
		return 1
	}
	return 0
}

// stateDirFlag is the one flag every command shares.
func stateDirFlag(fs *flag.FlagSet, e Env) *string {
	def := e.getenv("ACCIEW_AGENT_STATE_DIR")
	if def == "" {
		if dir, err := os.UserConfigDir(); err == nil {
			def = filepath.Join(dir, "acciew-agent")
		}
	}
	return fs.String("state-dir", def, "where the agent keeps its key and its enrolment (env ACCIEW_AGENT_STATE_DIR)")
}

func enroll(ctx context.Context, e Env) func(*flag.FlagSet) func() error {
	return func(fs *flag.FlagSet) func() error {
		url := fs.String("url", "", "the service's address, https://... (required)")
		token := fs.String("token", "", "the single-use enrolment token (or env ACCIEW_ENROLMENT_TOKEN, which keeps it out of the process list)")
		name := fs.String("name", "", "a name to show in the service (default: this host's name)")
		dir := stateDirFlag(fs, e)
		return func() error {
			tok := *token
			if tok == "" {
				tok = e.getenv("ACCIEW_ENROLMENT_TOKEN")
			}
			switch {
			case *url == "":
				return usageError{"--url is required"}
			case tok == "":
				return usageError{"--token is required"}
			case *dir == "":
				return usageError{"--state-dir is required: this host has no default"}
			}
			return lifecycle.Enroll(ctx, lifecycle.Enrollment{
				URL: *url, Token: tok, Name: *name, StateDir: *dir, Version: e.Version, Out: e.Stdout,
			})
		}
	}
}

func rotate(ctx context.Context, e Env) func(*flag.FlagSet) func() error {
	return func(fs *flag.FlagSet) func() error {
		dir := stateDirFlag(fs, e)
		return func() error {
			if *dir == "" {
				return usageError{"--state-dir is required: this host has no default"}
			}
			return lifecycle.Rotate(ctx, lifecycle.RotationOf{StateDir: *dir, Version: e.Version, Out: e.Stdout})
		}
	}
}
