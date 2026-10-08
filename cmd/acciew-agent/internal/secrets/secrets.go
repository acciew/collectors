// Package secrets turns the references in a job's configuration into files a collector can
// read, on the host the agent runs on. A reference is a string that is exactly env:NAME or
// file:/path; the service never has the value, and neither does anything the agent sends it.
//
// The collector is started with none of the agent's environment, so an env: reference is read
// here and handed over as a file of its own in a directory made for the run: the form core's
// runner uses for a secret it holds. The directory is removed when the run ends.
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.acciew.io/collector/cmd/acciew-agent/internal/pathid"
	"go.acciew.io/collector/sdk/go/collector"
)

// maxSecret is the most a secret may be. A credential is a few kilobytes at most.
const maxSecret = 1 << 20

const (
	// MaxReferences is how many different references a job may spell, and MaxSecretsTotal how much all the
	// places they lead to may hold: a job is the service's to write, and a megabyte of configuration
	// can spell one file five thousand ways.
	MaxReferences   = 32
	MaxSecretsTotal = 4 << 20
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Policy is where references are resolved from, and what they may name.
type Policy struct {
	// LookupEnv reads the agent's own environment; nil is os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// Dir is where a run's directory is made; empty is the system's temporary directory.
	// Point it at a memory-backed filesystem where there is one.
	Dir string
	// Tag marks the run directories of one agent, so that cleaning up after a crash leaves another
	// agent's alone: a directory is acciew-run-<Tag>-<random>.
	Tag string
	// Forbidden says a file is not one a job may name: the agent's own directory.
	Forbidden func(path string) bool
	// Warn is told of what the agent chose not to do and went on without; nil is silence.
	Warn func(message string)
	// AllowEnv and AllowPaths are everything a job may name: the environment variables, and the
	// files (or directories, and what is under them) that the operator listed. The service writes
	// the configuration, so a reference that is not listed is refused: a collector sends its
	// credential to the address in the configuration, and an unlisted reference could be an
	// ssh key sent to a host of the service's choosing.
	AllowEnv   []string
	AllowPaths []string
	// AllowAny lifts the list, for an operator who has decided to trust the service with every
	// variable and every file the agent can read. /proc, /sys, /dev and the agent's own
	// directory are still refused.
	AllowAny bool
}

func (p *Policy) tagPart() string {
	if p.Tag == "" {
		return ""
	}
	return p.Tag + "-"
}

// neverUnder are places a job may not name whatever else is allowed: /proc/self/environ is
// the agent's whole environment, and the others are not credentials anyone keeps.
var neverUnder = []string{"/proc", "/sys", "/dev"}

// Bound is a configuration with its references resolved, and the means to clean up.
type Bound struct {
	// Config is what the collector is given.
	Config []byte
	// Redact scrubs resolved values, and the run's directory, out of any text.
	Redact *Redactor
	dir    string
}

// PrepareDir makes a directory that secret files may be made in, or says why the one that is
// there will not do. One that is not there is made, private. One that is there must be a real
// directory (not a link), owned by this user, that nobody else can enter: a directory that
// others can reach is a place they can read secrets in. It is not changed, since it is not
// the agent's to change.
func PrepareDir(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("making the secrets directory %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // a directory this agent just made, private to its owner
			return fmt.Errorf("making the secrets directory %s private: %w", path, err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("the secrets directory %s: %w", path, unwrapPath(err))
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("the secrets directory %s is a link: name the directory itself", path)
	case !info.IsDir():
		return fmt.Errorf("the secrets directory %s is not a directory", path)
	case info.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("the secrets directory %s can be entered by others (mode %o): run `chmod 700 %s`", path, info.Mode().Perm(), path)
	}
	if err := CheckOwner(info, uint32(os.Getuid())); err != nil { //nolint:gosec // a user id fits
		return fmt.Errorf("the secrets directory %s is %w", path, err)
	}
	return nil
}

// CleanStale removes the run directories a crash left in dir for the agent with this tag. They
// hold secret values, so they are not kept for anything: a job that was running is offered
// again and resolves its own. Another agent's directories (another tag) may be in use, and
// a link is not a directory the agent made: neither is touched.
func CleanStale(dir, tag string) error {
	pattern := "acciew-run-*"
	if tag != "" {
		pattern = "acciew-run-" + tag + "-*"
	}
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return err
	}
	var errs []error
	for _, m := range matches {
		info, err := os.Lstat(m)
		if err != nil || !info.IsDir() || CheckOwner(info, uint32(os.Getuid())) != nil { //nolint:gosec // a user id fits
			continue
		}
		errs = append(errs, os.RemoveAll(m))
	}
	return errors.Join(errs...)
}

// Dir is the directory the run's secret files are in; empty when there are none.
func (b *Bound) Dir() string { return b.dir }

// Close removes the run's directory and every secret in it.
func (b *Bound) Close() error {
	if b.dir == "" {
		return nil
	}
	dir := b.dir
	b.dir = ""
	return os.RemoveAll(dir)
}

// Bind resolves every reference in a JSON configuration. An error names the reference's
// target (a variable, a path) and never a value; it is safe to send to the service.
func (p *Policy) Bind(config []byte) (*Bound, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(config)) == 0 {
		return &Bound{Config: config, Redact: &Redactor{}}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(config))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("the configuration is not JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the configuration holds more than one JSON document")
	}

	var refs []string
	var problems []error
	walk(doc, func(s string) string {
		if isReference(s) && len(refs) <= MaxReferences && !slices.Contains(refs, s) {
			refs = append(refs, s)
		}
		return s
	})
	if len(refs) == 0 {
		return &Bound{Config: config, Redact: &Redactor{}}, nil
	}
	if len(refs) > MaxReferences {
		return nil, fmt.Errorf("the configuration names more than %d references (spelled differently, even if they lead to the same place): a job may name at most %d", MaxReferences, MaxReferences)
	}

	// Each place is read, held and written once, however many ways the job spells it.
	var keys []string
	byKey := map[string][]byte{}
	labelOf := map[string]string{} // the first reference to lead to a place names it
	keyOf := make(map[string]string, len(refs))
	total := 0
	for _, ref := range refs {
		v, key, err := p.resolve(ref)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		keyOf[ref] = key
		if _, seen := byKey[key]; !seen {
			if total += len(v); total > MaxSecretsTotal {
				return nil, fmt.Errorf("the references in the configuration lead to more than %d MiB of secrets in all", MaxSecretsTotal>>20)
			}
			byKey[key] = v
			labelOf[key] = ref
			keys = append(keys, key)
		}
	}
	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}

	// Everything the job names is watched for in what the collector sends, or the job is refused here,
	// before anything is written: nothing is left out to make room.
	redact := &Redactor{}
	for _, key := range keys {
		if err := redact.add(byKey[key], labelOf[key]); err != nil {
			return nil, err
		}
	}
	dir, err := os.MkdirTemp(p.Dir, "acciew-run-"+p.tagPart())
	if err != nil {
		return nil, fmt.Errorf("making a place for the run's secrets: %w", unwrapPath(err))
	}
	redact.dir = dir
	written := make(map[string]string, len(keys))
	for i, key := range keys {
		path := filepath.Join(dir, fmt.Sprintf("s%d", i))
		if err := writeSecret(path, byKey[key]); err != nil {
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("writing a secret for the run: %w", unwrapPath(err))
		}
		written[key] = "file:" + path
	}
	paths := make(map[string]string, len(refs))
	for _, ref := range refs {
		paths[ref] = written[keyOf[ref]]
	}
	walk(doc, func(s string) string {
		if to, ok := paths[s]; ok {
			return to
		}
		return s
	})
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &Bound{Config: bytes.TrimRight(out.Bytes(), "\n"), Redact: redact, dir: dir}, nil
}

func isReference(s string) bool {
	return strings.HasPrefix(s, "env:") || strings.HasPrefix(s, "file:")
}

// resolve reads a reference. The key says where the value came from, whatever the spelling: the
// variable, or the file with every link followed.
func (p *Policy) resolve(ref string) (value []byte, key string, err error) {
	// The SDK's own reading of a reference decides what is one: a collector will parse it the same way.
	if _, err := collector.ParseSecret(ref); err != nil {
		return nil, "", fmt.Errorf("%q is not a usable reference: %w", ref, err)
	}
	if name, ok := strings.CutPrefix(ref, "env:"); ok {
		value, err = p.fromEnv(name)
		return value, "env:" + name, err
	}
	return p.fromFile(strings.TrimPrefix(ref, "file:"))
}

func (p *Policy) fromEnv(name string) ([]byte, error) {
	if !envName.MatchString(name) {
		return nil, fmt.Errorf("%q is not the name of an environment variable", name)
	}
	if !p.AllowAny && !slices.Contains(p.AllowEnv, name) {
		return nil, fmt.Errorf("env:%s is not allowed: start the agent with --secret-env %s to let jobs name it", name, name)
	}
	lookup := p.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	v, ok := lookup(name)
	if !ok || v == "" {
		return nil, fmt.Errorf("the environment variable %s is empty or unset", name)
	}
	if len(v) > maxSecret {
		return nil, fmt.Errorf("the environment variable %s is too big for a secret", name)
	}
	return []byte(v), nil
}

func (p *Policy) fromFile(path string) ([]byte, string, error) {
	ref := "file:" + path
	if !filepath.IsAbs(path) {
		return nil, "", fmt.Errorf("%s is not an absolute path", ref)
	}
	path = filepath.Clean(path)
	// Before anything is looked at, so that what a refusal says does not depend on what exists.
	if p.never(path) {
		return nil, "", fmt.Errorf("%s is never something a job may name: it is the agent's own, or /proc, /sys or /dev", ref)
	}
	if !p.AllowAny && !p.within(path) {
		return nil, "", fmt.Errorf("%s is not allowed: start the agent with --secret-path set to the file or its directory to let jobs name it", ref)
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, "", fmt.Errorf("cannot read the secret file %s: %w", path, unwrapPath(err))
	}
	if p.never(target) {
		return nil, "", fmt.Errorf("%s is never something a job may name: it leads to the agent's own, or /proc, /sys or /dev", ref)
	}
	if !p.AllowAny && !p.within(target) {
		return nil, "", fmt.Errorf("%s is a link that leaves the files this agent was told jobs may name (--secret-path)", ref)
	}
	// Looked at before it is opened: opening a pipe waits for someone to write to it, and nothing here
	// can be stopped. Opened without blocking all the same, in case it is swapped for one in between.
	if info, err := os.Stat(target); err != nil || !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("%s is not a file", path)
	}
	f, err := openNoBlock(target)
	if err != nil {
		return nil, "", fmt.Errorf("cannot read the secret file %s: %w", path, unwrapPath(err))
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("%s is not a file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecret+1))
	if err != nil {
		return nil, "", fmt.Errorf("cannot read the secret file %s: %w", path, unwrapPath(err))
	}
	if len(data) > maxSecret {
		return nil, "", fmt.Errorf("the secret file %s is too big (over %d bytes)", path, maxSecret)
	}
	return data, "file:" + target, nil
}

// never says a path is one that no setting allows: /proc, /sys and /dev, the agent's own
// directory, and the directory the run's secret files are made in.
func (p *Policy) never(path string) bool {
	for _, prefix := range neverUnder {
		if inside(prefix, path) || pathid.Inside(prefix, path) {
			return true
		}
	}
	if p.Dir != "" {
		for _, dir := range []string{p.Dir, resolved(p.Dir)} {
			if inside(dir, path) {
				return true
			}
		}
		if pathid.Inside(p.Dir, path) {
			return true
		}
	}
	return p.Forbidden != nil && p.Forbidden(path)
}

// within says a path is the one the operator allowed, or under one of them, on the page and as
// the links stand.
func (p *Policy) within(path string) bool {
	for _, allowed := range p.AllowPaths {
		if inside(allowed, path) || inside(resolved(allowed), path) {
			return true
		}
	}
	return false
}

// inside says path is root or under it, by whole path elements.
func inside(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func resolved(path string) string {
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	return filepath.Clean(path)
}

// Validate refuses a policy that cannot mean what it says.
func (p *Policy) Validate() error {
	for _, allowed := range p.AllowPaths {
		if !filepath.IsAbs(allowed) {
			return fmt.Errorf("--secret-path %q is not an absolute path", allowed)
		}
	}
	for _, name := range p.AllowEnv {
		if !envName.MatchString(name) {
			return fmt.Errorf("--secret-env %q is not the name of an environment variable", name)
		}
	}
	return nil
}

// unwrapPath keeps the reason and drops the path an *os.PathError repeats.
func unwrapPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func writeSecret(path string, value []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the directory was made for this run
	if err != nil {
		return err
	}
	_, werr := f.Write(value)
	return errors.Join(werr, f.Close())
}

// walk replaces every string value in a decoded document with what f makes of it. Keys are not values.
func walk(v any, f func(string) string) any {
	switch x := v.(type) {
	case string:
		return f(x)
	case []any:
		for i := range x {
			x[i] = walk(x[i], f)
		}
	case map[string]any:
		for k := range x {
			x[k] = walk(x[k], f)
		}
	}
	return v
}
