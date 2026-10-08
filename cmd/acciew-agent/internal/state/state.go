// Package state is what the agent keeps on its host between runs: the service it
// belongs to, its id, and its private key. The key is a file only its owner can read.
package state

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/pathid"
)

const (
	keyFile    = "agent.key"
	nextFile   = "agent.key.next"
	configFile = "agent.json"
)

var (
	// ErrNotEnrolled is a directory with no enrolment in it.
	ErrNotEnrolled = errors.New("this agent is not enrolled")
	// ErrEnrolled is a directory that already holds one: enrolling again would replace a
	// key the service still trusts.
	ErrEnrolled = errors.New("this state directory already holds an enrolment")
)

// Config is what an enrolment stores beside the key.
type Config struct {
	URL         string `json:"url"`
	AgentID     string `json:"agent_id"`
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// State is an enrolled agent as the host holds it.
type State struct {
	Config
	Dir string
	Key ed25519.PrivateKey
	// Next is a key whose registration with the service is not known to have happened:
	// a rotation was begun and not finished.
	Next ed25519.PrivateKey
}

// Create stores a new enrolment. It never replaces one.
func Create(dir string, cfg Config, key ed25519.PrivateKey) error {
	// A directory that is already there is the operator's to have set up; the key file
	// is what protects the key.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("making the state directory: %w", err)
	}
	if Exists(dir) {
		return ErrEnrolled
	}
	if err := writeKey(filepath.Join(dir, keyFile), key, true); err != nil {
		return err
	}
	return writeConfig(dir, cfg)
}

// Exists says whether the directory already holds an enrolment, or what is left of one.
func Exists(dir string) bool {
	return exists(filepath.Join(dir, configFile)) || exists(filepath.Join(dir, keyFile))
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Load reads an enrolment. It refuses a key that anyone else can read.
func Load(dir string) (*State, error) {
	raw, err := os.ReadFile(filepath.Join(dir, configFile)) //nolint:gosec // the operator's own state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: run `acciew-agent enroll` (state directory %s)", ErrNotEnrolled, dir)
	}
	if err != nil {
		return nil, err
	}
	s := &State{Dir: dir}
	if err := json.Unmarshal(raw, &s.Config); err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Join(dir, configFile), err)
	}
	if s.URL == "" || s.AgentID == "" {
		return nil, fmt.Errorf("%s names no service or no agent", filepath.Join(dir, configFile))
	}
	if s.Key, err = readKey(filepath.Join(dir, keyFile)); err != nil {
		return nil, err
	}
	switch next, err := readKey(filepath.Join(dir, nextFile)); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		s.Next = next
	}
	return s, nil
}

// SpoolDir is where a job's frames wait for upload, and RunDir where a run's secret files
// go when no better place is given.
func (s *State) SpoolDir() string { return filepath.Join(s.Dir, "spool") }

// RunDir is described at SpoolDir.
func (s *State) RunDir() string { return filepath.Join(s.Dir, "run") }

// Contains says whether a path is inside the state directory, symbolic links followed.
// A job's configuration must not be able to point a collector at the agent's own key.
func (s *State) Contains(path string) bool {
	root := resolve(s.Dir)
	p := resolve(path)
	if rel, err := filepath.Rel(root, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	// Judged by what it is as well: another spelling of the directory (other case, on a filesystem
	// that ignores it) is the directory, and a hard link to the key is the key.
	if pathid.Inside(s.Dir, path) {
		return true
	}
	for _, name := range []string{keyFile, nextFile, configFile} {
		if pathid.Same(path, filepath.Join(s.Dir, name)) {
			return true
		}
	}
	return false
}

// resolve follows links as far as the path exists, then appends what does not.
func resolve(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	rest := ""
	for p := abs; ; p = filepath.Dir(p) {
		if linked, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(linked, rest)
		}
		if filepath.Dir(p) == p {
			return abs
		}
		rest = filepath.Join(filepath.Base(p), rest)
	}
}

// BeginRotation stores the key a rotation is about to register, beside the current one, so
// that a crash after the service accepted it cannot leave the agent holding neither.
func (s *State) BeginRotation(next ed25519.PrivateKey) error {
	if err := writeKey(filepath.Join(s.Dir, nextFile), next, false); err != nil {
		return err
	}
	s.Next = next
	return nil
}

// NextAge is how long the pending key has been waiting, to tell a rotation that is under way
// in another process from one that ended long ago.
func (s *State) NextAge() (time.Duration, bool) {
	info, err := os.Stat(filepath.Join(s.Dir, nextFile))
	if err != nil {
		return 0, false
	}
	return time.Since(info.ModTime()), true
}

// Reload reads the key and the pending key again, as another process (a rotation from another
// terminal) may have changed them, and says whether either did.
func (s *State) Reload() (bool, error) {
	fresh, err := Load(s.Dir)
	if err != nil {
		return false, err
	}
	same := fresh.Key.Equal(s.Key) && fresh.Next.Equal(s.Next) && (fresh.Next == nil) == (s.Next == nil)
	s.Config, s.Key, s.Next = fresh.Config, fresh.Key, fresh.Next
	return !same, nil
}

// CommitRotation makes the pending key the key. The rename is atomic: at every moment the
// key file holds one whole key. If another process already did it, that is as good.
func (s *State) CommitRotation(fingerprint string) error {
	if s.Next == nil {
		return errors.New("no rotation is pending")
	}
	if err := os.Rename(filepath.Join(s.Dir, nextFile), filepath.Join(s.Dir, keyFile)); err != nil {
		current, rerr := readKey(filepath.Join(s.Dir, keyFile))
		if !errors.Is(err, fs.ErrNotExist) || rerr != nil || !current.Equal(s.Next) {
			return fmt.Errorf("replacing the key: %w", err)
		}
	}
	s.Key, s.Next = s.Next, nil
	s.Fingerprint = fingerprint
	return writeConfig(s.Dir, s.Config)
}

// AbandonRotation drops a pending key the service never took.
func (s *State) AbandonRotation() error {
	err := os.Remove(filepath.Join(s.Dir, nextFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	s.Next = nil
	return nil
}

func writeConfig(dir string, cfg Config) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return replaceFile(filepath.Join(dir, configFile), append(raw, '\n'))
}

// replaceFile writes a file of 0600 whole or not at all.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func writeKey(path string, key ed25519.PrivateKey, exclusive bool) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if !exclusive {
		return replaceFile(path, data)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the operator's own state directory
	if err != nil {
		return fmt.Errorf("storing the key: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("storing the key: %w", err)
	}
	return f.Close()
}

func readKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("the key file %s can be read by others (mode %o): run `chmod 600 %s`, and if it may have been seen, rotate the key", path, info.Mode().Perm(), path)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's own state directory
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s is not a PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return key, nil
}
