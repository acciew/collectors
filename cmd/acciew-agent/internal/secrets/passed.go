package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SecretVariable says a variable passed to a collector holds a credential by its name: a password, a
// secret, a token, a key, by the words of the name (AWS_SECRET_ACCESS_KEY, DB_PASSWORD, GITHUB_TOKEN)
// and not AWS_ACCESS_KEY_ID or COUNTRY_CODE, which are settings or identifiers.
func SecretVariable(name string) bool {
	switch classOfName(name) {
	case strongName, looseName:
		return true
	}
	words := nameWords(name)
	return len(words) > 0 && strings.EqualFold(words[len(words)-1], "key")
}

// AddVariable makes the value of a variable passed to a collector one to look for, as a reference's
// value is, when its name says it is a credential; and the password of an address, whatever the
// variable is called. A path or a key id under a name that is a token's is not the token.
func (r *Redactor) AddVariable(name, value string) error {
	source := "env:" + name
	if SecretVariable(name) && !ordinary(value) {
		if class := classOfName(name); class == strongName || (!isPath(value) && !awsKeyID.MatchString(value)) {
			if err := r.add([]byte(value), source); err != nil {
				return err
			}
		}
	}
	return r.AddURLCredentials(source, value)
}

// awsFiles are the variables that say where the AWS SDK reads its keys from, and where it looks when
// they are not set: under HOME.
var awsFiles = []struct{ variable, home string }{
	{"AWS_SHARED_CREDENTIALS_FILE", ".aws/credentials"},
	{"AWS_CONFIG_FILE", ".aws/config"},
}

// WatchPassed makes everything a collector is handed through its environment that is a credential one
// to look for: the variables of pass whose names say so, the passwords of addresses in them, and the
// keys in the AWS credentials and config files they lead to. The operator passed them, so they are
// read whatever --secret-path says; the agent's own files, /proc, /sys and /dev are still refused. A
// file that is not there is nothing to watch for, and one that cannot be read is an error, since the
// collector might read it.
func (p *Policy) WatchPassed(r *Redactor, pass []string) error {
	lookup := p.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	passed := map[string]string{}
	for _, name := range pass {
		v, ok := lookup(name)
		if !ok {
			continue
		}
		passed[name] = v
		if err := r.AddVariable(name, v); err != nil {
			return fmt.Errorf("the agent could not watch for the credentials in %s: %w", name, err)
		}
	}
	for _, f := range awsFiles {
		path, named := passed[f.variable], ""
		switch home, hasHome := passed["HOME"]; {
		case path != "":
			named = f.variable
		case hasHome && home != "":
			path, named = filepath.Join(home, f.home), "HOME"
		default:
			continue
		}
		data, skipped, err := p.readPassed(path)
		if err != nil {
			return fmt.Errorf("the agent could not watch for the credentials in the file %s leads to: %w", named, err)
		}
		if skipped != "" && p.Warn != nil {
			p.Warn(fmt.Sprintf("the AWS file %s leads to (%s) was not read, since %s; the collector cannot use it either", named, path, skipped))
		}
		for _, secret := range AWSFileSecrets(data) {
			if err := r.add([]byte(secret), "file:"+path); err != nil {
				return fmt.Errorf("the agent could not watch for the credentials in the file %s leads to: %w", named, err)
			}
		}
	}
	return nil
}

// readPassed reads a file the operator handed to the collector. The SDK goes on without one it cannot
// use, and a collector as the same user cannot read what the agent cannot: a file that is not there is
// nothing, and one that is not an absolute path or cannot be read or is not a file is skipped, with the
// reason. The agent's own files, /proc, /sys and /dev are refused, and so is a file too big to watch
// for, which the collector might read.
func (p *Policy) readPassed(path string) (data []byte, skipped string, err error) {
	if !filepath.IsAbs(path) {
		return nil, "it is not an absolute path", nil
	}
	path = filepath.Clean(path)
	target, err := filepath.EvalSymlinks(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, "", nil
	case err != nil:
		return nil, fmt.Sprintf("it cannot be looked at: %v", unwrapPath(err)), nil
	}
	if p.never(path) || p.never(target) {
		return nil, "", fmt.Errorf("file:%s is never something a collector may be pointed at: it is the agent's own, or /proc, /sys or /dev", path)
	}
	// Looked at before it is opened: opening a pipe waits for someone to write to it.
	if info, err := os.Stat(target); err != nil || !info.Mode().IsRegular() {
		return nil, "it is not a file", nil
	}
	f, err := openNoBlock(target)
	if err != nil {
		return nil, fmt.Sprintf("it cannot be read: %v", unwrapPath(err)), nil
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, "it is not a file", nil
	}
	data, err = io.ReadAll(io.LimitReader(f, maxSecret+1))
	if err != nil {
		return nil, fmt.Sprintf("it cannot be read: %v", unwrapPath(err)), nil
	}
	if len(data) > maxSecret {
		return nil, "", fmt.Errorf("the file %s is too big to watch for (over %d bytes)", path, maxSecret)
	}
	return data, "", nil
}

// AWSFileSecrets are the secrets in an AWS credentials or config file: the secret access key and the
// session token of every profile, with and without the quotes round them, which the SDK takes off. The
// key id is the name of a key and not a secret. A value too short to be looked for (LocalStack's "test") is
// a word and is left out: scrubbing it would hide it everywhere.
func AWSFileSecrets(data []byte) []string {
	var out []string
	for _, line := range bytes.Split(data, []byte("\n")) {
		// A comment or a section has no key of these names before an equals sign.
		key, value, ok := strings.Cut(string(line), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "aws_secret_access_key", "aws_session_token", "aws_security_token":
			value = strings.TrimSpace(value)
			if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
				if inner := value[1 : len(value)-1]; len(inner) >= MinEnforced {
					out = append(out, value, inner)
				}
				continue
			}
			if len(value) >= MinEnforced {
				out = append(out, value)
			}
		}
	}
	return out
}
