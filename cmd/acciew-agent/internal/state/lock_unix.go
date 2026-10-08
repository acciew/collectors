//go:build unix

package state

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Lock takes the state directory for this process. Two agents with one key would take each
// other's jobs and clean each other's spools.
func Lock(dir string) (unlock func(), err error) {
	return flock(filepath.Join(dir, "lock"), fmt.Sprintf("another acciew-agent is running with state directory %s", dir))
}

// LockRotation takes the right to change the key. It is not the lock of a running agent: an
// agent runs while its key is rotated from another terminal. Two rotations at once would
// overwrite each other's pending key, and could leave the service holding a key the disk does not.
func LockRotation(dir string) (unlock func(), err error) {
	return flock(filepath.Join(dir, "rotate.lock"), fmt.Sprintf("another acciew-agent rotate is changing the key of state directory %s: wait for it to finish", dir))
}

func flock(path, heldMessage string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // the operator's own state directory
	if err != nil {
		return nil, fmt.Errorf("locking the state directory: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s", heldMessage)
	}
	return func() { _ = f.Close() }, nil
}
