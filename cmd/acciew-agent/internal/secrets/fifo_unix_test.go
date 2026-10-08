//go:build unix

package secrets_test

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opening a FIFO waits for a writer. Bind takes no context, so the agent would stall on that job
// for ever, with its heartbeats holding the lease.
func TestAFifoOrADeviceNamedAsASecretIsRefusedWithoutBeingOpened(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no fifo here: %v", err)
	}
	p := policy(t, nil)
	done := make(chan error, 1)
	go func() {
		_, err := bindOne(p, "file:"+fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a file") {
			t.Errorf("err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Bind is waiting on a pipe")
	}
}
