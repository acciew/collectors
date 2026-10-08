//go:build unix

package secrets

import (
	"os"
	"syscall"
)

// openNoBlock opens a file for reading without waiting for a writer, which is what opening a pipe does.
func openNoBlock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // naming the operator's own secret file is the point of a reference
}
