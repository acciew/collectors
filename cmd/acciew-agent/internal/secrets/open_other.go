//go:build !unix

package secrets

import "os"

func openNoBlock(path string) (*os.File, error) { return os.Open(path) } //nolint:gosec // as on unix
