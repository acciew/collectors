//go:build !unix

package secrets

import "os"

// CheckOwner does nothing where files have no owner id the agent can read.
func CheckOwner(os.FileInfo, uint32) error { return nil }
