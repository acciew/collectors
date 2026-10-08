//go:build unix

package pathid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"syscall"
)

// tagOf names a directory by the device and inode it is on, which are the same whatever it is
// called. If it cannot be looked at, by its path.
func tagOf(dir string) string {
	info, err := statOf(dir)
	if err != nil {
		return fallbackTag(dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fallbackTag(dir)
	}
	// Printed as they are: their types differ between systems and the tag only has to be the same on one.
	sum := sha256.Sum256([]byte(fmt.Sprintf("dev:%d ino:%d", st.Dev, st.Ino)))
	return hex.EncodeToString(sum[:4])
}
