//go:build unix

package secrets

import (
	"fmt"
	"os"
	"syscall"
)

// CheckOwner says a directory belongs to uid.
func CheckOwner(info os.FileInfo, uid uint32) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != uid {
		return fmt.Errorf("owned by user %d, not by %d", st.Uid, uid)
	}
	return nil
}
