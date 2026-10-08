package pathid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// Tag is eight hex digits that name a directory as it is and not as it is spelled: the same
// for a relative name, a link, a trailing slash, and another case where the filesystem ignores
// case. A directory that is not there is named by its absolute path.
func Tag(dir string) string {
	return tagOf(dir)
}

func fallbackTag(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	if linked, err := filepath.EvalSymlinks(abs); err == nil {
		abs = linked
	}
	sum := sha256.Sum256([]byte("path:" + abs))
	return hex.EncodeToString(sum[:4])
}

func statOf(dir string) (os.FileInfo, error) { return os.Stat(dir) }
