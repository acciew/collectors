// Package pathid says whether a path is a directory, or inside it, by what the path is and not by
// how it is spelled: macOS and Windows filesystems ignore case, and any filesystem has links.
package pathid

import (
	"os"
	"path/filepath"
)

// Inside says path is dir or something under it. Every part of the path that exists is compared
// to dir with os.SameFile, so another spelling of dir (in other case, through a link, by a bind
// mount) is dir. A path that does not exist is judged by the part of it that does.
func Inside(dir, path string) bool {
	d, err := os.Stat(dir)
	if err != nil {
		return false
	}
	for p := filepath.Clean(path); ; {
		if info, err := os.Stat(p); err == nil && os.SameFile(info, d) {
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}

// Same says two paths are the one file, whatever each is called.
func Same(a, b string) bool {
	x, err := os.Stat(a)
	if err != nil {
		return false
	}
	y, err := os.Stat(b)
	return err == nil && os.SameFile(x, y)
}
