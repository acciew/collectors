package repocheck_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A Go binary takes its directory's name, so `go build ./...` run inside an
// example leaves an 18 MB executable beside the source, and `git add -A`
// sweeps it in. Once merged it is in the history for good.
//
// A .gitignore entry catches the ones we thought of. This catches the rest,
// by looking at what the files are rather than what they are called.
func TestNoCompiledBinaryIsTracked(t *testing.T) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	dir := strings.TrimSpace(string(root))

	out, err := exec.Command("git", "-C", dir, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	for _, name := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if name == "" {
			continue
		}
		// A text file may legitimately begin "MZ". Anything with a known
		// source extension is not a compiled artefact whatever its bytes.
		if source[strings.ToLower(filepath.Ext(name))] {
			continue
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue // deleted in the working tree, or unreadable; not our business
		}
		var head [4]byte
		n, _ := f.Read(head[:])
		_ = f.Close()
		if n == 4 && executableImage(head) {
			t.Errorf("%s is a compiled binary and is tracked; build output does not belong "+
				"in the history", name)
		}
	}
}

// source is the extensions a compiled artefact never has.
var source = map[string]bool{
	".go": true, ".md": true, ".json": true, ".yaml": true, ".yml": true, ".proto": true,
	".mod": true, ".sum": true, ".txt": true, ".sh": true, ".toml": true, ".gitignore": true,
}

// The magic numbers for the formats a Go toolchain produces.
func executableImage(b [4]byte) bool {
	switch {
	case b == [4]byte{0x7f, 'E', 'L', 'F'}: // Linux
		return true
	case b == [4]byte{0xcf, 0xfa, 0xed, 0xfe}, b == [4]byte{0xce, 0xfa, 0xed, 0xfe}: // Mach-O
		return true
	case b == [4]byte{0xca, 0xfe, 0xba, 0xbe}: // Mach-O universal
		return true
	case b[0] == 'M' && b[1] == 'Z': // PE
		return true
	}
	return false
}
