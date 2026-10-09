package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// put makes a directory named name under a fresh parent and fills it, in the order given.
func put(t *testing.T, name string, files [][2]string, modes map[string]os.FileMode, mtime time.Time) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		mode := os.FileMode(0o600)
		if m, ok := modes[f[0]]; ok {
			mode = m
		}
		p := filepath.Join(dir, f[0])
		if err := os.WriteFile(p, []byte(f[1]), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func zipOf(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := write(&buf, dir); err != nil {
		t.Fatalf("write: %v", err)
	}
	return buf.Bytes()
}

func TestTheEntriesAreTheFilesUnderTheDirectorysNameInOrderWithAFixedTimeAndMode(t *testing.T) {
	dir := put(t, "pack-1.0", [][2]string{
		{"tool.exe", "MZ body"}, {"README.md", "read me"}, {"LICENSE", "license"},
	}, map[string]os.FileMode{"tool.exe": 0o700, "LICENSE": 0o640},
		time.Date(2031, 5, 6, 7, 8, 9, 0, time.UTC))

	b := zipOf(t, dir)
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		if !f.Modified.Equal(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("%s is dated %s", f.Name, f.Modified)
		}
		want := os.FileMode(0o644)
		if f.Name == "pack-1.0/tool.exe" {
			want = 0o755
		}
		if f.Mode() != want {
			t.Errorf("%s has mode %v, want %v", f.Name, f.Mode(), want)
		}
	}
	if want := []string{"pack-1.0/LICENSE", "pack-1.0/README.md", "pack-1.0/tool.exe"}; !slices.Equal(names, want) {
		t.Errorf("entries %v, want %v", names, want)
	}

	// What is read back is what was written.
	r, err := zr.File[2].Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "MZ body" {
		t.Errorf("tool.exe holds %q (err %v)", got, err)
	}
}

func TestTheSameFilesMakeTheSameBytesWhateverTheirTimesAndTheOrderTheyWereMadeIn(t *testing.T) {
	a := put(t, "pack", [][2]string{{"a", "one"}, {"b", "two"}, {"c", "three"}},
		nil, time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC))
	b := put(t, "pack", [][2]string{{"c", "three"}, {"a", "one"}, {"b", "two"}},
		map[string]os.FileMode{"a": 0o666}, time.Date(2030, 12, 31, 23, 59, 58, 0, time.UTC))

	if !bytes.Equal(zipOf(t, a), zipOf(t, b)) {
		t.Error("the same files made different archives")
	}
}

func TestAChangedFileMakesADifferentArchive(t *testing.T) {
	a := put(t, "pack", [][2]string{{"a", "one"}}, nil, time.Now())
	b := put(t, "pack", [][2]string{{"a", "One"}}, nil, time.Now())
	if bytes.Equal(zipOf(t, a), zipOf(t, b)) {
		t.Error("different files made the same archive")
	}
}

func TestAnythingButRegularFilesIsRefused(t *testing.T) {
	dir := put(t, "pack", [][2]string{{"a", "one"}}, nil, time.Now())
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := write(&buf, dir); err == nil {
		t.Error("a directory inside was archived")
	}

	dir = put(t, "pack", [][2]string{{"a", "one"}}, nil, time.Now())
	if err := os.Symlink("a", filepath.Join(dir, "link")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	if err := write(&buf, dir); err == nil {
		t.Error("a symbolic link was archived")
	}
}

func TestAnEmptyDirectoryIsRefused(t *testing.T) {
	var buf bytes.Buffer
	if err := write(&buf, put(t, "pack", nil, nil, time.Now())); err == nil {
		t.Error("an archive with nothing in it was made")
	}
}
