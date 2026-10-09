// Command mkzip writes a zip of the files in a directory, the same bytes every time it
// is made from the same files.
//
// Usage:
//
//	mkzip -o out.zip dir
//
// The entries sit under a directory named for dir (as `tar -C parent -c dir` would
// have them), in name order, each with the earliest time a zip can hold and a mode of
// 0755 if it is executable and 0644 if not. The time and the owner the files had when
// they were made are not recorded, so the archive does not depend on when or where it
// was built. dir holds regular files and nothing else.
package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// zipTime is the earliest time a zip can hold: 1980-01-01, the start of the DOS clock.
var zipTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

func main() {
	out := flag.String("o", "", "the zip to write")
	flag.Parse()
	if *out == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: mkzip -o out.zip dir")
		os.Exit(2)
	}
	// In memory, so that a refused directory leaves no half-written file behind.
	var buf bytes.Buffer
	if err := write(&buf, flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, "mkzip:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil { //nolint:gosec // an archive meant to be published is world-readable
		fmt.Fprintln(os.Stderr, "mkzip:", err)
		os.Exit(1)
	}
}

// write writes the zip of dir's files to w.
func write(w io.Writer, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New(dir + " is empty")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	top := filepath.Base(filepath.Clean(dir))
	zw := zip.NewWriter(w)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", filepath.Join(dir, e.Name()))
		}
		mode := os.FileMode(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		h := &zip.FileHeader{Name: top + "/" + e.Name(), Method: zip.Deflate, Modified: zipTime}
		h.SetMode(mode)
		ew, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if err := copyFile(ew, filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return zw.Close()
}

func copyFile(w io.Writer, path string) error {
	f, err := os.Open(path) //nolint:gosec // a file found in the directory named on the command line
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(w, f)
	return err
}
