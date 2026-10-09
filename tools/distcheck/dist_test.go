package distcheck_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// The release archives are what somebody who does not build from source runs
// against their systems, so what is in them is checked the way they would
// check it: the files, the digests, and the binary's own account of how it was
// built. Run through `task dist:check`, which says where the archives are.
var collectors = []string{"keycloak", "github", "awsiam", "entra"}

// The agent ships in the same archive, so that its default collectors directory
// (the one it sits in) holds the collectors it runs.
const agent = "acciew-agent"

// The verifier ships in it too: an auditor who downloads the archive to check a pack
// has the command that does it. It is a module of its own, with no dependency of ours.
const verifier = "acciew-verify"

// For Windows only the verifier ships, in a zip: an auditor there is handed an evidence
// pack and has no use for the collectors or the agent, which are not built for Windows.
const windowsExe = verifier + ".exe"

// What is in an archive besides program files. BINARIES.sha256 lists the program files only.
var documents = []string{"LICENSE", "NOTICE", "README.md"}

// A zip entry carries a time, and a fixed one keeps a build to the same bytes. This is the
// earliest time a zip can hold.
var zipTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// The machine field of a PE file says what the program is for, whatever it is called.
var peMachine = map[string]uint16{"amd64": 0x8664, "arm64": 0xAA64}

// built is a binary in an archive: the package that is its main, the module that
// package is in, and what --version says.
type built struct{ name, file, main, module, version string }

func TestArchives(t *testing.T) {
	dist := os.Getenv("ACCIEW_DIST")
	if dist == "" {
		t.Skip("run through `task dist:check`")
	}
	version := os.Getenv("ACCIEW_VERSION")
	platforms := strings.Fields(os.Getenv("ACCIEW_PLATFORMS"))
	if version == "" || len(platforms) == 0 {
		t.Fatal("ACCIEW_VERSION and ACCIEW_PLATFORMS must be set")
	}

	sums := readSums(t, filepath.Join(dist, "SHA256SUMS"))
	if len(sums) != len(platforms) {
		t.Errorf("SHA256SUMS lists %d files, want one per platform (%d)", len(sums), len(platforms))
	}

	// Every program file in every archive is in BINARIES.sha256, and nothing else is.
	listed := readBinaries(t, filepath.Join(dist, "BINARIES.sha256"))
	seen := map[string]bool{}
	defer func() {
		var extra []string
		for key := range listed {
			if !seen[key] {
				extra = append(extra, key)
			}
		}
		slices.Sort(extra)
		for _, key := range extra {
			t.Errorf("BINARIES.sha256 lists %s, which is in no archive", key)
		}
	}()

	for _, platform := range platforms {
		goos, goarch, _ := strings.Cut(platform, "/")
		name := "acciew-collectors-" + version + "-" + goos + "-" + goarch
		t.Run(platform, func(t *testing.T) {
			if goos == "windows" {
				checkWindowsZip(t, dist, sums, version, goarch, listed, seen)
				return
			}
			path := filepath.Join(dist, name+".tar.gz")
			if got := digest(t, path); sums[name+".tar.gz"] != got {
				t.Errorf("SHA256SUMS has %q for %s, the file is %s", sums[name+".tar.gz"], name+".tar.gz", got)
			}

			files := unpack(t, path, name)
			want := slices.Clone(documents)
			for _, c := range collectors {
				want = append(want, "acciew-collector-"+c)
			}
			want = append(want, agent, verifier)
			var got []string
			for f := range files {
				got = append(got, f)
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("archive holds %v, want exactly %v", got, want)
			}
			checkListed(t, listed, seen, name, files)

			var bins []built
			for _, c := range collectors {
				bins = append(bins, built{c, "acciew-collector-" + c, "go.acciew.io/collector/plugins/" + c, "go.acciew.io/collector/plugins/" + c, c + " " + version})
			}
			bins = append(bins, built{agent, agent, "go.acciew.io/collector/cmd/acciew-agent", "go.acciew.io/collector/cmd/acciew-agent", agent + " " + version})
			bins = append(bins, verifierBuild(version))
			for _, b := range bins {
				if files[b.file] != "" {
					checkBuild(t, b, files[b.file], goos, goarch)
				}
			}
		})
	}
}

func verifierBuild(version string) built {
	return built{verifier, verifier, "go.acciew.io/collector/verify/cmd/acciew-verify", "go.acciew.io/collector/verify", verifier + " " + version}
}

// checkBuild reads a binary's own account of how it was built.
func checkBuild(t *testing.T, b built, bin, goos, goarch string) {
	t.Helper()
	c := b.name
	info, err := buildinfo.ReadFile(bin)
	if err != nil {
		t.Errorf("%s: no build information: %v", c, err)
		return
	}
	// The package that is main, and the module it is in: for a collector they are
	// the same path, and for the verifier the command is inside its module.
	if info.Path != b.main || info.Main.Path != b.module {
		t.Errorf("%s: built from package %s of module %s, want %s of %s", c, info.Path, info.Main.Path, b.main, b.module)
	}
	// The verifier is standard library only: nothing else is in the binary.
	if b.name == verifier && len(info.Deps) != 0 {
		t.Errorf("%s: built with %d dependencies, want none: %v", c, len(info.Deps), info.Deps)
	}
	set := map[string]string{}
	for _, s := range info.Settings {
		set[s.Key] = s.Value
	}
	// -trimpath keeps the linker flags out of the build information,
	// so the stamped version is read the way a user would read it:
	// by asking the binary. Only this machine's own binaries can be
	// run; one platform proves the flag reaches the variable, as
	// every platform is built by the same line.
	if goos == runtime.GOOS && goarch == runtime.GOARCH {
		out, err := exec.Command(bin, "--version").Output()
		if err != nil || strings.TrimSpace(string(out)) != b.version {
			t.Errorf("%s --version printed %q (err %v), want %q", c, out, err, b.version)
		}
	}
	for key, want := range map[string]string{
		"-trimpath": "true", "CGO_ENABLED": "0", "GOOS": goos, "GOARCH": goarch,
	} {
		if set[key] != want {
			t.Errorf("%s: build setting %s is %q, want %q", c, key, set[key], want)
		}
	}
}

// checkWindowsZip checks the Windows archive of a platform: listed in SHA256SUMS, holding
// the verifier and the documents and nothing else, in a fixed order with a fixed time,
// and the verifier is a Windows executable for the right processor.
func checkWindowsZip(t *testing.T, dist string, sums map[string]string, version, goarch string, listed map[string]string, seen map[string]bool) {
	t.Helper()
	name := verifier + "-" + version + "-windows-" + goarch
	path := filepath.Join(dist, name+".zip")
	if got := digest(t, path); sums[name+".zip"] != got {
		t.Errorf("SHA256SUMS has %q for %s, the file is %s", sums[name+".zip"], name+".zip", got)
	}

	files, order := unzip(t, path, name)
	want := append(slices.Clone(documents), windowsExe)
	if !slices.Equal(order, want) {
		t.Errorf("archive holds %v in this order, want exactly %v", order, want)
	}
	checkListed(t, listed, seen, name, files)

	exe := files[windowsExe]
	if exe == "" {
		return
	}
	checkPE(t, exe, goarch)
	checkBuild(t, verifierBuild(version), exe, "windows", goarch)
}

// unzip writes a zip's files into a temporary directory and returns their paths by name,
// and the names in the order the zip lists them. It fails on anything but regular files
// directly in the archive's own directory.
func unzip(t *testing.T, path, top string) (map[string]string, []string) {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer func() { _ = zr.Close() }()
	dir := t.TempDir()
	out := map[string]string{}
	var order []string
	for _, f := range zr.File {
		rel, ok := strings.CutPrefix(f.Name, top+"/")
		if !ok || rel == "" || strings.ContainsAny(rel, "/\\") || !f.Mode().IsRegular() {
			t.Errorf("unexpected entry %q; the archive holds only files in %s/", f.Name, top)
			continue
		}
		if _, dup := out[rel]; dup {
			t.Errorf("%s is in the archive twice", rel)
			continue
		}
		if !f.Modified.Equal(zipTime) {
			t.Errorf("%s is dated %s, want %s", rel, f.Modified.UTC().Format(time.RFC3339), zipTime.Format(time.RFC3339))
		}
		if rel == windowsExe && f.Mode()&0o111 == 0 {
			t.Errorf("%s is not executable", rel)
		}
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, rel)
		w, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, os.FileMode(f.Mode().Perm()))
		if err != nil {
			t.Fatal(err)
		}
		// Reading to the end is what checks the entry against its CRC.
		if _, err := io.Copy(w, r); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		_ = w.Close()
		_ = r.Close()
		out[rel] = dst
		order = append(order, rel)
	}
	return out, order
}

// checkPE reads the file's headers by hand: it starts "MZ", the offset at 0x3c is a
// "PE" header, and the machine field in it is the one for the architecture.
func checkPE(t *testing.T, path, goarch string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte("MZ")) || len(b) < 0x40 {
		t.Errorf("%s does not start with an MZ header", filepath.Base(path))
		return
	}
	off := uint64(binary.LittleEndian.Uint32(b[0x3c:]))
	if off+6 > uint64(len(b)) || !bytes.Equal(b[off:off+4], []byte("PE\x00\x00")) {
		t.Errorf("%s has no PE header where the MZ header says", filepath.Base(path))
		return
	}
	if got := binary.LittleEndian.Uint16(b[off+4:]); got != peMachine[goarch] {
		t.Errorf("%s is for machine %#04x, want %#04x for %s", filepath.Base(path), got, peMachine[goarch], goarch)
	}
}

// unpack writes the archive's files into a temporary directory and returns
// their paths by name, failing on anything outside the archive's own directory.
func unpack(t *testing.T, path, top string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	dir := t.TempDir()
	out := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if h.Typeflag == tar.TypeDir {
			if strings.TrimSuffix(h.Name, "/") != top {
				t.Errorf("unexpected directory %q; the archive holds only %s/", h.Name, top)
			}
			continue
		}
		rel, ok := strings.CutPrefix(h.Name, top+"/")
		if !ok || strings.Contains(rel, "/") || h.Typeflag != tar.TypeReg {
			t.Errorf("unexpected entry %q outside %s/", h.Name, top)
			continue
		}
		if (strings.HasPrefix(rel, "acciew-collector-") || rel == agent || rel == verifier) && h.Mode&0o111 == 0 {
			t.Errorf("%s is not executable", rel)
		}
		dst := filepath.Join(dir, rel)
		w, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, os.FileMode(h.Mode&0o777))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, tr); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		out[rel] = dst
	}
}

// checkListed compares each program file of an archive with its line in BINARIES.sha256,
// by the path "<archive>/<file>" a line gives it. The documents are not program files.
func checkListed(t *testing.T, listed map[string]string, seen map[string]bool, top string, files map[string]string) {
	t.Helper()
	for file, path := range files {
		key := top + "/" + file
		if slices.Contains(documents, file) {
			if _, ok := listed[key]; ok {
				seen[key] = true
				t.Errorf("BINARIES.sha256 lists %s, which is not a program file", key)
			}
			continue
		}
		seen[key] = true
		want, ok := listed[key]
		if !ok {
			t.Errorf("BINARIES.sha256 does not list %s", key)
			continue
		}
		if got := digest(t, path); want != got {
			t.Errorf("BINARIES.sha256 has %q for %s, the file is %s", want, key, got)
		}
	}
}

func digest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readSums(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SHA256SUMS: %v", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		sum, file, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("SHA256SUMS line %q is not \"<digest>  <file>\"", line)
		}
		out[strings.TrimPrefix(file, "*")] = sum
	}
	return out
}

// A line of BINARIES.sha256 is a line of SHA256SUMS: the digest, two spaces, and the path of
// the program file inside its archive's folder.
var binariesLine = regexp.MustCompile(`^([0-9a-f]{64})  ([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)$`)

// readBinaries reads BINARIES.sha256 as `sha256sum -c` would, and also insists on the order
// (by path, bytewise) and the final newline, so the same release always makes the same file.
func readBinaries(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read BINARIES.sha256: %v", err)
	}
	text := string(b)
	if !strings.HasSuffix(text, "\n") {
		t.Errorf("BINARIES.sha256 does not end with a newline")
	}
	out := map[string]string{}
	prev := ""
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		m := binariesLine.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("BINARIES.sha256 line %q is not \"<digest>  <archive>/<file>\"", line)
			continue
		}
		if _, dup := out[m[2]]; dup {
			t.Errorf("BINARIES.sha256 lists %s twice", m[2])
		}
		if m[2] <= prev {
			t.Errorf("BINARIES.sha256 has %s after %s; lines are sorted by path", m[2], prev)
		}
		prev = m[2]
		out[m[2]] = m[1]
	}
	return out
}
