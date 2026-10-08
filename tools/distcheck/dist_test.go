package distcheck_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The release archives are what somebody who does not build from source runs
// against their systems, so what is in them is checked the way they would
// check it: the files, the digests, and the binary's own account of how it was
// built. Run through `task dist:check`, which says where the archives are.
var collectors = []string{"keycloak", "github", "awsiam", "entra"}

// The agent ships in the same archive, so that its default collectors directory
// (the one it sits in) holds the collectors it runs.
const agent = "acciew-agent"

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

	for _, platform := range platforms {
		goos, goarch, _ := strings.Cut(platform, "/")
		name := "acciew-collectors-" + version + "-" + goos + "-" + goarch
		t.Run(platform, func(t *testing.T) {
			path := filepath.Join(dist, name+".tar.gz")
			if got := digest(t, path); sums[name+".tar.gz"] != got {
				t.Errorf("SHA256SUMS has %q for %s, the file is %s", sums[name+".tar.gz"], name+".tar.gz", got)
			}

			files := unpack(t, path, name)
			want := []string{"LICENSE", "NOTICE", "README.md"}
			for _, c := range collectors {
				want = append(want, "acciew-collector-"+c)
			}
			want = append(want, agent)
			var got []string
			for f := range files {
				got = append(got, f)
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("archive holds %v, want exactly %v", got, want)
			}

			type binary struct{ name, file, main, version string }
			var bins []binary
			for _, c := range collectors {
				bins = append(bins, binary{c, "acciew-collector-" + c, "go.acciew.io/collector/plugins/" + c, c + " " + version})
			}
			bins = append(bins, binary{agent, agent, "go.acciew.io/collector/cmd/acciew-agent", agent + " " + version})
			for _, b := range bins {
				c, bin := b.name, files[b.file]
				if bin == "" {
					continue
				}
				info, err := buildinfo.ReadFile(bin)
				if err != nil {
					t.Errorf("%s: no build information: %v", c, err)
					continue
				}
				if info.Main.Path != b.main {
					t.Errorf("%s: built from %s, want %s", c, info.Main.Path, b.main)
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
		})
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
		if (strings.HasPrefix(rel, "acciew-collector-") || rel == agent) && h.Mode&0o111 == 0 {
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
