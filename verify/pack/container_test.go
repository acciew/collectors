package pack_test

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.acciew.io/collector/verify/pack"
)

// rawZip writes entries in the order given, with no checking of names, as a
// hostile archive would be written.
func rawZip(t testing.TB, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type zipEntry struct {
	name string
	body []byte
	mode fs.FileMode
}

// withPack is the entries of a good pack and then these.
func withPack(t testing.TB, extra ...zipEntry) []zipEntry {
	t.Helper()
	p := newPack(t).build()
	var out []zipEntry
	for name, body := range p.files {
		out = append(out, zipEntry{name: name, body: body})
	}
	return append(out, extra...)
}

func verifyZip(t testing.TB, data []byte, opts pack.Options) (*pack.Report, error) {
	t.Helper()
	return pack.VerifyZip(bytes.NewReader(data), int64(len(data)), opts)
}

func TestWhatIsNotAnArchiveIsUnreadableAndNothingMore(t *testing.T) {
	for name, data := range map[string][]byte{"nothing": nil, "text": []byte("this is not a zip"), "a cut archive": rawZip(t, withPack(t))[:100]} {
		_, err := verifyZip(t, data, pack.Options{})
		if err == nil || pack.ReasonOf(err) != "unreadable" {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	_, err := verifyZip(t, rawZip(t, nil), pack.Options{})
	if err == nil || pack.ReasonOf(err) != "unreadable" {
		t.Errorf("an empty archive: error = %v", err)
	}
}

// An entry whose name could write outside a folder, or is not a plain name, is
// not read, not listed, and named; the rest of the pack is checked as it is.
func TestANameNoPackHasIsNamedAndTheEntryIsNeverRead(t *testing.T) {
	bad := []string{"../escape.txt", "/etc/passwd", `a\b.txt`, "a//b.txt", "./a.txt", "history/../manifest.json", "con.txt", "x/aux", ".hidden", "__MACOSX/._manifest.json",
		"a b.txt", "caf\xc3\xa9.txt", "a\x1b[2Jb.txt", "a\xe2\x80\xaeb.txt", strings.Repeat("n", 129), "a/b/c/d/e/f/g/h/i/j.txt"}
	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			rep, err := verifyZip(t, rawZip(t, withPack(t, zipEntry{name: name, body: []byte("hostile")})), pack.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Findings) != 1 || rep.Findings[0].Reason != "name" {
				t.Fatalf("findings = %v", findingKeys(rep))
			}
			f := rep.Findings[0]
			if strings.ContainsAny(f.Message+f.String(), "\x1b") || strings.Contains(f.Message+f.String(), "\xe2\x80\xae") {
				t.Errorf("a raw name reached the message: %q", f.String())
			}
		})
	}
}

func TestALinkInAnArchiveIsNamedAndNotFollowed(t *testing.T) {
	rep, err := verifyZip(t, rawZip(t, withPack(t, zipEntry{name: "latest", body: []byte("history/conn-1/keycloak.jsonl"), mode: fs.ModeSymlink | 0o777})), pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "notplain latest")
}

func TestTheSameNameTwiceInAnArchiveIsNamed(t *testing.T) {
	rep, err := verifyZip(t, rawZip(t, withPack(t, zipEntry{name: "README.txt", body: []byte("another README")})), pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "duplicate README.txt")
}

func TestADirectoryEntryWithAPlainNameIsFine(t *testing.T) {
	rep, err := verifyZip(t, rawZip(t, withPack(t, zipEntry{name: "history/", mode: fs.ModeDir | 0o755})), pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep)
}

func TestAnArchiveThatExpandsFarBeyondItsSizeIsRefusedBeforeItIsRead(t *testing.T) {
	// Five megabytes of zeros is a few kilobytes of archive: a ratio of about a thousand.
	bomb := bytes.Repeat([]byte{0}, 5<<20)
	data := rawZip(t, withPack(t, zipEntry{name: "bomb.bin", body: bomb}))
	if len(data) > 200_000 {
		t.Fatalf("the test archive is %d bytes", len(data))
	}
	_, err := verifyZip(t, data, pack.Options{})
	if err == nil || pack.ReasonOf(err) != "limit" || !strings.Contains(err.Error(), "bomb.bin") {
		t.Errorf("error = %v", err)
	}
	// Told to take it, it is checked, and the file is not in the manifest.
	rep, err := verifyZip(t, data, pack.Options{Limits: pack.Limits{MaxRatio: 100_000}})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "unlisted bomb.bin")
}

func TestTooManyEntriesAreRefused(t *testing.T) {
	data := rawZip(t, withPack(t))
	_, err := verifyZip(t, data, pack.Options{Limits: pack.Limits{MaxEntries: 5}})
	if err == nil || pack.ReasonOf(err) != "limit" {
		t.Errorf("error = %v", err)
	}
}

func TestAFileLargerThanTheLimitIsRefused(t *testing.T) {
	data := rawZip(t, withPack(t, zipEntry{name: "big.bin", body: bytes.Repeat([]byte("abcdefghij"), 500)}))
	_, err := verifyZip(t, data, pack.Options{Limits: pack.Limits{MaxFileBytes: 4000}})
	if err == nil || pack.ReasonOf(err) != "limit" || !strings.Contains(err.Error(), "big.bin") {
		t.Errorf("error = %v", err)
	}
}

func TestAPackLargerThanTheLimitInAllIsRefused(t *testing.T) {
	data := rawZip(t, withPack(t))
	_, err := verifyZip(t, data, pack.Options{Limits: pack.Limits{MaxTotalBytes: 500}})
	if err == nil || pack.ReasonOf(err) != "limit" {
		t.Errorf("error = %v", err)
	}
}

// A header can say any size. What is read is counted, and past the size the
// header gave, or the limit, it stops.
func TestAnEntryThatIsLongerThanItsHeaderSaysIsNotReadPastTheLimit(t *testing.T) {
	p := newPack(t).build()
	var entries []zipEntry
	for name, body := range p.files {
		entries = append(entries, zipEntry{name: name, body: body})
	}
	data := rawZip(t, entries)
	// The headers are right here; this is the guard for the case they are not: the
	// largest file read is bounded by the file limit whatever the header says.
	_, err := verifyZip(t, data, pack.Options{Limits: pack.Limits{MaxFileBytes: 100}})
	if err == nil || pack.ReasonOf(err) != "limit" {
		t.Errorf("error = %v", err)
	}
}

func TestADamagedEntryIsNamedAsUnreadableAndNotAsAChange(t *testing.T) {
	p := newPack(t).build()
	var entries []zipEntry
	for name, body := range p.files {
		entries = append(entries, zipEntry{name: name, body: body})
	}
	data := rawZip(t, entries)
	// Flip a byte in the middle of the compressed data of an entry.
	damaged := append([]byte(nil), data...)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == "register.xlsx" {
			off, err := f.DataOffset()
			if err != nil {
				t.Fatal(err)
			}
			damaged[off+int64(f.CompressedSize64)/2] ^= 0xff
		}
	}
	rep, err := verifyZip(t, damaged, pack.Options{})
	if err != nil {
		if pack.ReasonOf(err) != "unreadable" {
			t.Errorf("error = %v", err)
		}
		return
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Path == "register.xlsx" && (f.Reason == "unreadable" || f.Reason == "sha256" || f.Reason == "size") {
			found = true
		}
	}
	if !found {
		t.Errorf("findings = %v", findingKeys(rep))
	}
}

func TestAFolderWithNothingInItIsNotAPack(t *testing.T) {
	_, err := pack.VerifyDir(t.TempDir(), pack.Options{})
	if err == nil || pack.ReasonOf(err) != "unreadable" {
		t.Errorf("error = %v", err)
	}
	_, err = pack.VerifyDir(filepath.Join(t.TempDir(), "nowhere"), pack.Options{})
	if err == nil || pack.ReasonOf(err) != "unreadable" {
		t.Errorf("a folder that is not there: %v", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pack.VerifyDir(file, pack.Options{}); err == nil || pack.ReasonOf(err) != "unreadable" {
		t.Errorf("a file given as a folder: %v", err)
	}
}

func TestInAFolderALinkAndAStrangeNameAreNamedAndNeverFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links and such names are not made here")
	}
	p := newPack(t).build()
	dir := dirOf(t, p.files)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("not part of the pack"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "latest")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	odd := "a\x1b[2Jb\xe2\x80\xaec"
	if err := os.WriteFile(filepath.Join(dir, odd), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := pack.VerifyDir(dir, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	keys := strings.Join(findingKeys(rep), "\n")
	for _, want := range []string{"notplain latest", "notplain elsewhere"} {
		if !strings.Contains(keys, want) {
			t.Errorf("findings:\n%s\nwant %q", keys, want)
		}
	}
	var named bool
	for _, f := range rep.Findings {
		if f.Reason == "name" {
			named = true
		}
		if strings.ContainsAny(f.String(), "\x1b") || strings.Contains(f.String(), "\xe2\x80\xae") {
			t.Errorf("a raw name reached the message: %q", f.String())
		}
	}
	if !named {
		t.Errorf("the strange name was not named:\n%s", keys)
	}
}

func TestAFolderThatIsTheManifestsFolderButHoldsALinkInsteadOfAFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links are not made here")
	}
	p := newPack(t).build()
	dir := dirOf(t, p.files)
	target := filepath.Join(t.TempDir(), "README.txt")
	if err := os.WriteFile(target, p.files["README.txt"], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "README.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "README.txt")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	rep, err := pack.VerifyDir(dir, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The link is not followed, so the listed file is not there.
	expect(t, rep, "notplain README.txt", "missing README.txt")
}

func TestAFindingNamesItsFileAndSaysSoInWords(t *testing.T) {
	p := newPack(t).build()
	p.files["register.xlsx"][3] ^= 1
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %v", findingKeys(rep))
	}
	got := rep.Findings[0].String()
	if !strings.Contains(got, "register.xlsx") || !strings.Contains(got, "manifest") {
		t.Errorf("finding = %q", got)
	}
	for _, word := range []string{"tamper", "forged", "attack"} {
		if strings.Contains(strings.ToLower(got), word) {
			t.Errorf("%q says more than the files can show", got)
		}
	}
}

// A folder is an entry whose name ends in a slash, which is what archive/zip's own
// Open goes by. Mode bits that say folder, on a name with no slash, are not a
// reason to leave the entry unread, or to cut a byte off its name.
func TestAnEntryWithFolderModeBitsAndNoSlashIsAFileThatIsNotPlainAndNeverSkipped(t *testing.T) {
	rep, err := verifyZip(t, rawZip(t, withPack(t, zipEntry{name: "report.pdf", body: []byte("%PDF-1.7 an unlisted file"), mode: fs.ModeDir | 0o755})), pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "notplain report.pdf")
	if rep.Verified() {
		t.Error("a file written with folder mode bits verified clean")
	}
}

func TestTheManifestWrittenWithFolderModeBitsIsNotThereAndItsNameIsNotCutShort(t *testing.T) {
	p := newPack(t).build()
	var entries []zipEntry
	for name, body := range p.files {
		e := zipEntry{name: name, body: body}
		if name == "manifest.json" {
			e.mode = fs.ModeDir | 0o755
		}
		entries = append(entries, e)
	}
	_, err := verifyZip(t, rawZip(t, entries), pack.Options{})
	if err == nil || pack.ReasonOf(err) != "unreadable" || !strings.Contains(err.Error(), "manifest.json") {
		t.Errorf("error = %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "manifest.jso ") {
		t.Errorf("error = %q: a byte was cut off the name", err)
	}
}

func TestAFolderEntryThatCarriesDataIsRefused(t *testing.T) {
	// The writer will not put data in a folder, so the name is changed after: the
	// same length, in the local header and in the central directory.
	data := rawZip(t, withPack(t, zipEntry{name: "extraQ", body: []byte("a folder has no data")}))
	data = bytes.ReplaceAll(data, []byte("extraQ"), []byte("extra/"))
	rep, err := verifyZip(t, data, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "notplain extra")
}
