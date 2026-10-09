package pack_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"testing"

	"go.acciew.io/collector/verify/pack"
)

// archive/zip takes what it needs from the central directory and trusts the local
// header for where the data is. A tool that goes by the local header would extract
// another file than the one this verifier checked, so an archive whose two disagree
// is refused: it is not one thing that two readers read the same way.

func goodZip(t testing.TB) []byte { return zipOf(t, newPack(t).build().files) }

func local(t *testing.T, data []byte) error {
	t.Helper()
	_, err := verifyZip(t, data, pack.Options{})
	return err
}

func wantDisagreement(t *testing.T, err error) {
	t.Helper()
	if err == nil || pack.ReasonOf(err) != "unreadable" || !strings.Contains(err.Error(), "local header") {
		t.Errorf("error = %v, want an archive refused for a local header that disagrees", err)
	}
}

func TestAnArchiveWhoseLocalHeaderNamesAnotherFileIsRefused(t *testing.T) {
	data := goodZip(t)
	i := bytes.Index(data, []byte("README.txt"))
	if i < 0 {
		t.Fatal("no README.txt in the archive")
	}
	copy(data[i:], "REPORT.pdf")
	wantDisagreement(t, local(t, data))
}

func TestAnArchiveWhoseLocalHeaderHasAnotherMethodIsRefused(t *testing.T) {
	data := goodZip(t)
	i := bytes.Index(data, []byte("README.txt"))
	// The method is the two bytes at offset 8 of the 30-byte header the name follows.
	binary.LittleEndian.PutUint16(data[i-30+8:], 0)
	wantDisagreement(t, local(t, data))
}

func TestAnArchiveWhoseLocalHeaderHasAnotherSizeOrDigestIsRefused(t *testing.T) {
	body := []byte("stored with its sizes in the local header")
	build := func() []byte {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, err := w.CreateRaw(&zip.FileHeader{Name: "a.txt", Method: zip.Store, CRC32: crc32.ChecksumIEEE(body),
			CompressedSize64: uint64(len(body)), UncompressedSize64: uint64(len(body))})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	// As written it is an archive with no manifest, and is said to be, not refused for its headers.
	if err := local(t, build()); err == nil || strings.Contains(err.Error(), "local header") {
		t.Fatalf("an agreeing archive: %v", err)
	}
	for name, offset := range map[string]int{"crc": 14, "compressed size": 18, "size": 22} {
		data := build()
		data[offset] ^= 1
		if err := local(t, data); err == nil || !strings.Contains(err.Error(), "local header") {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestAnArchiveWithAPrefixOrACommentIsStillRead(t *testing.T) {
	p := newPack(t).build()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	if err := w.SetComment("made by a program that says things here"); err != nil {
		t.Fatal(err)
	}
	for name, body := range p.files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(body)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"a comment": buf.Bytes(), "a prefix": append(bytes.Repeat([]byte("#!/bin/sh\n"), 10), buf.Bytes()...)} {
		rep, err := verifyZip(t, data, pack.Options{})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		expect(t, rep)
	}
}

// zip64 builds a one-file archive in the ZIP64 form, by hand, with the sizes and
// the offset of the local header in the extra field.
func zip64(name, body string, localName string) []byte {
	le := binary.LittleEndian
	u16 := func(n uint16) []byte { return le.AppendUint16(nil, n) }
	u32 := func(n uint32) []byte { return le.AppendUint32(nil, n) }
	u64 := func(n uint64) []byte { return le.AppendUint64(nil, n) }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	crc := crc32.ChecksumIEEE([]byte(body))

	extra := cat(u16(1), u16(16), u64(uint64(len(body))), u64(uint64(len(body))))
	localHeader := cat(u32(0x04034b50), u16(45), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(0xFFFFFFFF), u32(0xFFFFFFFF),
		u16(uint16(len(localName))), u16(uint16(len(extra))), []byte(localName), extra, []byte(body))

	centralExtra := cat(u16(1), u16(24), u64(uint64(len(body))), u64(uint64(len(body))), u64(0))
	central := cat(u32(0x02014b50), u16(45), u16(45), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(0xFFFFFFFF), u32(0xFFFFFFFF),
		u16(uint16(len(name))), u16(uint16(len(centralExtra))), u16(0), u16(0), u16(0), u32(0o644<<16), u32(0xFFFFFFFF), []byte(name), centralExtra)

	cdOffset := uint64(len(localHeader))
	eocd64Offset := cdOffset + uint64(len(central))
	eocd64 := cat(u32(0x06064b50), u64(44), u16(45), u16(45), u32(0), u32(0), u64(1), u64(1), u64(uint64(len(central))), u64(cdOffset))
	locator := cat(u32(0x07064b50), u32(0), u64(eocd64Offset), u32(1))
	eocd := cat(u32(0x06054b50), u16(0xFFFF), u16(0xFFFF), u16(0xFFFF), u16(0xFFFF), u32(0xFFFFFFFF), u32(0xFFFFFFFF), u16(0))
	return cat(localHeader, central, eocd64, locator, eocd)
}

func TestAZip64ArchiveIsReadAndItsLocalHeadersAreComparedToo(t *testing.T) {
	// The archive Go's reader makes of it is one with one file and no manifest.
	err := local(t, zip64("a.txt", "hello", "a.txt"))
	if err == nil || strings.Contains(err.Error(), "local header") || !strings.Contains(err.Error(), "manifest.json") {
		t.Fatalf("a zip64 archive: %v", err)
	}
	wantDisagreement(t, local(t, zip64("a.txt", "hello", "b.txt")))
}

// archive/zip compares the number of entries the end of the archive gives with the
// number it read in 16 bits only. An archive with a count that is 65,536 more or
// less than its entries is accepted by it, and this verifier, which reads the
// directory again, must not take the two readings for one: it refuses the archive,
// and does not index past what it read.
func TestAnArchiveWhoseCountOfEntriesIsNotTheNumberItHoldsIsRefused(t *testing.T) {
	setCount := func(data []byte, n uint64) {
		t.Helper()
		i := bytes.LastIndex(data, []byte{'P', 'K', 0x06, 0x06})
		if i < 0 {
			t.Fatal("the archive has no ZIP64 end of central directory")
		}
		binary.LittleEndian.PutUint64(data[i+32:], n)
	}

	// One entry, and a count of 65,537.
	more := zip64("a.txt", "hello", "a.txt")
	setCount(more, 65537)
	if _, err := zip.NewReader(bytes.NewReader(more), int64(len(more))); err != nil {
		t.Fatalf("archive/zip does not take the archive, so it does not test the guard: %v", err)
	}
	if err := local(t, more); err == nil || pack.ReasonOf(err) != "unreadable" {
		t.Errorf("a count past the entries: error = %v", err)
	}

	// 65,537 entries, and a count of 1.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := range 65537 {
		if _, err := w.Create(fmt.Sprintf("f%05d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	fewer := buf.Bytes()
	setCount(fewer, 1)
	zr, err := zip.NewReader(bytes.NewReader(fewer), int64(len(fewer)))
	if err != nil || len(zr.File) != 65537 {
		t.Fatalf("archive/zip does not take the archive, so it does not test the guard: %v", err)
	}
	if err := local(t, fewer); err == nil || pack.ReasonOf(err) != "unreadable" || !strings.Contains(err.Error(), "lists 1 entries") {
		t.Errorf("a count short of the entries: error = %v", err)
	}
}
