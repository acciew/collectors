package chunk_test

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/chunk"
)

// readFrames reads a chunk the way the service does (internal/pluginhost/remote): inflate,
// then unsigned-varint length and that many bytes, until nothing is left.
func readFrames(t *testing.T, c []byte) [][]byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(c))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("cannot inflate: %v", err)
	}
	var out [][]byte
	for len(raw) > 0 {
		size, w := binary.Uvarint(raw)
		if w <= 0 || len(raw)-w < int(size) {
			t.Fatalf("a frame is cut off")
		}
		out = append(out, raw[w:w+int(size)])
		raw = raw[w+int(size):]
	}
	return out
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestAFrameIsItsLengthAsAVarintAndItsBytes(t *testing.T) {
	got, err := chunk.Frame([]byte("hello"))
	if err != nil || !bytes.Equal(got, append([]byte{5}, "hello"...)) {
		t.Errorf("Frame = %v, %v", got, err)
	}
	long, _ := chunk.Frame(make([]byte, 300))
	if long[0] != 0xac || long[1] != 0x02 || len(long) != 302 {
		t.Errorf("a 300-byte frame starts %x %x and is %d long; a varint of 300 is ac 02", long[0], long[1], len(long))
	}
}

func TestAFrameOverFourMiBIsRefused(t *testing.T) {
	if _, err := chunk.Frame(make([]byte, chunk.MaxFrame)); err != nil {
		t.Errorf("exactly 4 MiB should be fine: %v", err)
	}
	if _, err := chunk.Frame(make([]byte, chunk.MaxFrame+1)); err == nil {
		t.Error("a frame of 4 MiB and a byte was framed")
	}
}

func TestFramesSurviveSealingInOrder(t *testing.T) {
	var raw []byte
	var want [][]byte
	for _, s := range []string{"first", "second", "", "fourth"} {
		f, _ := chunk.Frame([]byte(s))
		raw = append(raw, f...)
		want = append(want, []byte(s))
	}
	chunks, err := chunk.Seal(raw, chunk.MaxChunk)
	if err != nil || len(chunks) != 1 {
		t.Fatalf("%d chunks, %v", len(chunks), err)
	}
	got := readFrames(t, chunks[0])
	if len(got) != len(want) {
		t.Fatalf("%d frames, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("frame %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// Random bytes do not compress, so 1.25 MiB of them cannot fit in one chunk of at most 256 KiB.
func TestAChunkTooBigIsCutBetweenFramesNeverInsideOne(t *testing.T) {
	const limit = 256 << 10
	var raw []byte
	var want [][]byte
	for range 20 {
		p := randomBytes(64 << 10)
		f, _ := chunk.Frame(p)
		raw = append(raw, f...)
		want = append(want, p)
	}
	chunks, err := chunk.Seal(raw, limit)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 5 {
		t.Fatalf("%d chunks for 1.25 MiB that cannot be compressed", len(chunks))
	}
	var got [][]byte
	for i, c := range chunks {
		if len(c) > limit {
			t.Errorf("chunk %d is %d bytes, over the limit", i, len(c))
		}
		got = append(got, readFrames(t, c)...) // each chunk read on its own: no frame straddles
	}
	if len(got) != len(want) {
		t.Fatalf("%d frames, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("frame %d differs or is out of order", i)
		}
	}
}

func TestACompressibleStreamIsOneChunkHoweverManyFrames(t *testing.T) {
	var raw []byte
	for range 100000 {
		f, _ := chunk.Frame(bytes.Repeat([]byte("alice "), 10))
		raw = append(raw, f...)
	}
	chunks, err := chunk.Seal(raw, chunk.MaxChunk)
	if err != nil || len(chunks) != 1 {
		t.Errorf("%d chunks, %v (%d bytes of frames)", len(chunks), err, len(raw))
	}
}

func TestOneFrameThatCannotFitIsAnErrorNotAnOversizeChunk(t *testing.T) {
	f, _ := chunk.Frame(randomBytes(300 << 10))
	if _, err := chunk.Seal(f, 100<<10); err == nil {
		t.Error("a 300 KiB random frame was sealed into a chunk limited to 100 KiB")
	}
}

// Nothing to send still has to be sendable: the last chunk may have no frames left.
func TestNothingSealsToOneValidEmptyChunk(t *testing.T) {
	chunks, err := chunk.Seal(nil, chunk.MaxChunk)
	if err != nil || len(chunks) != 1 || len(chunks[0]) == 0 {
		t.Fatalf("%d chunks, %v", len(chunks), err)
	}
	if got := readFrames(t, chunks[0]); len(got) != 0 {
		t.Errorf("%d frames in an empty chunk", len(got))
	}
}

func TestFramesThatAreCutOffAreNotSealed(t *testing.T) {
	f, _ := chunk.Frame([]byte("whole"))
	for name, raw := range map[string][]byte{
		"a body cut short":   f[:len(f)-1],
		"a length cut short": {0x80},
	} {
		if _, err := chunk.Seal(raw, chunk.MaxChunk); err == nil {
			t.Errorf("%s was sealed", name)
		}
	}
}

func TestADigestIsTheHexOfTheSHA256(t *testing.T) {
	if got, want := chunk.Digest([]byte("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Errorf("Digest = %s", got)
	}
}

// within fails the test if f does not finish: a loop that makes no progress holds the job's
// lease with heartbeats and grows without end.
func within(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("Seal does not finish")
	}
}

func framesOf(t *testing.T, payloads ...[]byte) []byte {
	t.Helper()
	var raw []byte
	for _, p := range payloads {
		f, err := chunk.Frame(p)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, f...)
	}
	return raw
}

// A small frame before a big one used to make a cut that left the same input to be cut again.
func TestAFrameThatCannotFitTheLimitEndsSealingWithAnErrorWhateverPrecedesIt(t *testing.T) {
	big := randomBytes(600 << 10)
	for name, payloads := range map[string][][]byte{
		"small then big":           {{1}, big},
		"big then small":           {big, {1}},
		"small, big, small":        {{1}, big, {2}},
		"two smalls then big":      {{1}, {2}, big},
		"the only frame is big":    {big},
		"a sequence of empty ones": {{}, {}, big},
	} {
		within(t, 20*time.Second, func() {
			if _, err := chunk.Seal(framesOf(t, payloads...), 256<<10); err == nil {
				t.Errorf("%s: a frame that compresses past the limit was sealed", name)
			}
		})
	}
}

func TestEveryPartOfAnInputThatCanBeCutFitsOrTheInputIsRefused(t *testing.T) {
	a, b := randomBytes(200<<10), randomBytes(200<<10)
	within(t, 20*time.Second, func() {
		chunks, err := chunk.Seal(framesOf(t, []byte{1}, a, []byte{2}, b, []byte{3}), 256<<10)
		if err != nil {
			t.Fatal(err)
		}
		for i, c := range chunks {
			if len(c) > 256<<10 {
				t.Errorf("chunk %d is %d bytes", i, len(c))
			}
		}
		var got int
		for _, c := range chunks {
			got += len(readFrames(t, c))
		}
		if got != 5 {
			t.Errorf("%d frames came out of 5", got)
		}
	})
}

// The service names the chunk size a job may use. A size too small to hold one event would
// give every job up, and one larger than the protocol's would be refused.
func TestTheChunkSizeTheServiceNamesIsKeptWithinWhatCanWork(t *testing.T) {
	for in, want := range map[int]int{
		-1: chunk.MaxChunk, 0: chunk.MaxChunk, 1: chunk.MinChunk, 100: chunk.MinChunk, chunk.MinChunk - 1: chunk.MinChunk,
		chunk.MinChunk: chunk.MinChunk, 1 << 20: 1 << 20, chunk.MaxChunk: chunk.MaxChunk, chunk.MaxChunk + 1: chunk.MaxChunk, 1 << 30: chunk.MaxChunk,
	} {
		if got := chunk.Limit(in); got != want {
			t.Errorf("Limit(%d) = %d, want %d", in, got, want)
		}
	}
}

// The stream limits the service has are in events and in inflated bytes, so each chunk says how
// many of both it holds.
func TestEachSealedChunkSaysHowManyFramesAndHowManyRawBytesItHolds(t *testing.T) {
	var payloads [][]byte
	for range 9 {
		payloads = append(payloads, randomBytes(40<<10))
	}
	raw := framesOf(t, payloads...)
	parts, err := chunk.SealParts(raw, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 3 {
		t.Fatalf("%d parts of 360 KiB that does not compress, with a limit of 128 KiB", len(parts))
	}
	frames, bytesRaw := 0, 0
	for i, p := range parts {
		frames += p.Frames
		bytesRaw += p.Raw
		if got := len(readFrames(t, p.Bytes)); got != p.Frames {
			t.Errorf("part %d says %d frames and holds %d", i, p.Frames, got)
		}
	}
	if frames != 9 || bytesRaw != len(raw) {
		t.Errorf("%d frames and %d raw bytes in all, want 9 and %d", frames, bytesRaw, len(raw))
	}
	if only, err := chunk.SealParts(nil, chunk.MaxChunk); err != nil || len(only) != 1 || only[0].Frames != 0 || only[0].Raw != 0 {
		t.Errorf("nothing: %+v %v", only, err)
	}
}
