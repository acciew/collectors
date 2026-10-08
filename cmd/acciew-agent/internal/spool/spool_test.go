package spool_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/chunk"
	"go.acciew.io/collector/cmd/acciew-agent/internal/spool"
)

func create(t *testing.T, limit int64) *spool.Spool {
	t.Helper()
	s, err := spool.Create(filepath.Join(t.TempDir(), "spool"), limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Remove() })
	return s
}

// frames splits what Next returned back into the messages that were appended.
func frames(t *testing.T, raw []byte) []string {
	t.Helper()
	var out []string
	for len(raw) > 0 {
		size, w := binary.Uvarint(raw)
		if w <= 0 || len(raw)-w < int(size) {
			t.Fatalf("Next returned a frame cut off")
		}
		out = append(out, string(raw[w:w+int(size)]))
		raw = raw[w+int(size):]
	}
	return out
}

func next(t *testing.T, s *spool.Spool, target int) ([]string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, final, err := s.Next(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	return frames(t, raw), final
}

func TestWhatIsAppendedComesBackWholeAndInOrderOnceTheTargetIsReached(t *testing.T) {
	s := create(t, 1<<20)
	for _, m := range []string{"aaaa", "bbbb", "cccc", "dddd", "eeee"} {
		if err := s.Append([]byte(m), false); err != nil {
			t.Fatal(err)
		}
	}
	// Each frame is five bytes; a target of 12 takes two and stops before a third.
	got, final := next(t, s, 12)
	if len(got) != 2 || got[0] != "aaaa" || got[1] != "bbbb" || final {
		t.Errorf("got %q final %v", got, final)
	}
	got, final = next(t, s, 12)
	if len(got) != 2 || got[0] != "cccc" || final {
		t.Errorf("got %q final %v", got, final)
	}
}

func TestAFrameBiggerThanTheTargetIsStillSentAlone(t *testing.T) {
	s := create(t, 1<<20)
	big := string(bytes.Repeat([]byte("x"), 100))
	_ = s.Append([]byte(big), false)
	_ = s.Append([]byte("y"), false)
	got, _ := next(t, s, 10)
	if len(got) != 1 || got[0] != big {
		t.Errorf("got %d frames", len(got))
	}
}

func TestNextWaitsForMoreUntilTheEndIsSaid(t *testing.T) {
	s := create(t, 1<<20)
	_ = s.Append([]byte("one"), false)
	type result struct {
		frames []string
		final  bool
	}
	done := make(chan result, 1)
	go func() {
		raw, final, err := s.Next(context.Background(), 1000)
		if err != nil {
			t.Error(err)
		}
		done <- result{frames(t, raw), final}
	}()
	select {
	case r := <-done:
		t.Fatalf("Next returned %v with less than the target and no end", r)
	case <-time.After(100 * time.Millisecond):
	}
	_ = s.Append([]byte("two"), false)
	s.End()
	r := <-done
	if len(r.frames) != 2 || !r.final {
		t.Errorf("%+v", r)
	}
}

// Room is kept for the completion, so that it never takes the file past its cap; one that does not
// fit even in that room is refused like any other frame.
func TestTheLastFrameEndsTheSpoolAndFitsInTheRoomKeptForIt(t *testing.T) {
	s := create(t, 1000) // 125 bytes of the 1000 are kept for the completion
	for range 8 {        // 160 bytes
		if err := s.Append([]byte("0123456789012345678"), false); err != nil { // 20 bytes
			t.Fatal(err)
		}
	}
	last := bytes.Repeat([]byte("c"), 100)
	if err := s.AppendLast(last); err != nil {
		t.Fatalf("the completion should fit in the room kept: %v", err)
	}
	if s.Written() > 1000 {
		t.Errorf("the spool holds %d bytes, over its cap of 1000", s.Written())
	}
	got, final := next(t, s, 1<<20)
	if len(got) != 9 || !final {
		t.Errorf("got %d frames final %v", len(got), final)
	}
	if err := s.Append([]byte("late"), false); err == nil {
		t.Error("an append after the end was taken")
	}
}

func TestACompletionThatDoesNotFitEvenTheRoomKeptForItIsRefusedAndTheSpoolIsNotPastItsCap(t *testing.T) {
	s := create(t, 1000)
	if err := s.AppendLast(bytes.Repeat([]byte("c"), 2000)); !errors.Is(err, spool.ErrFull) {
		t.Fatalf("err = %v", err)
	}
	if s.Written() != 0 {
		t.Errorf("Written = %d after a refusal", s.Written())
	}
	// And a spool that is full to the byte takes nothing more, the completion included.
	full := create(t, 1000)
	for full.Written() < 870 {
		if err := full.Append([]byte("0123456789012345678"), false); err != nil {
			break
		}
	}
	for {
		if err := full.Append([]byte("x"), false); err != nil {
			break
		}
	}
	if err := full.AppendLast(bytes.Repeat([]byte("c"), 200)); !errors.Is(err, spool.ErrFull) {
		t.Errorf("a completion past a full spool: %v", err)
	}
}

func TestAtTheCapTheFrameIsRefusedAndWhatIsThereIsKept(t *testing.T) {
	s := create(t, 12)
	if err := s.Append([]byte("aaaa"), false); err != nil { // 5 bytes
		t.Fatal(err)
	}
	if err := s.Append([]byte("bbbb"), false); err != nil { // 10
		t.Fatal(err)
	}
	if err := s.Append([]byte("cccc"), false); !errors.Is(err, spool.ErrFull) {
		t.Fatalf("third frame: %v", err)
	}
	if s.Written() != 10 {
		t.Errorf("Written = %d: a refused frame must write nothing", s.Written())
	}
}

// At the cap the stream ends at the last checkpoint: what follows it is not a point anyone
// can resume from, and the next stream sends it again.
func TestEndingAtTheLastCheckpointDropsWhatFollowsIt(t *testing.T) {
	s := create(t, 1<<20)
	_ = s.Append([]byte("n1"), false)
	_ = s.Append([]byte("c1"), true)
	_ = s.Append([]byte("n2"), false)
	_ = s.Append([]byte("c2"), true)
	_ = s.Append([]byte("n3"), false)
	s.EndAtCheckpoint()
	got, final := next(t, s, 1<<20)
	if len(got) != 4 || got[3] != "c2" || !final {
		t.Errorf("got %q final %v", got, final)
	}
}

func TestEndingAtACheckpointWithNoneSendsNothing(t *testing.T) {
	s := create(t, 1<<20)
	_ = s.Append([]byte("n1"), false)
	s.EndAtCheckpoint()
	got, final := next(t, s, 1<<20)
	if len(got) != 0 || !final {
		t.Errorf("got %q final %v", got, final)
	}
}

// Chunks are cut by size, so the cap can come after frames past the last checkpoint have gone.
func TestEndingAtACheckpointBehindWhatWasAlreadyTakenSendsNothingMore(t *testing.T) {
	s := create(t, 1<<20)
	_ = s.Append([]byte("c1"), true)
	_ = s.Append([]byte("n2"), false)
	_ = s.Append([]byte("n3"), false)
	got, final := next(t, s, 9) // takes all three, 3 bytes each
	if len(got) != 3 || final {
		t.Fatalf("got %q final %v", got, final)
	}
	s.EndAtCheckpoint()
	got, final = next(t, s, 9)
	if len(got) != 0 || !final {
		t.Errorf("got %q final %v", got, final)
	}
}

func TestEndWithNothingAppendedIsAFinalWithNothing(t *testing.T) {
	s := create(t, 1<<20)
	s.End()
	got, final := next(t, s, 100)
	if len(got) != 0 || !final {
		t.Errorf("got %q final %v", got, final)
	}
}

func TestNextGivesUpWhenItsContextDoes(t *testing.T) {
	s := create(t, 1<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := s.Next(ctx, 100); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
}

func TestTheSpoolIsAFileOnlyItsOwnerCanReadAndRemoveTakesItAway(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := spool.Create(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Append([]byte("secret-ish records"), false)
	info, err := os.Stat(s.Path())
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("spool file: %v, %v", info, err)
	}
	if err := s.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the spool is still there: %v", err)
	}
	if err := s.Remove(); err != nil {
		t.Errorf("removing twice: %v", err)
	}
	if _, _, err := s.Next(context.Background(), 1); err == nil {
		t.Error("Next on a removed spool succeeded")
	}
	if err := s.Append([]byte("x"), false); err == nil {
		t.Error("Append on a removed spool succeeded")
	}
}

func TestRemoveWakesAReaderThatIsWaiting(t *testing.T) {
	s := create(t, 1<<20)
	errc := make(chan error, 1)
	go func() { _, _, err := s.Next(context.Background(), 100); errc <- err }()
	time.Sleep(50 * time.Millisecond)
	_ = s.Remove()
	select {
	case err := <-errc:
		if err == nil {
			t.Error("Next returned no error from a removed spool")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Next is still waiting on a spool that is gone")
	}
}

func TestAFrameOverTheLimitOnTheWireIsNotSpooled(t *testing.T) {
	s := create(t, 1<<30)
	if err := s.Append(make([]byte, chunk.MaxFrame+1), false); err == nil {
		t.Error("an event of 4 MiB and a byte was spooled")
	}
}

// Stale files are what a crash leaves; a lapsed job starts again from nothing, so they go.
func TestCleanRemovesWhatACrashLeftAndNothingElse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s, _ := spool.Create(dir, 1<<20)
	other := filepath.Join(dir, "notes.txt")
	_ = os.WriteFile(other, []byte("keep"), 0o600)
	if err := spool.Clean(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Error("a stale spool was kept")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("a file that is not a spool was removed")
	}
	if err := spool.Clean(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Errorf("cleaning a directory that is not there: %v", err)
	}
}

// The uploader needs to know whether a stream that has to end early has anything to resume from,
// and whether what it ends with is a whole collection.
func TestTheSpoolSaysWhereItsFirstCheckpointEndsWhatWasTakenAndWhetherItHoldsACompletion(t *testing.T) {
	s := create(t, 1<<20)
	if s.FirstCheckpoint() != 0 || s.Taken() != 0 || s.Completed() {
		t.Fatal("a new spool claims something")
	}
	_ = s.Append([]byte("aaaa"), false) // 5 bytes
	_ = s.Append([]byte("c1"), true)    // 3 bytes: ends at 8
	_ = s.Append([]byte("bbbb"), false)
	_ = s.Append([]byte("c2"), true)
	if got := s.FirstCheckpoint(); got != 8 {
		t.Errorf("FirstCheckpoint = %d, want 8 (the first, not the last)", got)
	}
	got, _ := next(t, s, 1)
	if len(got) != 1 || s.Taken() != 5 {
		t.Errorf("taken %d after one frame of %q", s.Taken(), got)
	}
	if s.Completed() {
		t.Error("Completed before a completion")
	}
	s.EndAtCheckpoint()
	if s.Completed() {
		t.Error("a stream cut at a checkpoint is not a completed one")
	}
	if err := create(t, 10).AppendLast([]byte("done")); err != nil {
		t.Fatal(err)
	}
	done := create(t, 1<<20)
	_ = done.AppendLast([]byte("done"))
	if !done.Completed() {
		t.Error("Completed is false after AppendLast")
	}
	plain := create(t, 1<<20)
	plain.End()
	if plain.Completed() {
		t.Error("a stream that simply ended was taken for a completed one")
	}
}

// The room kept at the end of the cap is for the completion: ordinary frames stop short of it, and
// the completion then fits.
func TestOrdinaryFramesStopShortOfTheRoomKeptForTheCompletion(t *testing.T) {
	s := create(t, 1000) // an eighth, 125 bytes, is kept
	for {
		if err := s.Append([]byte("0123456789"), false); err != nil { // 11 bytes
			if !errors.Is(err, spool.ErrFull) {
				t.Fatal(err)
			}
			break
		}
	}
	if s.Written() > 875 || s.Written() < 860 {
		t.Errorf("ordinary frames filled it to %d: they should stop at 875, short of the room kept", s.Written())
	}
	if err := s.AppendLast(bytes.Repeat([]byte("c"), 120)); err != nil {
		t.Errorf("a completion of 120 bytes in the 125 kept: %v", err)
	}
	if s.Written() > 1000 {
		t.Errorf("%d bytes in a spool capped at 1000", s.Written())
	}
	// A large spool keeps no more than a megabyte.
	big := create(t, 1<<30)
	if got := big.Reserve(); got != 1<<20 {
		t.Errorf("Reserve = %d for a 1 GiB spool, want 1 MiB", got)
	}
	if got := s.Reserve(); got != 125 {
		t.Errorf("Reserve = %d for a 1000 byte spool, want 125", got)
	}
}

// A stream the service keeps to its last checkpoint: how far that is, for a number of bytes sent.
func TestCheckpointBeforeSaysWhereTheLastCheckpointThatWasSentEnds(t *testing.T) {
	s := create(t, 1<<20)
	if s.CheckpointBefore(100) != 0 {
		t.Fatal("a checkpoint before any")
	}
	_ = s.Append([]byte("aaaa"), false) // 0-5
	_ = s.Append([]byte("c1"), true)    // 5-8
	_ = s.Append([]byte("bbbb"), false) // 8-13
	_ = s.Append([]byte("c2"), true)    // 13-16
	_ = s.Append([]byte("cc"), false)   // 16-19
	for n, want := range map[int64]int64{0: 0, 7: 0, 8: 8, 9: 8, 15: 8, 16: 16, 18: 16, 19: 16, 100: 16} {
		if got := s.CheckpointBefore(n); got != want {
			t.Errorf("CheckpointBefore(%d) = %d, want %d", n, got, want)
		}
	}
}
