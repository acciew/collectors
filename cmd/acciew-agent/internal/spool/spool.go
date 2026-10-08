// Package spool holds a job's frames on disk between the collector that makes them and the
// uploads that take them away, so that a slow or absent network costs disk and not memory,
// and the collector is never waiting on a request.
//
// It is one file, appended to by one writer and read from by one reader. Its size is capped:
// at the cap the writer stops the collector and ends the stream at the last checkpoint.
package spool

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"go.acciew.io/collector/cmd/acciew-agent/internal/chunk"
)

// ErrFull is a frame that would take the spool past its cap. Nothing was written.
var ErrFull = errors.New("the spool is full")

var errGone = errors.New("the spool is closed")

const pattern = "job-*.frames"

// Spool is one job's frames.
type Spool struct {
	f     *os.File
	path  string
	limit int64

	mu         sync.Mutex
	changed    chan struct{} // closed and replaced whenever anything moves
	written    int64
	checkpoint int64   // the end of the last checkpoint's frame; 0 for none
	first      int64   // the end of the first checkpoint's frame; 0 for none
	cps        []int64 // the end of each checkpoint's frame, in order
	completed  bool    // the stream ended with a completion
	taken      int64   // what Next has returned
	ended      bool
	cut        int64 // where the stream ends, once it has
	gone       bool
}

// Create makes the spool's file in dir, which is made too: 0700, and the file 0600.
func Create(dir string, limit int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("making the spool directory: %w", err)
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, fmt.Errorf("making the spool: %w", err)
	}
	return &Spool{f: f, path: f.Name(), limit: limit, changed: make(chan struct{})}, nil
}

// Clean removes the spools a crash left in dir. A job that was running when the agent died
// is offered again as a new attempt, with a new stream, so nothing in one is wanted.
func Clean(dir string) error {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return err
	}
	for _, m := range matches {
		if err := os.Remove(m); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Path is where the spool is.
func (s *Spool) Path() string { return s.path }

// Written is how many bytes of frames have been appended.
func (s *Spool) Written() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written
}

// FirstCheckpoint is where the first checkpoint's frame ends, or 0 if there has been none: if
// that much has been taken, a checkpoint has gone up, and a stream cut now can be resumed.
func (s *Spool) FirstCheckpoint() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.first
}

// CheckpointBefore is where the last checkpoint ends that ends at or before the n-th byte, or 0 if
// none does: what the service keeps of a stream of which n bytes were sent.
func (s *Spool) CheckpointBefore(n int64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := sort.Search(len(s.cps), func(i int) bool { return s.cps[i] > n })
	if i == 0 {
		return 0
	}
	return s.cps[i-1]
}

// Taken is how many bytes of frames Next has returned.
func (s *Spool) Taken() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.taken
}

// Completed says the stream ended with the collector's completion, and not before it finished.
func (s *Spool) Completed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// signal wakes whoever waits. The caller holds the lock.
func (s *Spool) signal() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// Append adds one event: a marshalled CollectResponse. checkpoint says it is a Checkpoint.
func (s *Spool) Append(msg []byte, checkpoint bool) error { return s.append(msg, checkpoint, false) }

// reserve is the room kept at the end of the cap for the completion, so that it fits and the
// file never goes past its cap: an eighth of it, and at most a megabyte.
func (s *Spool) reserve() int64 { return min(1<<20, s.limit/8) }

// Reserve is the room kept at the end of the cap for the completion.
func (s *Spool) Reserve() int64 { return s.reserve() }

// AppendLast adds the Completion and ends the stream with it. Room is kept for it at the end of the
// cap; one that does not fit even there is refused, like any other frame.
func (s *Spool) AppendLast(msg []byte) error { return s.append(msg, false, true) }

func (s *Spool) append(msg []byte, checkpoint, last bool) error {
	frame, err := chunk.Frame(msg)
	if err != nil {
		return err
	}
	s.mu.Lock()
	switch {
	case s.gone:
		s.mu.Unlock()
		return errGone
	case s.ended:
		s.mu.Unlock()
		return errors.New("the spool has ended")
	case s.written+int64(len(frame)) > s.limit-s.reserve() && !last, s.written+int64(len(frame)) > s.limit:
		s.mu.Unlock()
		return ErrFull
	}
	at := s.written
	s.mu.Unlock()

	if _, err := s.f.WriteAt(frame, at); err != nil {
		return fmt.Errorf("writing the spool: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.written += int64(len(frame))
	if checkpoint {
		s.checkpoint = s.written
		s.cps = append(s.cps, s.written)
		if s.first == 0 {
			s.first = s.written
		}
	}
	if last {
		s.ended, s.cut, s.completed = true, s.written, true
	}
	s.signal()
	return nil
}

// End says no more is coming: what is there is the whole stream.
func (s *Spool) End() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ended {
		s.ended, s.cut = true, s.written
		s.signal()
	}
}

// EndAtCheckpoint ends the stream at the last checkpoint and drops what follows it. If
// chunks went up past it already (they are cut by size, not at checkpoints) those stay
// where they are; the next stream sends the records again.
func (s *Spool) EndAtCheckpoint() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ended {
		s.ended, s.cut = true, s.checkpoint
		s.signal()
	}
}

// Next waits until target bytes of whole frames are waiting, or the stream has ended, and
// returns them: frames back to back, as many as fit in target (one at least, however large).
// final says that nothing is left after these.
func (s *Spool) Next(ctx context.Context, target int) (frames []byte, final bool, err error) {
	for {
		s.mu.Lock()
		if s.gone {
			s.mu.Unlock()
			return nil, false, errGone
		}
		end := s.written
		if s.ended {
			end = s.cut
		}
		pending := end - s.taken
		if pending >= int64(target) || s.ended {
			from := s.taken
			s.mu.Unlock()
			frames, err = s.read(from, end, target)
			if err != nil {
				return nil, false, err
			}
			s.mu.Lock()
			s.taken = from + int64(len(frames))
			final = s.ended && s.taken >= s.cut
			s.mu.Unlock()
			return frames, final, nil
		}
		wait := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-wait:
		}
	}
}

// read takes whole frames from [from, end) up to target bytes.
func (s *Spool) read(from, end int64, target int) ([]byte, error) {
	window := min(end-from, int64(target)+chunk.MaxFrame+binary.MaxVarintLen32)
	if window <= 0 {
		return nil, nil
	}
	buf := make([]byte, window)
	if _, err := s.f.ReadAt(buf, from); err != nil {
		return nil, fmt.Errorf("reading the spool: %w", err)
	}
	pos := 0
	for pos < len(buf) {
		size, w := binary.Uvarint(buf[pos:])
		if w <= 0 || size > uint64(len(buf)-pos-w) { //nolint:gosec // w is at most what is left, so this is not negative
			break // the window ends inside this frame; it is for the next call
		}
		frameLen := w + int(size) //nolint:gosec // not more than what is left, by the check above
		if pos > 0 && pos+frameLen > target {
			break
		}
		pos += frameLen
		if pos >= target {
			break
		}
	}
	return buf[:pos], nil
}

// Remove closes and deletes the spool. It is safe to call twice, and wakes a reader.
func (s *Spool) Remove() error {
	s.mu.Lock()
	if s.gone {
		s.mu.Unlock()
		return nil
	}
	s.gone = true
	s.signal()
	s.mu.Unlock()
	cerr := s.f.Close()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return cerr
}
