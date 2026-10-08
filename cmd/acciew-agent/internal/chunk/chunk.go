// Package chunk is the wire form of a collection: frames, and the gzip chunks they travel in.
//
// A frame is an unsigned varint length and that many bytes of a CollectResponse; at most 4 MiB.
// A chunk is the gzip of whole frames; at most 8 MiB as sent. No frame is cut across two chunks.
package chunk

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// MaxFrame is the most one event may be.
	MaxFrame = 4 << 20
	// MaxChunk is the most a chunk may be as sent.
	MaxChunk = 8 << 20
	// MinChunk is the least the agent will take as a chunk limit from the service. A smaller one
	// could not hold an ordinary event.
	MinChunk = 64 << 10
)

// Limit is the chunk size to use when the service says chunk_bytes: what it says, within
// [MinChunk, MaxChunk], and MaxChunk when it says nothing.
func Limit(fromService int) int {
	if fromService <= 0 {
		return MaxChunk
	}
	return min(max(fromService, MinChunk), MaxChunk)
}

// Frame wraps one marshalled CollectResponse.
func Frame(msg []byte) ([]byte, error) {
	if len(msg) > MaxFrame {
		return nil, fmt.Errorf("an event of %d bytes is over the limit of %d", len(msg), MaxFrame)
	}
	out := binary.AppendUvarint(make([]byte, 0, len(msg)+binary.MaxVarintLen32), uint64(len(msg)))
	return append(out, msg...), nil
}

// Digest is the hex SHA-256 of a chunk's bytes, as X-Acciew-Sha256 carries it.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Part is a sealed chunk and what is in it: the figures the service's limits on a stream are in.
type Part struct {
	Bytes  []byte
	Frames int // events
	Raw    int // bytes before gzip
}

// Seal gzips frames into chunks of at most limit bytes each, cutting only between frames.
// frames is whole frames back to back. Nothing at all seals to one chunk with no frames in it.
func Seal(frames []byte, limit int) ([][]byte, error) {
	parts, err := SealParts(frames, limit)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(parts))
	for i, p := range parts {
		out[i] = p.Bytes
	}
	return out, nil
}

// SealParts is Seal, saying how many events and raw bytes each chunk holds.
func SealParts(frames []byte, limit int) ([]Part, error) {
	ends, err := boundaries(frames)
	if err != nil {
		return nil, err
	}
	return seal(frames, ends, limit)
}

// boundaries is where each frame ends.
func boundaries(frames []byte) ([]int, error) {
	var ends []int
	for pos := 0; pos < len(frames); {
		size, w := binary.Uvarint(frames[pos:])
		if w <= 0 {
			return nil, errors.New("a frame's length is cut off")
		}
		if size > uint64(len(frames)-pos-w) { //nolint:gosec // w is at most what is left, so this is not negative
			return nil, errors.New("a frame is cut off")
		}
		pos += w + int(size) //nolint:gosec // not more than what is left, by the check above
		ends = append(ends, pos)
	}
	return ends, nil
}

func seal(frames []byte, ends []int, limit int) ([]Part, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(frames); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() <= limit {
		return []Part{{Bytes: buf.Bytes(), Frames: len(ends), Raw: len(frames)}}, nil
	}
	if len(ends) < 2 {
		return nil, fmt.Errorf("one event is %d bytes compressed, over the limit of %d", buf.Len(), limit)
	}
	// Compressed size follows raw size closely, so cut into as many parts as the first
	// attempt says are needed (with some room) rather than halving until it fits.
	parts := (buf.Len()*10)/(limit*9) + 1
	cuts := split(ends, len(frames)/max(parts, 2))
	if len(cuts) < 2 {
		// No frame reached the target before the last, so one big frame follows small ones. Cut the
		// first frame off: every part then has fewer frames than the whole, and sealing ends.
		cuts = []int{ends[0], ends[len(ends)-1]}
	}
	var out []Part
	start := 0
	for _, cut := range cuts {
		part := make([]int, 0, len(ends))
		for _, e := range ends {
			if e > start && e <= cut {
				part = append(part, e-start)
			}
		}
		chunks, err := seal(frames[start:cut], part, limit)
		if err != nil {
			return nil, err
		}
		out = append(out, chunks...)
		start = cut
	}
	return out, nil
}

// split is where to cut: after the first frame that brings a part to the target size, and so
// on, and at the end. A target that no frame reaches before the last gives one cut.
func split(ends []int, target int) []int {
	var cuts []int
	start := 0
	for i, e := range ends {
		if i == len(ends)-1 {
			cuts = append(cuts, e)
		} else if e-start >= target {
			cuts = append(cuts, e)
			start = e
		}
	}
	return cuts
}
