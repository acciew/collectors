package fakeservice

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// Job is what a test asks an agent to do. Config is the connection's configuration as
// stored: references, never values.
type Job struct {
	Collector string
	Config    string
	Scopes    []string
	// Budget is sent as it is; the service sends null. ResumeCursor, when set, is sent as it is
	// on the first offer; otherwise a job offered again after an early end carries the cursor
	// of the last checkpoint, as {"token": "<standard base64>"}.
	Budget, ResumeCursor string
	// ResumeEvents is the resume_events of the first offer, for a test that begins part-way. Later offers
	// say how many events the earlier streams of the run contribute: those up to each one's last checkpoint.
	ResumeEvents int
}

// Run is one offered job and what the agent did with it.
type Run struct {
	svc *Service
	job Job
	id  string

	mu         sync.Mutex
	stream     string
	agent      string
	attempts   int
	chunks     [][]byte
	finals     map[int]bool
	closed     bool // the last chunk is in
	endedEarly bool // ... and carried no completion: the run is offered again, resumed
	aborted    string
	failed     string // the run failed after three lapses
	moved      bool   // the run is on another attempt: this stream's lease is lost
	heartbeat  int
	cursor     []byte       // where an attempt offered now resumes from
	streamEv   int          // events in the latest stream so far
	cpEvents   int          // events in the latest stream up to its last checkpoint
	earlierEv  int          // events the earlier streams contribute
	history    []pastStream // the streams of earlier attempts
	claimed    chan struct{}
	done       chan struct{}
	doneOnce   sync.Once
}

// pastStream is what an earlier attempt of a run left.
type pastStream struct {
	id     string
	chunks [][]byte
	finals map[int]bool
}

// maxAttempts is how many times a run is started before it is given up on.
const maxAttempts = 8

// Queue offers a job to the next agent that asks for work.
func (s *Service) Queue(j Job) *Run {
	r := &Run{svc: s, job: j, id: uuid(), claimed: make(chan struct{}), done: make(chan struct{}), finals: map[int]bool{}}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, r)
	return r
}

// Inflated is how many bytes the chunks of the latest stream inflate to.
func (r *Run) Inflated() int {
	r.mu.Lock()
	chunks := append([][]byte(nil), r.chunks...)
	r.mu.Unlock()
	var n int
	for _, c := range chunks {
		if raw, err := inflate(c); err == nil {
			n += len(raw)
		}
	}
	return n
}

// Reoffer puts the run back to be offered again, as the service does when a lease has lapsed: to this
// agent, as a new attempt on a new stream.
func (r *Run) Reoffer() { r.svc.offerAgain(r) }

// ID is the run's id, as the job says it.
func (r *Run) ID() string { return r.id }

// Claimed is closed when an agent has been given the job.
func (r *Run) Claimed() <-chan struct{} { return r.claimed }

// Done is closed when the stream has its last chunk or an abort.
func (r *Run) Done() <-chan struct{} { return r.done }

// Stream is the id of the stream the agent was told to write to.
func (r *Run) Stream() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stream
}

func (s *Service) chunkBytes() int {
	if s.ChunkBytes > 0 {
		return s.ChunkBytes
	}
	return MaxChunkBytes
}

// FinalChunks lists the numbers of the chunks that were sent as the last.
func (r *Run) FinalChunks() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []int
	for n := range r.chunks {
		if r.finals[n] {
			out = append(out, n)
		}
	}
	return out
}

// Heartbeats is how many the agent has sent.
func (r *Run) Heartbeats() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.heartbeat
}

// Aborted is the reason the agent gave up, or "".
func (r *Run) Aborted() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aborted
}

// Chunks is how many chunks are stored, and Final whether the last one is in.
func (r *Run) Chunks() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.chunks)
}

// Final says the last chunk is in.
func (r *Run) Final() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// LoseLease is the service moving the run to another attempt: this stream's next
// heartbeat or new chunk is answered lease_lost.
func (r *Run) LoseLease() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.moved = true
}

func (r *Run) finish() { r.doneOnce.Do(func() { close(r.done) }) }

// Events reads the chunks of the latest stream the way the service reads a stream.
func (r *Run) Events() ([]*collectorv1.CollectResponse, error) {
	r.mu.Lock()
	chunks := append([][]byte(nil), r.chunks...)
	r.mu.Unlock()
	return decodeAll(chunks)
}

// AllEvents reads the streams of every attempt, oldest first, one after another. They are not
// stitched: that is the service's work, and a test that wants the whole reads each part.
func (r *Run) AllEvents() ([]*collectorv1.CollectResponse, error) {
	r.mu.Lock()
	var chunks [][]byte
	for _, h := range r.history {
		chunks = append(chunks, h.chunks...)
	}
	chunks = append(chunks, r.chunks...)
	r.mu.Unlock()
	return decodeAll(chunks)
}

// StreamEvents reads the events of the i-th attempt's stream (from 0).
func (r *Run) StreamEvents(i int) ([]*collectorv1.CollectResponse, error) {
	r.mu.Lock()
	var chunks [][]byte
	switch {
	case i < len(r.history):
		chunks = append(chunks, r.history[i].chunks...)
	case i == len(r.history):
		chunks = append(chunks, r.chunks...)
	}
	r.mu.Unlock()
	return decodeAll(chunks)
}

// StreamOf is the id of the i-th attempt's stream (from 0).
func (r *Run) StreamOf(i int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i < len(r.history) {
		return r.history[i].id
	}
	return r.stream
}

// Attempts is how many times the run has been offered and taken.
func (r *Run) Attempts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempts
}

// EndedEarly says the latest stream's last chunk carried no completion.
func (r *Run) EndedEarly() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.endedEarly
}

// Failed is why the service gave up on the run after it lapsed too often, or "".
func (r *Run) Failed() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}

// Cursor is the token an attempt offered now would resume from, or nil.
func (r *Run) Cursor() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.cursor...)
}

func decodeAll(chunks [][]byte) ([]*collectorv1.CollectResponse, error) {
	var out []*collectorv1.CollectResponse
	for n, raw := range chunks {
		events, err := decode(raw)
		out = append(out, events...)
		if err != nil {
			return out, fmt.Errorf("chunk %d: %w", n, err)
		}
	}
	return out, nil
}

// decode reads one chunk as the service does (internal/pluginhost/remote): inflate under a
// limit, then frames, each an unsigned varint length and a CollectResponse, under a limit.
func decode(raw []byte) ([]*collectorv1.CollectResponse, error) {
	inflated, err := inflate(raw)
	if err != nil {
		return nil, err
	}
	var out []*collectorv1.CollectResponse
	for len(inflated) > 0 {
		size, w := binary.Uvarint(inflated)
		if w <= 0 {
			return out, errors.New("a frame's length is cut off")
		}
		if size > math.MaxInt32 || int(size) > 4<<20 {
			return out, fmt.Errorf("a frame of %d bytes is over the limit", size)
		}
		if len(inflated)-w < int(size) {
			return out, errors.New("a frame is cut off")
		}
		var e collectorv1.CollectResponse
		if err := proto.Unmarshal(inflated[w:w+int(size)], &e); err != nil {
			return out, errors.New("a frame is not an event")
		}
		out = append(out, &e)
		inflated = inflated[w+int(size):]
	}
	return out, nil
}

// scanInfo is what a chunk says about its stream, as remote.Scan reports it.
type scanInfo struct {
	events, checkpoint int
	token              []byte
	completion         bool
}

// scan reads a chunk as it arrives. One that is not well formed, or has an event after the
// completion, is refused.
func scan(raw []byte) (scanInfo, error) {
	events, err := decode(raw)
	if err != nil {
		return scanInfo{}, err
	}
	var info scanInfo
	for _, e := range events {
		if info.completion {
			return scanInfo{}, errors.New("an event follows the completion")
		}
		info.events++
		switch ev := e.GetEvent().(type) {
		case *collectorv1.CollectResponse_Checkpoint:
			info.checkpoint, info.token = info.events, ev.Checkpoint.GetCursor().GetToken()
		case *collectorv1.CollectResponse_Completion:
			info.completion = true
		}
	}
	return info, nil
}

// ChunkBytes returns a stored chunk as it arrived.
func (r *Run) ChunkBytes(n int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.chunks[n]
}

func inflate(raw []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("it is not gzip")
	}
	b, err := io.ReadAll(io.LimitReader(zr, 64<<20+1))
	if err != nil {
		return nil, fmt.Errorf("it cannot be inflated: %w", err)
	}
	if len(b) > 64<<20 {
		return nil, errors.New("it inflates beyond 64 MiB")
	}
	return b, nil
}

// jobs holds the poll until there is a job for the agent, or the hold is over.
func (s *Service) jobs(w http.ResponseWriter, r *http.Request) {
	agent := s.authenticate(w, r)
	if agent == nil {
		return
	}
	end := time.Now().Add(s.Hold)
	for {
		if run := s.claim(agent.ID); run != nil {
			s.mu.Lock()
			lease, beat := s.LeaseSeconds, s.HeartbeatSeconds
			s.mu.Unlock()
			cfg := json.RawMessage(run.job.Config)
			if len(bytes.TrimSpace(cfg)) == 0 {
				cfg = json.RawMessage("{}")
			}
			rawOrNull := func(s string) json.RawMessage {
				if s == "" {
					return json.RawMessage("null")
				}
				return json.RawMessage(s)
			}
			run.mu.Lock()
			resumeEvents := run.job.ResumeEvents + run.earlierEv
			resume := rawOrNull(run.job.ResumeCursor)
			if run.attempts > 1 && len(run.cursor) > 0 {
				resume, _ = json.Marshal(map[string]string{"token": base64.StdEncoding.EncodeToString(run.cursor)})
			}
			run.mu.Unlock()
			scopes := run.job.Scopes
			if scopes == nil {
				scopes = []string{}
			}
			run.mu.Lock()
			stream, attempt := run.stream, run.attempts
			run.mu.Unlock()
			reply(w, http.StatusOK, map[string]any{
				"run": run.id, "stream": stream, "attempt": attempt, "source_id": "src-" + run.id[:8], "collector": run.job.Collector,
				"config": cfg, "scopes": scopes, "budget": rawOrNull(run.job.Budget), "resume_cursor": resume, "resume_events": resumeEvents,
				"lease_until":   time.Now().Add(time.Duration(lease) * time.Second).UTC().Format(time.RFC3339),
				"lease_seconds": lease, "heartbeat_seconds": beat, "chunk_bytes": s.chunkBytes(),
			}, "application/json")
			return
		}
		if !time.Now().Before(end) || r.Context().Err() != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// claim gives the agent the next queued job unless it holds one: an agent has one at a time.
func (s *Service) claim(agent string) *Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, run := range s.runs {
		run.mu.Lock()
		busy := run.agent == agent && !run.closed && run.aborted == "" && !run.moved
		run.mu.Unlock()
		if busy {
			return nil
		}
	}
	if len(s.queue) == 0 {
		return nil
	}
	run := s.queue[0]
	s.queue = s.queue[1:]
	run.mu.Lock()
	if run.attempts > 0 {
		run.history = append(run.history, pastStream{id: run.stream, chunks: run.chunks, finals: run.finals})
		run.chunks, run.finals, run.closed, run.endedEarly, run.heartbeat, run.moved = nil, map[int]bool{}, false, false, 0, false
		run.earlierEv += run.cpEvents
		run.streamEv, run.cpEvents = 0, 0
	}
	run.attempts++
	run.stream = uuid()
	run.agent = agent
	run.mu.Unlock()
	s.runs[run.stream] = run
	select {
	case <-run.claimed:
	default:
		close(run.claimed)
	}
	return run
}

var chunkNumber = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)

func (s *Service) stream(w http.ResponseWriter, r *http.Request) {
	agent := s.authenticate(w, r)
	if agent == nil {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/agent/v1/streams/")
	parts := strings.Split(rest, "/")
	s.mu.Lock()
	run := s.runs[parts[0]]
	s.mu.Unlock()
	if run == nil || run.agent != agent.ID {
		problem(w, http.StatusNotFound, "", nil)
		return
	}
	// A stream the run has moved on from is on another attempt: its lease is lost.
	run.mu.Lock()
	old := parts[0] != run.stream
	run.mu.Unlock()
	switch {
	case len(parts) == 2 && parts[1] == "heartbeat" && r.Method == http.MethodPost:
		s.heartbeat(w, run, old)
	case len(parts) == 2 && parts[1] == "abort" && r.Method == http.MethodPost:
		s.abort(w, r, run, old)
	case len(parts) == 3 && parts[1] == "chunks" && r.Method == http.MethodPut:
		s.chunk(w, r, run, parts[0], old, parts[2])
	default:
		problem(w, http.StatusNotFound, "", nil)
	}
}

func refusal(w http.ResponseWriter, status int, code, detail string, extra map[string]any) {
	body := map[string]any{"code": code}
	for k, v := range extra {
		body[k] = v
	}
	problem(w, status, detail, body)
}

func (s *Service) heartbeat(w http.ResponseWriter, run *Run, old bool) {
	run.mu.Lock()
	defer run.mu.Unlock()
	switch {
	case run.moved || old:
		refusal(w, http.StatusConflict, "lease_lost", "the run is on another attempt now: stop this job and ask for work again", nil)
	case run.closed || run.aborted != "":
		refusal(w, http.StatusConflict, "stream_closed", "this stream takes no more", nil)
	default:
		run.heartbeat++
		reply(w, http.StatusOK, map[string]any{"lease_until": time.Now().Add(time.Duration(s.LeaseSeconds) * time.Second).UTC().Format(time.RFC3339), "lease_seconds": s.LeaseSeconds}, "application/json")
	}
}

func (s *Service) abort(w http.ResponseWriter, r *http.Request, run *Run, old bool) {
	var in struct {
		Reason string `json:"reason"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if strings.TrimSpace(in.Reason) == "" {
		problem(w, http.StatusUnprocessableEntity, "say why the job cannot be done", nil)
		return
	}
	switch {
	case run.moved || old:
		refusal(w, http.StatusConflict, "lease_lost", "the run is on another attempt now", nil)
	case run.closed || run.aborted != "":
		refusal(w, http.StatusConflict, "stream_closed", "this stream takes no more", nil)
	default:
		if len(in.Reason) > 500 {
			in.Reason = in.Reason[:500]
		}
		run.aborted = in.Reason
		run.finish()
		w.WriteHeader(http.StatusNoContent)
	}
}

// refuseBeforeReading decides what can be decided of a chunk without its body, as the service does:
// a stream that is not this agent's, one that is not on this attempt, one that is closed, a number
// that is not the next, and a number that arrived before (the same bytes by the digest the agent
// sent are a duplicate, other bytes a conflict, and the stored chunk is not read). It writes the
// answer and says so, or says the body is to be read.
func (s *Service) refuseBeforeReading(w http.ResponseWriter, run *Run, streamID string, old bool, n int, digest string) bool {
	run.mu.Lock()
	defer run.mu.Unlock()
	held := run.chunks
	if old {
		held = nil
		for _, h := range run.history {
			if h.id == streamID {
				held = h.chunks
			}
		}
	}
	if n < len(held) && digest != "" {
		sum := sha256.Sum256(held[n])
		if strings.EqualFold(digest, hex.EncodeToString(sum[:])) {
			reply(w, http.StatusOK, map[string]any{"status": "duplicate", "n": n}, "application/json")
		} else {
			s.countConflict()
			refusal(w, http.StatusConflict, "chunk_conflict", "that chunk number arrived before with other bytes: the stream is refused and the run has failed", nil)
		}
		return true
	}
	if n < len(held) {
		return false // no digest to compare: the body has to be read
	}
	switch {
	case run.moved || old:
		refusal(w, http.StatusConflict, "lease_lost", "the run is on another attempt now: stop this job and ask for work again", nil)
	case run.closed || run.aborted != "":
		refusal(w, http.StatusConflict, "stream_closed", "this stream takes no more", nil)
	case n != len(run.chunks):
		refusal(w, http.StatusConflict, "out_of_order", fmt.Sprintf("chunk %d is wanted", len(run.chunks)), map[string]any{"next": len(run.chunks)})
	default:
		return false
	}
	return true
}

func (s *Service) countConflict() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conflicts++
}

// Conflicts is how many chunks arrived with other bytes under a number that had arrived.
func (s *Service) Conflicts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conflicts
}

// chunk takes one chunk. The order of the checks is the service's: what can be told without the
// body (above), then the digest, then what the chunk holds, read as it arrives and refused with
// nothing kept if it is not well formed.
func (s *Service) chunk(w http.ResponseWriter, r *http.Request, run *Run, streamID string, old bool, nText string) {
	if !chunkNumber.MatchString(nText) {
		problem(w, http.StatusNotFound, "", nil)
		return
	}
	n, _ := strconv.Atoi(nText)
	digest := strings.TrimSpace(r.Header.Get("X-Acciew-Sha256"))
	if s.refuseBeforeReading(w, run, streamID, old, n, digest) {
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxChunkBytes))
	if err != nil {
		problem(w, http.StatusRequestEntityTooLarge, "a chunk is at most 8 MiB", nil)
		return
	}
	if digest != "" {
		got := sha256.Sum256(data)
		if len(digest) != 64 || !strings.EqualFold(digest, hex.EncodeToString(got[:])) {
			problem(w, http.StatusUnprocessableEntity, "the bytes are not the ones the digest in X-Acciew-Sha256 is of: they were damaged on the way, send them again", nil)
			return
		}
	}
	final := r.Header.Get("X-Acciew-Final") == "true"
	info, err := scan(data)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "the chunk is not well formed: "+err.Error(), nil)
		return
	}
	if len(data) == 0 {
		problem(w, http.StatusUnprocessableEntity, "a chunk has bytes", nil)
		return
	}
	if info.checkpoint > 0 && len(info.token) == 0 {
		problem(w, http.StatusUnprocessableEntity, "a checkpoint carries a cursor", nil)
		return
	}
	if info.completion && !final {
		problem(w, http.StatusUnprocessableEntity, "a completion ends the stream: it goes in the last chunk", nil)
		return
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if n < len(run.chunks) && !old {
		// Sent without a digest to go by: the stored bytes are compared.
		if bytes.Equal(run.chunks[n], data) {
			reply(w, http.StatusOK, map[string]any{"status": "duplicate", "n": n}, "application/json")
			return
		}
		s.countConflict()
		refusal(w, http.StatusConflict, "chunk_conflict", "that chunk number arrived before with other bytes: the stream is refused and the run has failed", nil)
		return
	}
	if old || n != len(run.chunks) || run.closed || run.aborted != "" || run.moved {
		refusal(w, http.StatusConflict, "lease_lost", "the run is on another attempt now: stop this job and ask for work again", nil)
		return
	}
	run.chunks = append(run.chunks, data)
	if info.checkpoint > 0 {
		run.cursor = info.token
		run.cpEvents = run.streamEv + info.checkpoint
	}
	run.streamEv += info.events
	endedEarly := false
	if final {
		run.closed = true
		run.finals[n] = true
		if info.completion {
			run.finish()
		} else {
			// The stream ended before the collector finished: the run is offered again at once, resumed
			// from the last checkpoint any stream carried, unless it has been started too often.
			run.endedEarly = true
			endedEarly = true
			if run.attempts >= maxAttempts {
				run.failed = "the agent ended its stream before the collector finished " + strconv.Itoa(maxAttempts) + " times"
				run.finish()
			} else {
				go s.offerAgain(run)
			}
		}
	}
	reply(w, http.StatusCreated, map[string]any{"status": "stored", "n": n, "final": final, "ended_early": endedEarly}, "application/json")
}

// offerAgain puts a run that ended early at the front of the queue.
func (s *Service) offerAgain(run *Run) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append([]*Run{run}, s.queue...)
}
