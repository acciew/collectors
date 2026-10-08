// Package job runs one job the service offered: it finds the collector, resolves the references
// in the job's configuration into files the collector can read, starts the collector, checks
// every event it sends against the contract, spools the events and uploads them as chunks,
// holds the lease with heartbeats, and ends the job in one of five ways (see Outcome).
package job

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/cmd/acciew-agent/internal/backoff"
	"go.acciew.io/collector/cmd/acciew-agent/internal/chunk"
	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/host"
	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
	"go.acciew.io/collector/cmd/acciew-agent/internal/session"
	"go.acciew.io/collector/cmd/acciew-agent/internal/spool"
)

// SecretsPolicy is where a job's references are resolved from and what they may name.
type SecretsPolicy = secrets.Policy

// Defaults, each overridable in Config.
const (
	// DefaultSpoolLimit is the most one job's frames may take on disk.
	DefaultSpoolLimit = 2 << 30
	// DefaultRawTarget is how many bytes of frames are gathered before a chunk is sealed. They
	// compress, and a chunk inflates to at most 64 MiB at the service.
	DefaultRawTarget = 24 << 20
	// DefaultStreamChunks and DefaultStreamBytes are how much of the service's limit for one stream (1024
	// chunks, 2 GiB compressed) the agent uses before it ends the stream early: the rest of the room is
	// for the chunk that ends it.
	DefaultStreamChunks = 1000
	DefaultStreamBytes  = 19 << 30 / 10
	// DefaultStreamEvents and DefaultStreamInflated are how much of a collection the agent sends before it
	// gives the source up as too big, and DefaultMaxStreamEvents and DefaultMaxStreamInflated the service's
	// limits for a whole collection (the streams of a run, each to its checkpoint): 1,000,000 events and
	// 2 GiB inflated. They are not the stream's: stitching eight streams of a million events each is eight
	// times the memory the service reads a collection in, so ending a stream early at the limit would only
	// put off the failure. The chunk that carries the completion may go to the limit itself, since giving up
	// on a collection that is whole would throw it away.
	DefaultStreamEvents      = 990_000
	DefaultMaxStreamEvents   = 1_000_000
	DefaultStreamInflated    = 19 << 30 / 10
	DefaultMaxStreamInflated = 2 << 30
	completionSlack          = 64 << 20 // how far past the byte limit of a stream the chunk with the completion may go
	// DefaultPatience is how long one chunk is retried before the job is given up. A lease is
	// five minutes: by then the service has offered the job again.
	DefaultPatience = 10 * time.Minute

	// maxCursor is the most a checkpoint's cursor may be: the service keeps it and hands it back.
	maxCursor = 64 << 10

	collectorPrefix = "acciew-collector-"
	maxReason       = 500
)

var collectorName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Config is everything a Runner needs.
type Config struct {
	Client  *client.Client
	Session *session.Session
	// CollectorsDir holds acciew-collector-<name> files. A job names a collector, never a path.
	CollectorsDir string
	// SpoolDir is where a job's frames wait.
	SpoolDir string
	Secrets  SecretsPolicy
	// PassEnv names the agent's variables a collector may inherit (proxy and certificate settings),
	// read where Secrets.LookupEnv reads: the agent's environment, or what a test gives it.
	PassEnv []string

	// StreamChunks and StreamBytes are how many chunks and how many compressed bytes one stream
	// may have before it is ended early, when zero the defaults below.
	StreamChunks int
	StreamBytes  int64
	// StreamEvents and StreamInflated are the most one collection may hold before a source is given up on
	// (the budget), and MaxStreamEvents and MaxStreamInflated the most the chunk that carries the completion
	// may bring it to (the service's own limits). Zero is the defaults below.
	StreamEvents      int
	MaxStreamEvents   int
	StreamInflated    int64
	MaxStreamInflated int64

	// SpoolLimit, RawTarget and UploadPatience are the defaults above when zero.
	SpoolLimit     int64
	RawTarget      int
	UploadPatience time.Duration
	Backoff        backoff.Policy
	// HeartbeatEvery is how often to hold the lease; nil is what the job says.
	HeartbeatEvery func(*client.Job) time.Duration
	// Now is the clock for the account of what a run has sent; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
}

// Runner runs jobs, one at a time.
type Runner struct {
	Config

	mu sync.Mutex
	// spent is, for each run that has had a stream ended early, how many inflated bytes the service keeps of
	// its streams (each to its last checkpoint). The service's limit on data is for the whole collection and it
	// does not say how much of it is gone, so the agent keeps the account itself, for as long as it runs. After a
	// restart the account starts again at nothing, and a collection too big for the service is then refused by it
	// when it reads it. An account is dropped when the run's job ends any other way, and when it is a day and a
	// half old.
	spent map[string]account
}

type account struct {
	bytes int64
	at    time.Time
}

const (
	// accountLife is how long an account is kept: a run is given up on by the service long before.
	accountLife = 36 * time.Hour
	// maxAccounts bounds the map; past it the oldest account goes.
	maxAccounts = 1024
)

// New makes a Runner. A Backoff left empty is the schedule the loop uses for the service.
func New(c Config) *Runner {
	if c.Backoff == (backoff.Policy{}) {
		c.Backoff = backoff.Defaults
	}
	return &Runner{Config: c, spent: map[string]account{}}
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Spent is how many bytes of data the streams of a run that ended early have sent, as the agent counts
// them. It is nothing once the run is over.
func (r *Runner) Spent(run string) int64 { return r.spentOf(run) }

func (r *Runner) spentOf(run string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.spent[run]
	if !ok || r.now().Sub(a.at) > accountLife {
		return 0
	}
	return a.bytes
}

// spend adds to what a run's streams have sent; forget ends the account. The map is bounded by age
// and by number, and never wiped: the accounts of runs that are still going are the point of it.
func (r *Runner) spend(run string, n int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for id, a := range r.spent {
		if now.Sub(a.at) > accountLife {
			delete(r.spent, id)
		}
	}
	if _, known := r.spent[run]; !known && len(r.spent) >= maxAccounts {
		oldest, when := "", now
		for id, a := range r.spent {
			if a.at.Before(when) {
				oldest, when = id, a.at
			}
		}
		delete(r.spent, oldest)
	}
	r.spent[run] = account{bytes: r.spent[run].bytes + n, at: now}
}

func (r *Runner) forget(run string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.spent, run)
}

// Outcome is how a job ended.
type Outcome int

const (
	// Uploaded: the stream's last chunk is in the service. Whether the collection was whole is
	// the service's to say, from the Completion in it.
	Uploaded Outcome = iota + 1
	// Aborted: the agent could not do the job and told the service why.
	Aborted
	// LeaseLost: the service gave the job to another attempt. The collector was stopped.
	LeaseLost
	// Failed: the job did not complete and the service could not be told, or does not accept this agent.
	Failed
	// Cancelled: the agent was asked to stop.
	Cancelled
)

func (o Outcome) String() string {
	switch o {
	case Uploaded:
		return "uploaded"
	case Aborted:
		return "aborted"
	case LeaseLost:
		return "lease lost"
	case Failed:
		return "failed"
	case Cancelled:
		return "cancelled"
	}
	return "unknown"
}

// Result is what happened. Reason is for people and has been scrubbed of anything resolved.
type Result struct {
	Outcome Outcome
	Reason  string
	Chunks  int
	// EndedEarly: the last chunk carried no completion (the collector's stream ended without
	// one, or the spool was full) and the service offers the job again, resumed.
	EndedEarly bool
}

var (
	errLeaseLost = errors.New("the service has given this job to another attempt")
	// errRunGone is the service saying the stream is not this agent's, or is closed: the run is over, or
	// is not this agent's any more.
	errRunGone = errors.New("the service says this run is over")
	errRevoked = errors.New("the service no longer accepts this agent")
	// errStoppedAtLimit is why the collector was stopped when the spool or the service's limits were
	// reached: a planned end of the stream, not a failure.
	errStoppedAtLimit = errors.New("the collector was stopped at a limit")
	// errTooLarge is the service refusing a chunk as over a limit it has and the agent can only guess at.
	errTooLarge = errors.New("the service refused a chunk as too large")
)

// cause is why a context ended, and nil if the collector was stopped on purpose.
func cause(ctx context.Context) error {
	if c := context.Cause(ctx); !errors.Is(c, errStoppedAtLimit) {
		return c
	}
	return nil
}

// giveUp is a reason the job cannot be done, written to be sent to the service: it names what
// is wrong and never holds a value. Whatever might is scrubbed before it leaves.
type giveUp struct{ reason string }

func (g *giveUp) Error() string { return g.reason }

func giveUpf(format string, args ...any) *giveUp { return &giveUp{fmt.Sprintf(format, args...)} }

// shared is what the goroutines of one job tell each other.
type shared struct {
	finalSent  atomic.Bool
	endedEarly atomic.Bool
	chunks     atomic.Int32
	inflated   atomic.Int64 // frame bytes sent in this stream
	kept       atomic.Int64 // ... of which the service keeps: those up to the last checkpoint
	rejected   atomic.Bool  // the collector could not use the cursor and started over
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Run does one job to the end. It returns when the job is over, whatever way.
func (r *Runner) Run(ctx context.Context, j *client.Job) Result {
	log := r.log().With("run", j.Run, "stream", j.Stream, "collector", j.Collector, "attempt", j.Attempt)
	jobCtx, cancel := context.WithCancelCause(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(nil); wg.Wait() }()
	st := &shared{}

	wg.Go(func() { r.heartbeats(jobCtx, cancel, j, st, log) })

	p, redact, err := r.prepare(jobCtx, j, log)
	if err != nil {
		cancel(err)
		return r.conclude(ctx, jobCtx, j, redact, st, log)
	}
	defer p.close()

	spl, err := spool.Create(r.SpoolDir, r.spoolLimit())
	if err != nil {
		cancel(giveUpf("the agent could not make its spool: %v", err))
		return r.conclude(ctx, jobCtx, j, redact, st, log)
	}
	defer func() { _ = spl.Remove() }()

	collectCtx, stopCollector := context.WithCancelCause(jobCtx)
	defer stopCollector(nil)

	uploaded := make(chan error, 1)
	wg.Go(func() {
		err := r.upload(jobCtx, spl, j, st, stopCollector, log)
		if err != nil {
			cancel(err)
		}
		uploaded <- err
	})

	if err := r.produce(collectCtx, p, j, spl, st, stopCollector, log); err != nil {
		cancel(err)
	}
	<-uploaded
	// The service keeps a stream that ended early to its last checkpoint and drops what is after it, which
	// the next stream sends again: only what is kept is spent.
	st.kept.Store(spl.CheckpointBefore(st.inflated.Load()))
	return r.conclude(ctx, jobCtx, j, redact, st, log)
}

// conclude reads why the job ended and, where the service should hear of it, tells it.
func (r *Runner) conclude(ctx, jobCtx context.Context, j *client.Job, redact *secrets.Redactor, st *shared, log *slog.Logger) Result {
	res := Result{Chunks: int(st.chunks.Load()), EndedEarly: st.endedEarly.Load()}
	cause := context.Cause(jobCtx)
	var give *giveUp
	keep := false
	switch {
	case ctx.Err() != nil:
		res.Outcome, res.Reason = Cancelled, "the agent was asked to stop"
	case cause == nil:
		res.Outcome = Uploaded
	case errors.Is(cause, errLeaseLost):
		res.Outcome, res.Reason, keep = LeaseLost, cause.Error(), true
	case errors.Is(cause, errRunGone):
		res.Outcome, res.Reason = LeaseLost, cause.Error()
	case errors.Is(cause, errRevoked):
		res.Outcome, res.Reason = Failed, cause.Error()
	case errors.As(cause, &give):
		res.Outcome, res.Reason = Aborted, scrub(redact, give.reason)
		if err := r.abort(ctx, j, res.Reason); err != nil {
			switch {
			case leaseLost(err):
				res.Outcome, keep = LeaseLost, true
			case runGone(err):
				res.Outcome = LeaseLost
			}
			log.Warn("the service could not be told the job was given up", "error", err)
		}
	default:
		res.Outcome, res.Reason, keep = Failed, scrub(redact, cause.Error()), true
	}
	if ctx.Err() != nil {
		keep = true
	}
	// The account is the run's, and the run goes on until it is finished, given up on by the agent, or gone
	// from the service. A job that ends in a lost lease or because the agent is stopped is the service offering
	// the run again, with the earlier streams kept: its account stays. One that rejected its cursor stands
	// alone, and the service lets the earlier streams go: it starts again.
	if st.rejected.Load() {
		r.forget(j.Run)
	}
	// What this stream sent is spent to its last checkpoint whenever the run goes on: the service resumes
	// from there on any stream that ended, and a lost lease or a stop is one.
	switch {
	case res.EndedEarly && res.Outcome == Uploaded:
		r.spend(j.Run, st.kept.Load())
	case keep:
		if n := st.kept.Load(); n > 0 {
			r.spend(j.Run, n)
		}
	default:
		r.forget(j.Run)
	}
	log.Info("job ended", "outcome", res.Outcome.String(), "reason", res.Reason, "chunks", res.Chunks, "ended_early", res.EndedEarly)
	return res
}

// scrub makes a reason one short line with nothing resolved in it. It is cleaned first, as a whole (the
// pieces of a reason are put together before this, and a credential can be in two of them), and cut to
// length last, so that no half of a credential is left by the cut.
func scrub(redact *secrets.Redactor, s string) string {
	s = redact.Line(s)
	if r := []rune(s); len(r) > maxReason {
		s = string(r[:maxReason-1]) + "…"
	}
	return s
}

func (r *Runner) abort(ctx context.Context, j *client.Job, reason string) error {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	return r.Session.Do(actx, func(tok string) error { return r.Client.Abort(actx, tok, j.Stream, reason) })
}

// leaseLost is the service moving the run to another attempt; runGone, its saying the stream is closed
// or is not this agent's.
func leaseLost(err error) bool {
	var e *client.APIError
	return errors.As(err, &e) && e.Status == http.StatusConflict && e.Code == "lease_lost"
}

func runGone(err error) bool {
	var e *client.APIError
	return errors.As(err, &e) && (e.Status == http.StatusNotFound || (e.Status == http.StatusConflict && e.Code == "stream_closed"))
}

func revoked(err error) bool {
	var e *client.APIError
	return errors.As(err, &e) && e.Status == 403
}

func (r *Runner) streamChunks() int {
	if r.StreamChunks > 0 {
		return r.StreamChunks
	}
	return DefaultStreamChunks
}

func (r *Runner) streamBytes() int64 {
	if r.StreamBytes > 0 {
		return r.StreamBytes
	}
	return DefaultStreamBytes
}

func (r *Runner) streamEvents() int {
	if r.StreamEvents > 0 {
		return r.StreamEvents
	}
	return DefaultStreamEvents
}

func (r *Runner) maxStreamEvents() int {
	if r.MaxStreamEvents > 0 {
		return r.MaxStreamEvents
	}
	return DefaultMaxStreamEvents
}

func (r *Runner) maxStreamInflated() int64 {
	if r.MaxStreamInflated > 0 {
		return r.MaxStreamInflated
	}
	return DefaultMaxStreamInflated
}

func (r *Runner) streamInflated() int64 {
	if r.StreamInflated > 0 {
		return r.StreamInflated
	}
	return DefaultStreamInflated
}

func (r *Runner) spoolLimit() int64 {
	if r.SpoolLimit > 0 {
		return r.SpoolLimit
	}
	return DefaultSpoolLimit
}

func (r *Runner) rawTarget() int {
	if r.RawTarget > 0 {
		return r.RawTarget
	}
	return DefaultRawTarget
}

func (r *Runner) patience() time.Duration {
	if r.UploadPatience > 0 {
		return r.UploadPatience
	}
	return DefaultPatience
}

// heartbeats holds the lease every heartbeat_seconds while the job runs.
func (r *Runner) heartbeats(ctx context.Context, cancel context.CancelCauseFunc, j *client.Job, st *shared, log *slog.Logger) {
	every := 30 * time.Second
	switch {
	case r.HeartbeatEvery != nil:
		every = r.HeartbeatEvery(j)
	case j.HeartbeatSeconds > 0:
		every = time.Duration(j.HeartbeatSeconds) * time.Second
	}
	tick := time.NewTicker(max(every, time.Millisecond))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		err := r.Session.Do(ctx, func(tok string) error { return r.Client.Heartbeat(ctx, tok, j.Stream) })
		var api *client.APIError
		switch {
		case err == nil, ctx.Err() != nil:
		case errors.As(err, &api) && api.Code == "stream_closed" && st.finalSent.Load():
			return // the last chunk closed the stream; this is not a lost lease
		case leaseLost(err):
			cancel(errLeaseLost)
			return
		case runGone(err):
			cancel(errRunGone)
			return
		case revoked(err):
			cancel(errRevoked)
			return
		default:
			log.Warn("a heartbeat failed; trying again at the next", "error", err)
		}
	}
}

// prepared is a collector, ready to be asked for its inventory.
type prepared struct {
	plugin *host.Plugin
	bound  *secrets.Bound
	req    *collectorv1.CollectRequest
	name   string
}

func (p *prepared) close() {
	if p.plugin != nil {
		p.plugin.Close()
	}
	if p.bound != nil {
		_ = p.bound.Close()
	}
}

// prepare gets a job as far as a running, configured collector, or says why it cannot. The
// redactor comes back either way: a reason for failing can hold what a collector echoed.
func (r *Runner) prepare(ctx context.Context, j *client.Job, log *slog.Logger) (p *prepared, redact *secrets.Redactor, err error) {
	p = &prepared{name: j.Collector}
	defer func() {
		if err != nil {
			p.close()
			p = nil
		}
	}()
	if !collectorName.MatchString(j.Collector) {
		return p, nil, giveUpf("the job names %q, which is not the name of a collector", truncate(j.Collector, 64))
	}
	if !j.NoBudget() {
		return p, nil, giveUpf("this agent does not run a job that carries a budget: the protocol does not yet say what one is")
	}
	resume, rerr := j.Resume()
	if rerr != nil {
		return p, nil, giveUpf("the job's resume cursor cannot be used: %v", rerr)
	}
	path := filepath.Join(r.CollectorsDir, collectorPrefix+j.Collector)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return p, nil, giveUpf("no collector called %q is installed on this agent", j.Collector)
	}

	policy := r.Secrets
	if p.bound, err = policy.Bind(j.Config); err != nil {
		return p, nil, giveUpf("the agent could not resolve the references in the configuration: %v", err)
	}
	redact = p.bound.Redact
	// What the collector is handed in its environment is a credential when its name says so (a secret
	// key, a token, a password), when it is an address with a password in it, and when it leads to an AWS
	// credentials file. The other variables are settings.
	policy.Warn = func(message string) { log.Warn(redact.Line(message)) }
	if err := policy.WatchPassed(redact, r.PassEnv); err != nil {
		return p, redact, giveUpf("%v", err)
	}
	if p.plugin, err = host.Launch(ctx, path, host.Options{
		Env: host.ChildEnv(r.PassEnv, r.Secrets.LookupEnv), Dir: r.CollectorsDir, Log: log, Scrub: redact.Line,
	}); err != nil {
		log.Warn("the collector could not be started", "collector", j.Collector, "error", redact.Line(err.Error()))
		return p, redact, giveUpf("the collector %q could not be started (the agent's log has the detail)", j.Collector)
	}

	vctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	issues, err := p.plugin.ValidateConfig(vctx, p.bound.Config)
	if err != nil {
		log.Warn("the collector could not check its configuration", "collector", j.Collector, "error", redact.Line(err.Error()))
		return p, redact, giveUpf("the collector %q could not check its configuration (%s)", j.Collector, host.Code(err))
	}
	var bad []string
	for _, i := range issues {
		if i.GetSeverity() == collectorv1.Severity_SEVERITY_ERROR {
			// The field and the code are the collector's vocabulary; its sentence may hold anything,
			// including what it was handed, so it stays in the agent's log.
			// Cleaned before they are cut (a cut can leave twenty characters of a credential), and
			// the reason they go into is cleaned again as a whole.
			field, code := redact.Line(i.GetField()), redact.Line(i.GetCode())
			bad = append(bad, strings.TrimSpace(truncate(field, 80)+" "+truncate(code, 80)))
			log.Warn("the collector refused its configuration", "collector", j.Collector, "field", field, "code", code, "message", redact.Line(i.GetMessage()))
		}
	}
	if len(bad) > 0 {
		return p, redact, giveUpf("the collector %q rejected the configuration: %s", j.Collector, strings.Join(bad[:min(len(bad), 3)], "; "))
	}
	p.req = &collectorv1.CollectRequest{Config: p.bound.Config, Scopes: j.Scopes}
	if resume != nil {
		// The collector picks up where the earlier attempt's last checkpoint was. It says in its
		// completion that its stream is only the rest; the agent passes that on as it is.
		p.req.ResumeFrom = &collectorv1.Cursor{Token: resume}
		log.Info("resuming from the cursor of an earlier attempt", "bytes", len(resume))
	}
	return p, redact, nil
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// produce reads the collector's events, checks each against the contract, and spools them.
// It returns nil when the stream is in the spool (whole, or ended early), and an error when
// the job must stop: a giveUp for a collector that broke the contract or failed.
func (r *Runner) produce(ctx context.Context, p *prepared, j *client.Job, spl *spool.Spool, st *shared, stopCollector context.CancelCauseFunc, log *slog.Logger) error {
	stream, err := p.plugin.Collect(ctx, p.req)
	if err != nil {
		if ctx.Err() != nil {
			return cause(ctx)
		}
		log.Warn("the collection could not start", "collector", p.name, "error", p.bound.Redact.Line(err.Error()))
		return giveUpf("the collector %q could not start the collection (%s)", p.name, host.Code(err))
	}
	var (
		seen        collectorv1.Counters
		records     int
		checkpoints int
		completed   bool
		rejected    bool // the collector said it could not use the cursor and started over
	)
	resumed := p.req.GetResumeFrom() != nil
	scan := p.bound.Redact.Scanner()
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return cause(ctx)
			}
			log.Warn("the collector's stream failed", "collector", p.name, "status", host.Code(err), "error", p.bound.Redact.Line(host.Plain(err).Error()))
			if status.Code(err) == codes.ResourceExhausted {
				// An event the agent cannot receive is there on every start: ending early would only repeat it.
				return giveUpf("the collector %q sent an event over the limit of %d bytes (%s)", p.name, chunk.MaxFrame, host.Code(err))
			}
			// A collector that dies has not finished. The stream ends at its last checkpoint, as when a
			// spool fills, and the service offers the job again from there, up to eight starts.
			log.Warn("ending the stream at its last checkpoint")
			spl.EndAtCheckpoint()
			return nil
		}
		if completed {
			return violation(p.name, collectorv1.Violation{Field: "event", Rule: "completion-must-be-last", Message: "an event arrived after the completion marker"})
		}
		if vs := collectorv1.ValidateEvent(ev); len(vs) > 0 {
			return violation(p.name, vs[0])
		}
		isCheckpoint := false
		switch e := ev.GetEvent().(type) {
		case *collectorv1.CollectResponse_Node:
			records++
			seen.CountNode(e.Node)
		case *collectorv1.CollectResponse_Edge:
			records++
			seen.Edges++
		case *collectorv1.CollectResponse_Activity:
			records++
			seen.Activities++
		case *collectorv1.CollectResponse_Checkpoint:
			// A checkpoint is where the collection resumes from, and the cursor is how: the service
			// refuses a chunk that holds one without, or with one it cannot keep.
			switch token := e.Checkpoint.GetCursor().GetToken(); {
			case len(token) == 0:
				return violation(p.name, collectorv1.Violation{Field: "checkpoint.cursor", Rule: "checkpoint-cursor-required", Message: "a checkpoint carries the cursor to resume from"})
			case len(token) > maxCursor:
				return violation(p.name, collectorv1.Violation{Field: "checkpoint.cursor", Rule: "checkpoint-cursor-too-large", Message: fmt.Sprintf("a cursor is at most %d bytes and this one is %d", maxCursor, len(token))})
			}
			checkpoints++
			isCheckpoint = true
		case *collectorv1.CollectResponse_Diagnostic:
			if e.Diagnostic.GetCode() == "cursor.rejected" {
				rejected = true
				st.rejected.Store(true)
			}
		case *collectorv1.CollectResponse_Completion:
			// A stream that resumed carries the rest of the collection, and cannot say it is the whole of
			// it; one that could not use the cursor started over and says so, and stands alone.
			if resumed && !rejected && e.Completion.GetVerdict() == collectorv1.Verdict_VERDICT_COMPLETE {
				return violation(p.name, collectorv1.Violation{Field: "completion.verdict", Rule: "resumed-stream-must-not-be-complete", Message: "a stream that resumed from a cursor ends INCOMPLETE with PARTIAL_STREAM"})
			}
			// What the service would refuse the stream for, said here and now.
			if declared := e.Completion.GetCounts(); declared != nil {
				if vs := seen.Disagreements(declared); len(vs) > 0 {
					return violation(p.name, vs[0])
				}
			}
			if records > 0 && checkpoints == 0 {
				return violation(p.name, collectorv1.Violation{Field: "checkpoint", Rule: "checkpoint-required", Message: "a stream that emits records must offer at least one checkpoint to resume from"})
			}
		}
		msg, err := proto.Marshal(ev)
		if err != nil {
			return giveUpf("an event from the collector %q could not be encoded: %v", p.name, err)
		}
		// The agent holds the values it resolved, and nothing the service is sent should hold one,
		// whoever wrote it there. The event is dropped here, before it can be spooled or sealed.
		if hit, found := scan.Find(msg, ev); found {
			log.Warn("a collector echoed a resolved credential in an event", "collector", p.name,
				"reference", hit.Source, "part", hit.Part, "form", hit.Form)
			return giveUpf("the collector %q echoed a credential in an event (%s): that event was not uploaded and the job was given up", p.name, hit.Describe())
		}
		if _, ok := ev.GetEvent().(*collectorv1.CollectResponse_Completion); ok {
			switch err := spl.AppendLast(msg); {
			case errors.Is(err, spool.ErrFull):
				// No room for it: the stream is cut at its last checkpoint and the tail collected again.
				log.Warn("the spool has no room for the collector's completion: stopping the collector and sending what is up to its last checkpoint", "bytes", spl.Written())
				stopCollector(errStoppedAtLimit)
				spl.EndAtCheckpoint()
				return nil
			case err != nil:
				return giveUpf("the agent could not spool the collector's last event: %v", err)
			}
			completed = true
			continue
		}
		switch err := spl.Append(msg, isCheckpoint); {
		case errors.Is(err, spool.ErrFull):
			log.Warn("the spool is full: stopping the collector and sending what is up to its last checkpoint", "bytes", spl.Written())
			stopCollector(errStoppedAtLimit)
			spl.EndAtCheckpoint()
			return nil
		case err != nil:
			if ctx.Err() != nil {
				return cause(ctx)
			}
			if _, tooBig := ev.GetEvent().(*collectorv1.CollectResponse_Node); tooBig && len(msg) > chunk.MaxFrame {
				return giveUpf("the collector %q sent an event of %d bytes, over the limit of %d", p.name, len(msg), chunk.MaxFrame)
			}
			return giveUpf("the agent could not spool an event: %v", err)
		}
	}
	if !completed {
		// The service resumes from the last checkpoint, so that is where the stream ends: what the
		// collector sent after it would only be sent again.
		log.Warn("the collector ended its stream without a completion; ending the stream at its last checkpoint")
		spl.EndAtCheckpoint()
	}
	return nil
}

func violation(name string, v collectorv1.Violation) *giveUp {
	// The rule and the field are the contract's words; the message can hold the data that broke it.
	return giveUpf("the collector %q broke the contract: %s: %s", name, v.Field, v.Rule)
}

// upload takes chunks from the spool and sends them, in order, until the last is accepted. It
// ends the stream early, with a last chunk that carries nothing, when the next chunk would take
// the stream past what the service allows, or when the service refuses one as too large: the
// events after the last checkpoint sent are the next attempt's to send.
func (r *Runner) upload(ctx context.Context, spl *spool.Spool, j *client.Job, st *shared, stopCollector context.CancelCauseFunc, log *slog.Logger) error {
	// The service names the size; one too small to hold an ordinary event would give every job up.
	limit := chunk.Limit(j.ChunkBytes)
	n, sent, events, inflated := 0, int64(0), 0, int64(0)
	// The limits are the collection's. What the earlier streams of the run contribute is spent already:
	// the service says how many events (resume_events), and the agent keeps the account of the bytes.
	eventsSpent, bytesSpent := max(j.ResumeEvents, 0), r.spentOf(j.Run)
	for {
		before := spl.Taken()
		raw, final, err := spl.Next(ctx, r.rawTarget())
		if err != nil {
			return err
		}
		// Looked at after the wait: the collector says it in its first event, which is what ends the wait.
		if st.rejected.Load() {
			// The collector could not use the cursor and started over: its stream stands alone, and the
			// service lets the earlier streams go, so nothing of them is spent from it.
			eventsSpent, bytesSpent = 0, 0
		}
		parts, err := chunk.SealParts(raw, limit)
		if err != nil {
			return giveUpf("the agent could not form a chunk: %v", err)
		}
		// A checkpoint is up if the first one ended before this batch began: the batches before it were sent.
		resumable := func() bool { first := spl.FirstCheckpoint(); return first > 0 && first <= before }
		for i, part := range parts {
			c := part.Bytes
			last := final && i == len(parts)-1
			completes := last && spl.Completed()
			// A source with more than a collection may hold cannot be helped by ending the stream early: the
			// next one would add to what is already too much. Give it up, and say so.
			eventsAllowed, bytesAllowed := r.streamEvents(), r.streamInflated()
			if completes {
				eventsAllowed, bytesAllowed = r.maxStreamEvents(), r.maxStreamInflated()
			}
			if eventsSpent+events+part.Frames > eventsAllowed {
				return giveUpf("this source holds more than %s events, the most one collection may hold (the service refuses more than %s)",
					thousands(r.streamEvents()), thousands(r.maxStreamEvents()))
			}
			if bytesSpent+inflated+int64(part.Raw) > bytesAllowed {
				return giveUpf("this source holds more than %s of data, the most one collection may hold (the service refuses more than %s)",
					sizeOf(r.streamInflated()), sizeOf(r.maxStreamInflated()))
			}
			full := n >= r.streamChunks()-1 || sent+int64(len(c)) > r.streamBytes()
			if completes {
				full = n >= r.streamChunks() || sent+int64(len(c)) > r.streamBytes()+completionSlack
			}
			if full {
				return r.endEarly(ctx, j, n, resumable(), "the stream has all the chunks or bytes the service allows", st, stopCollector, log)
			}
			if last {
				st.finalSent.Store(true)
			}
			res, err := r.putChunk(ctx, j, n, c, last, log)
			if errors.Is(err, errTooLarge) {
				return r.endEarly(ctx, j, n, resumable(), fmt.Sprintf("the service refused chunk %d as over its limits", n), st, stopCollector, log)
			}
			if err != nil {
				return err
			}
			// Known from what was sent: the answer to a chunk sent again says "duplicate" and no more.
			if (last && !completes) || res.EndedEarly {
				st.endedEarly.Store(true)
				log.Info("the stream ended before the collector finished; the service offers the job again, resumed")
			}
			st.chunks.Add(1)
			sent += int64(len(c))
			events += part.Frames
			inflated += int64(part.Raw)
			st.inflated.Store(inflated)
			n++
		}
		if final {
			return nil
		}
	}
}

// endEarly stops the collector and ends the stream with a last chunk that holds nothing, as chunk
// n. What the stream already holds is kept by the service to its last checkpoint. With none up
// there is nothing to resume from and a second attempt would stop where this one did.
func (r *Runner) endEarly(ctx context.Context, j *client.Job, n int, resumable bool, why string, st *shared, stopCollector context.CancelCauseFunc, log *slog.Logger) error {
	if !resumable {
		return giveUpf("%s, and the collector has offered no checkpoint that was sent to resume from", why)
	}
	log.Warn("ending the stream early, at its last checkpoint", "why", why, "chunk", n)
	stopCollector(errStoppedAtLimit)
	empty, err := chunk.Seal(nil, chunk.MaxChunk)
	if err != nil {
		return err
	}
	st.finalSent.Store(true)
	if _, err := r.putChunk(ctx, j, n, empty[0], true, log); err != nil {
		if errors.Is(err, errTooLarge) {
			return giveUpf("%s, and the service refused even the chunk that ends the stream", why)
		}
		return err
	}
	st.endedEarly.Store(true)
	st.chunks.Add(1)
	return nil
}

// maxThrottleWait is the longest one Retry-After is believed for, and maxThrottled how long a
// chunk may be put off in all before the job is given up.
const (
	maxThrottleWait = 2 * time.Minute
	maxThrottled    = time.Hour
)

// maxUnprocessable is how many times in a row one chunk is sent again after a 422. A digest that
// does not match is damage on the way and clears at once; a chunk the service finds not well
// formed will not become well formed by being sent again.
const maxUnprocessable = 3

// putChunk sends one chunk until the service has it. An answer that is lost is not a reason
// to send different bytes: the same chunk goes again and the service says "duplicate".
func (r *Runner) putChunk(ctx context.Context, j *client.Job, n int, body []byte, final bool, log *slog.Logger) (client.ChunkResult, error) {
	start := time.Now()
	unprocessable := 0
	var throttled time.Duration
	for attempt := 0; ; attempt++ {
		var res client.ChunkResult
		err := r.Session.Do(ctx, func(tok string) (err error) {
			res, err = r.Client.PutChunk(ctx, tok, j.Stream, n, body, final)
			return err
		})
		if err == nil {
			log.Debug("chunk accepted", "n", n, "bytes", len(body), "final", final, "duplicate", res.Duplicate, "ended_early", res.EndedEarly)
			return res, nil
		}
		var api *client.APIError
		if errors.As(err, &api) && api.Status == http.StatusServiceUnavailable && api.RetryAfter > 0 && ctx.Err() == nil {
			// The service is reading as many chunks as it will at once. That is not trouble: the chunk
			// stays where it is, the agent waits as asked, and the wait is not held against it.
			wait := min(api.RetryAfter, maxThrottleWait)
			if throttled += wait; throttled > maxThrottled {
				return res, giveUpf("the service asked this agent to wait for %s before taking chunk %d", throttled.Round(time.Minute), n)
			}
			log.Debug("the service asks for a wait before taking a chunk", "n", n, "wait", wait)
			if err := backoff.Sleep(ctx, wait); err != nil {
				return res, context.Cause(ctx)
			}
			start, attempt = time.Now(), attempt-1
			continue
		}
		switch {
		case ctx.Err() != nil:
			return res, context.Cause(ctx)
		case leaseLost(err):
			return res, errLeaseLost
		case runGone(err):
			return res, errRunGone
		case revoked(err):
			return res, errRevoked
		case errors.As(err, &api) && api.Status == http.StatusRequestEntityTooLarge:
			return res, errTooLarge
		case errors.As(err, &api) && api.Status == 409:
			return res, giveUpf("the service refused chunk %d: %s", n, api.Error())
		case errors.As(err, &api) && api.Status == http.StatusUnprocessableEntity:
			if unprocessable++; unprocessable >= maxUnprocessable {
				return res, giveUpf("the service refused chunk %d: %v", n, err)
			}
		case !client.Transient(err):
			return res, giveUpf("the service refused chunk %d: %v", n, err)
		}
		wait := r.Backoff.Delay(attempt)
		if api != nil {
			wait = max(wait, min(api.RetryAfter, r.patience()))
		}
		if time.Since(start)+wait > r.patience() {
			return res, giveUpf("chunk %d could not be delivered for %s: %v", n, r.patience().Round(time.Second), err)
		}
		log.Warn("a chunk was not delivered; sending it again", "n", n, "attempt", attempt+1, "wait", wait, "error", err)
		if err := backoff.Sleep(ctx, wait); err != nil {
			return res, context.Cause(ctx)
		}
	}
}

// thousands writes 990000 as 990,000.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// sizeOf writes a number of bytes as KiB, MiB or GiB.
func sizeOf(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d KiB", n>>10)
}
