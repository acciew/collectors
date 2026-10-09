package client_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/cmd/acciew-agent/internal/chunk"
	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/fakeservice"
	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
)

type rig struct {
	svc    *fakeservice.Service
	c      *client.Client
	signer *identity.Signer
	id     string
}

// enrolled is an agent the service has confirmed.
func enrolled(t *testing.T) *rig {
	t.Helper()
	svc := fakeservice.New(t)
	c, err := client.New(svc.URL(), "test")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.GenerateKey()
	svc.AddEnrolment("acc_enr_x")
	got, err := c.Enroll(context.Background(), client.EnrollRequest{
		Token: "acc_enr_x", Name: "plant-1", Versions: map[string]string{"agent": "test", "protocol": "1"},
		PublicKey: base64.StdEncoding.EncodeToString(identity.PublicKey(key)),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.Confirm(got.AgentID)
	s, err := identity.NewSigner(got.AgentID, key)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{svc: svc, c: c, signer: s, id: got.AgentID}
}

func (r *rig) token(t *testing.T) string {
	t.Helper()
	a, err := r.signer.TokenAssertion(r.c.Base)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := r.c.Token(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Token
}

func apiError(t *testing.T, err error) *client.APIError {
	t.Helper()
	var e *client.APIError
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not an APIError", err)
	}
	return e
}

func TestEnrollingReturnsTheIdAndTheFingerprintTheServiceMade(t *testing.T) {
	svc := fakeservice.New(t)
	c, _ := client.New(svc.URL(), "test")
	key, _ := identity.GenerateKey()
	pub := identity.PublicKey(key)
	svc.AddEnrolment("acc_enr_x")
	got, err := c.Enroll(context.Background(), client.EnrollRequest{Token: "acc_enr_x", Name: "n", PublicKey: base64.StdEncoding.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != identity.Fingerprint(pub) || got.State != "pending" || !strings.Contains(got.AgentID, ".") {
		t.Errorf("enrolled = %+v", got)
	}
	// The token is good once.
	_, err = c.Enroll(context.Background(), client.EnrollRequest{Token: "acc_enr_x", PublicKey: base64.StdEncoding.EncodeToString(pub)})
	if e := apiError(t, err); e.Status != http.StatusUnauthorized {
		t.Errorf("a used token: %v", e)
	}
}

func TestAPendingAgentIsToldSoWhenItAsksForAToken(t *testing.T) {
	svc := fakeservice.New(t)
	c, _ := client.New(svc.URL(), "test")
	key, _ := identity.GenerateKey()
	svc.AddEnrolment("t")
	got, _ := c.Enroll(context.Background(), client.EnrollRequest{Token: "t", PublicKey: base64.StdEncoding.EncodeToString(identity.PublicKey(key))})
	s, _ := identity.NewSigner(got.AgentID, key)
	a, _ := s.TokenAssertion(c.Base)
	_, err := c.Token(context.Background(), a)
	if e := apiError(t, err); e.Status != http.StatusForbidden || e.State != "pending" {
		t.Errorf("token for a pending agent: %v", e)
	}
	svc.Revoke(got.AgentID)
	a, _ = s.TokenAssertion(c.Base)
	_, err = c.Token(context.Background(), a)
	if e := apiError(t, err); e.State != "revoked" {
		t.Errorf("token for a revoked agent: %v", e)
	}
}

func TestAConfirmedAgentTradesAnAssertionOnceForAnAccessToken(t *testing.T) {
	r := enrolled(t)
	a, _ := r.signer.TokenAssertion(r.c.Base)
	tok, err := r.c.Token(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Token, "acc_agt_") || time.Until(tok.ExpiresAt) < 50*time.Minute {
		t.Errorf("token = %+v", tok)
	}
	// An assertion is for one use.
	_, err = r.c.Token(context.Background(), a)
	if e := apiError(t, err); e.Status != http.StatusUnauthorized {
		t.Errorf("a replayed assertion: %v", e)
	}
}

func TestNoJobIsNilAndAJobCarriesWhatTheServiceSent(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	job, err := r.c.Jobs(context.Background(), tok)
	if err != nil || job != nil {
		t.Fatalf("with nothing queued: %v, %v", job, err)
	}
	run := r.svc.Queue(fakeservice.Job{Collector: "keycloak", Config: `{"url":"https://kc","client_secret":"env:KC"}`, Scopes: []string{"master"}})
	job, err = r.c.Jobs(context.Background(), tok)
	if err != nil || job == nil {
		t.Fatalf("with one queued: %v, %v", job, err)
	}
	if job.Stream != run.Stream() || job.Collector != "keycloak" || job.HeartbeatSeconds != 100 || job.LeaseSeconds != 300 ||
		job.ChunkBytes != 8<<20 || len(job.Scopes) != 1 || job.Attempt != 1 || job.Run == "" {
		t.Errorf("job = %+v", job)
	}
	if cur, err := job.Resume(); string(job.Config) != `{"url":"https://kc","client_secret":"env:KC"}` || !job.NoBudget() || cur != nil || err != nil {
		t.Errorf("config %s, budget %s, cursor %s", job.Config, job.Budget, job.ResumeCursor)
	}
}

func TestAResumeCursorIsDecodedFromItsBase64(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	r.svc.Queue(fakeservice.Job{Collector: "minimal", Config: `{}`, ResumeCursor: `{"token": "` + base64.StdEncoding.EncodeToString([]byte("page-7")) + `"}`})
	job, err := r.c.Jobs(context.Background(), tok)
	if err != nil || job == nil {
		t.Fatal(err)
	}
	if got, err := job.Resume(); err != nil || string(got) != "page-7" {
		t.Errorf("Resume = %q, %v", got, err)
	}
}

func TestACursorThatIsNotOneIsAnErrorAndNeverAFreshStart(t *testing.T) {
	for name, raw := range map[string]string{
		"a string":         `"MQ=="`,
		"no token":         `{}`,
		"other field":      `{"cursor": "MQ=="}`,
		"extra field":      `{"token": "MQ==", "at": 3}`,
		"not base64":       `{"token": "***"}`,
		"url alphabet":     `{"token": "_-8="}`,
		"empty token":      `{"token": ""}`,
		"a number":         `5`,
		"token not string": `{"token": 5}`,
	} {
		j := client.Job{ResumeCursor: json.RawMessage(raw)}
		if got, err := j.Resume(); err == nil {
			t.Errorf("%s: Resume = %q with no error: a bad cursor would start the job over and call it a resume", name, got)
		}
	}
	for _, none := range []string{"", "null", " null "} {
		j := client.Job{ResumeCursor: json.RawMessage(none)}
		if got, err := j.Resume(); got != nil || err != nil {
			t.Errorf("%q: Resume = %q, %v", none, got, err)
		}
	}
}

// The agent says which file it ran, on every chunk. The service has only its word for it.
func TestEveryChunkSaysWhichCollectorFileTheAgentRanAndWhatItCalledItself(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	run := r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	col := client.Collector{SHA256: strings.Repeat("ab", 32), Version: "0.2.0-rc.1+b5"}
	if _, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, chunkOf(t, diagnostic("a")), false, col); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.PutChunk(context.Background(), tok, job.Stream, 1, chunkOf(t, diagnostic("b"), completion()), true, col); err != nil {
		t.Fatal(err)
	}
	want := fakeservice.Report{SHA256: col.SHA256, Version: col.Version}
	if got := run.Reports(); len(got) != 2 || got[0] != want || got[1] != want {
		t.Errorf("the service was told %+v, want %+v twice", got, want)
	}
}

// A value that is not what it should be is left out, and the chunk still goes: the agent does not
// fail an upload over a label, and does not let a collector put a line of its own in a header.
func TestWhatTheAgentDoesNotKnowOfTheCollectorOrCannotSendIsLeftOutAndTheChunkStillGoes(t *testing.T) {
	good := strings.Repeat("0f", 32)
	for name, c := range map[string]struct {
		col  client.Collector
		want fakeservice.Report
	}{
		"nothing known":              {client.Collector{}, fakeservice.Report{}},
		"a digest and no version":    {client.Collector{SHA256: good}, fakeservice.Report{SHA256: good}},
		"a version and no digest":    {client.Collector{Version: "0.2.0"}, fakeservice.Report{Version: "0.2.0"}},
		"a line break in version":    {client.Collector{SHA256: good, Version: "0.2.0\r\nX-Acciew-Final: true"}, fakeservice.Report{SHA256: good}},
		"a space in version":         {client.Collector{SHA256: good, Version: "0.2.0 beta"}, fakeservice.Report{SHA256: good}},
		"a version past 64 bytes":    {client.Collector{SHA256: good, Version: strings.Repeat("1", 65)}, fakeservice.Report{SHA256: good}},
		"a version of 64 bytes":      {client.Collector{SHA256: good, Version: strings.Repeat("1", 64)}, fakeservice.Report{SHA256: good, Version: strings.Repeat("1", 64)}},
		"a non-ASCII version":        {client.Collector{SHA256: good, Version: "0.2.0\u00e9"}, fakeservice.Report{SHA256: good}},
		"a digest in capitals":       {client.Collector{SHA256: strings.ToUpper(good), Version: "0.2.0"}, fakeservice.Report{Version: "0.2.0"}},
		"a digest that is too short": {client.Collector{SHA256: good[:62], Version: "0.2.0"}, fakeservice.Report{Version: "0.2.0"}},
	} {
		t.Run(name, func(t *testing.T) {
			r := enrolled(t)
			tok := r.token(t)
			run := r.svc.Queue(fakeservice.Job{Collector: "minimal"})
			job, _ := r.c.Jobs(context.Background(), tok)
			if _, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, chunkOf(t, diagnostic("a")), false, c.col); err != nil {
				t.Fatalf("the chunk did not go: %v", err)
			}
			if got := run.Reports(); len(got) != 1 || got[0] != c.want {
				t.Errorf("the service was told %+v, want %+v", got, c.want)
			}
			if run.Final() {
				t.Error("a header the collector wrote ended the stream")
			}
		})
	}
}

func TestABudgetInAJobIsNoticed(t *testing.T) {
	j := client.Job{Budget: json.RawMessage(`{"max_records": 5}`)}
	if j.NoBudget() {
		t.Error("a budget went unnoticed")
	}
}

func TestChunksAreStoredOnceAndSentAgainAsDuplicates(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	body := chunkOf(t, diagnostic("one"))
	got, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, body, false, client.Collector{})
	if err != nil || got.Duplicate {
		t.Fatalf("first: %+v, err %v", got, err)
	}
	got, err = r.c.PutChunk(context.Background(), tok, job.Stream, 0, body, false, client.Collector{})
	if err != nil || !got.Duplicate {
		t.Fatalf("again: %+v, err %v", got, err)
	}
	_, err = r.c.PutChunk(context.Background(), tok, job.Stream, 2, body, false, client.Collector{})
	if e := apiError(t, err); e.Code != "out_of_order" || !e.HasNext || e.Next != 1 {
		t.Errorf("a gap: %+v", e)
	}
	_, err = r.c.PutChunk(context.Background(), tok, job.Stream, 0, chunkOf(t, diagnostic("other")), false, client.Collector{})
	if e := apiError(t, err); e.Code != "chunk_conflict" {
		t.Errorf("other bytes under an old number: %+v", e)
	}
	if _, err := r.c.PutChunk(context.Background(), tok, job.Stream, 1, body, true, client.Collector{}); err != nil {
		t.Fatal(err)
	}
	_, err = r.c.PutChunk(context.Background(), tok, job.Stream, 2, body, false, client.Collector{})
	if e := apiError(t, err); e.Code != "stream_closed" {
		t.Errorf("after the last: %+v", e)
	}
}

func TestAHeartbeatHoldsTheLeaseUntilItIsLost(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	run := r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	if err := r.c.Heartbeat(context.Background(), tok, job.Stream); err != nil {
		t.Fatal(err)
	}
	run.LoseLease()
	err := r.c.Heartbeat(context.Background(), tok, job.Stream)
	if e := apiError(t, err); e.Status != http.StatusConflict || e.Code != "lease_lost" {
		t.Errorf("after the lease moved: %+v", e)
	}
}

func TestAbortGivesTheReason(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	run := r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	if err := r.c.Abort(context.Background(), tok, job.Stream, "no collector called \"minimal\" is installed"); err != nil {
		t.Fatal(err)
	}
	if got := run.Aborted(); !strings.Contains(got, "no collector called") {
		t.Errorf("the service was told %q", got)
	}
	err := r.c.Abort(context.Background(), tok, job.Stream, "again")
	if e := apiError(t, err); e.Code != "stream_closed" {
		t.Errorf("a second abort: %+v", e)
	}
}

func TestAStreamOfAnotherAgentIsNotFound(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	err := r.c.Heartbeat(context.Background(), tok, "no-such-stream")
	if e := apiError(t, err); e.Status != http.StatusNotFound {
		t.Errorf("%+v", e)
	}
}

func TestAnExpiredTokenIsA401(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	r.svc.ForgetTokens()
	_, err := r.c.Jobs(context.Background(), tok)
	if e := apiError(t, err); e.Status != http.StatusUnauthorized {
		t.Errorf("%+v", e)
	}
}

func TestARetryAfterIsRead(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	r.svc.Fail(fakeservice.Path(http.MethodGet, "/agent/v1/jobs"), 1, http.StatusTooManyRequests, http.Header{"Retry-After": {"3600"}})
	_, err := r.c.Jobs(context.Background(), tok)
	e := apiError(t, err)
	if e.Status != http.StatusTooManyRequests || e.RetryAfter != time.Hour {
		t.Errorf("%+v", e)
	}
	if !client.Transient(err) {
		t.Error("a 429 is worth asking again after the wait")
	}
}

func TestWhatIsWorthRetryingAndWhatIsNot(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&client.APIError{Status: 500}, true},
		{&client.APIError{Status: 502}, true},
		{&client.APIError{Status: 503}, true},
		{&client.APIError{Status: 429}, true},
		{&client.APIError{Status: 408}, true},
		{&client.APIError{Status: 422}, true}, // damaged in transit: send again
		{&client.APIError{Status: 401}, false},
		{&client.APIError{Status: 403}, false},
		{&client.APIError{Status: 404}, false},
		{&client.APIError{Status: 409, Code: "lease_lost"}, false},
		{&client.APIError{Status: 413}, false},
		{errors.New("connection refused"), true},
		{context.Canceled, false},
	} {
		if got := client.Transient(c.err); got != c.want {
			t.Errorf("Transient(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestANetworkThatLosesTheAnswerIsNotAnAPIError(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	r.svc.DropAnswers(fakeservice.Chunk(0), 1)
	x := chunkOf(t, diagnostic("x"))
	_, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, x, false, client.Collector{})
	var e *client.APIError
	if err == nil || errors.As(err, &e) || !client.Transient(err) {
		t.Fatalf("err = %v", err)
	}
	got, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, x, false, client.Collector{})
	if err != nil || !got.Duplicate {
		t.Errorf("after the lost answer the same chunk should be a duplicate: %+v %v", got, err)
	}
}

func TestPlainHTTPIsRefusedExceptToTheMachineItself(t *testing.T) {
	for _, u := range []string{"http://acciew.example.test", "ftp://x", "acciew.example.test", "", "https://"} {
		if _, err := client.New(u, "t"); err == nil {
			t.Errorf("New(%q) succeeded", u)
		}
	}
	for _, u := range []string{"https://acciew.example.test", "https://acciew.example.test/", "http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		if _, err := client.New(u, "t"); err != nil {
			t.Errorf("New(%q): %v", u, err)
		}
	}
	c, _ := client.New("https://acciew.example.test///", "t")
	if c.Base != "https://acciew.example.test" {
		t.Errorf("Base = %q: the audience is compared exactly, so the trailing slashes go", c.Base)
	}
}

// A redirect would carry an assertion or a token to a host nobody configured.
func TestARedirectIsNotFollowed(t *testing.T) {
	r := enrolled(t)
	other := fakeservice.New(t)
	r.svc.Fail(fakeservice.Path(http.MethodGet, "/agent/v1/hello"), 1, http.StatusFound, http.Header{"Location": {other.URL() + "/agent/v1/hello"}})
	_, err := r.c.Hello(context.Background(), r.token(t))
	if err == nil {
		t.Fatal("a redirect was followed or ignored")
	}
	if n := other.Hits("GET /agent/v1/hello"); n != 0 {
		t.Errorf("the other host was asked %d times", n)
	}
}

func TestTheServersClockIsReadFromItsAnswers(t *testing.T) {
	r := enrolled(t)
	fresh, _ := client.New(r.svc.URL(), "test")
	if _, ok := fresh.ClockOffset(); ok {
		t.Error("an offset before any answer")
	}
	_, _ = fresh.Hello(context.Background(), "unknown")
	off, ok := fresh.ClockOffset()
	if !ok || off > 5*time.Second || off < -5*time.Second {
		t.Errorf("offset = %v, %v", off, ok)
	}
}

func diagnostic(msg string) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Diagnostic{Diagnostic: &collectorv1.Diagnostic{
		Severity: collectorv1.Severity_SEVERITY_INFO, Code: "test", Message: msg,
	}}}
}

func completion() *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Completion{Completion: &collectorv1.Completion{
		Verdict: collectorv1.Verdict_VERDICT_COMPLETE, Counts: &collectorv1.Counts{},
	}}}
}

func checkpoint(token string) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Checkpoint{Checkpoint: &collectorv1.Checkpoint{Cursor: &collectorv1.Cursor{Token: []byte(token)}}}}
}

// chunkOf is a well-formed chunk holding these events.
func chunkOf(t *testing.T, events ...*collectorv1.CollectResponse) []byte {
	t.Helper()
	var raw []byte
	for _, e := range events {
		msg, err := proto.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		f, err := chunk.Frame(msg)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, f...)
	}
	chunks, err := chunk.Seal(raw, chunk.MaxChunk)
	if err != nil {
		t.Fatal(err)
	}
	return chunks[0]
}

// The service reads each chunk as it arrives. One that is not well formed is refused and
// nothing of it is kept; a completion is the last event of the last chunk.
func TestAChunkThatIsNotWellFormedIsRefusedWithAReason(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	for name, c := range map[string]struct {
		body  []byte
		final bool
		want  string
	}{
		"not gzip":                      {[]byte("hello"), false, "not well formed"},
		"an event after the completion": {chunkOf(t, completion(), diagnostic("late")), true, "follows the completion"},
		"a completion that is not last": {chunkOf(t, completion()), false, "last chunk"},
	} {
		_, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, c.body, c.final, client.Collector{})
		e := apiError(t, err)
		if e.Status != http.StatusUnprocessableEntity || !strings.Contains(e.Detail, c.want) {
			t.Errorf("%s: %+v", name, e)
		}
	}
	if got := r.svc.Hits("PUT /agent/v1/streams/{stream}/chunks/{n}"); got != 3 {
		t.Fatalf("%d PUTs", got)
	}
	// Nothing was kept: chunk 0 is still wanted.
	if _, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, chunkOf(t, diagnostic("ok")), false, client.Collector{}); err != nil {
		t.Errorf("chunk 0 after the refusals: %v", err)
	}
}

func TestALastChunkWithNoCompletionEndsTheStreamEarlyAndOffersTheJobAgainResumed(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	run := r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	got, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, chunkOf(t, diagnostic("a"), checkpoint("3"), diagnostic("b")), true, client.Collector{})
	if err != nil || !got.EndedEarly || got.Duplicate {
		t.Fatalf("%+v %v", got, err)
	}
	var again *client.Job
	for range 100 {
		if again, err = r.c.Jobs(context.Background(), tok); again != nil || err != nil {
			break
		}
	}
	if err != nil || again == nil {
		t.Fatalf("the job was not offered again: %v", err)
	}
	cur, cerr := again.Resume()
	if again.Stream == job.Stream || again.Attempt != 2 || cerr != nil || string(cur) != "3" {
		t.Errorf("second offer: stream %q (was %q), attempt %d, cursor %q (%v)", again.Stream, job.Stream, again.Attempt, cur, cerr)
	}
	// The earlier stream's lease is gone; the answer to a chunk resent from it is still "duplicate".
	if _, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, chunkOf(t, diagnostic("a"), checkpoint("3"), diagnostic("b")), true, client.Collector{}); err != nil {
		t.Errorf("a lost answer from the first attempt: %v", err)
	}
	// A whole last chunk is not early.
	got, err = r.c.PutChunk(context.Background(), tok, again.Stream, 0, chunkOf(t, diagnostic("c"), completion()), true, client.Collector{})
	if err != nil || got.EndedEarly {
		t.Errorf("%+v %v", got, err)
	}
	select {
	case <-run.Done():
	default:
		t.Error("the run is not done")
	}
}

// The service refuses a chunk that cannot be taken before it reads the body. An 8 MiB upload
// that is answered early must come back as the answer, and not as a broken pipe that would be
// sent again to be refused again.
func TestAnEightMegabyteChunkRefusedBeforeItsBodyIsReadComesBackAsTheRefusal(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	run := r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	big := make([]byte, 8<<20)
	_, _ = rand.Read(big)

	_, err := r.c.PutChunk(context.Background(), tok, job.Stream, 3, big, false, client.Collector{})
	if e := apiError(t, err); e.Code != "out_of_order" || !e.HasNext || e.Next != 0 {
		t.Errorf("a number that is not the next: %v", err)
	}
	_, err = r.c.PutChunk(context.Background(), tok, "not-a-stream", 0, big, false, client.Collector{})
	if e := apiError(t, err); e.Status != http.StatusNotFound {
		t.Errorf("a stream that is not this agent's: %v", err)
	}
	run.LoseLease()
	_, err = r.c.PutChunk(context.Background(), tok, job.Stream, 0, big, false, client.Collector{})
	if e := apiError(t, err); e.Code != "lease_lost" {
		t.Errorf("a lease that was lost: %v", err)
	}
}

// A number that arrived before is answered from its digest alone, without reading the body again.
func TestAChunkNumberThatArrivedBeforeIsAnsweredFromItsDigest(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	first := chunkOf(t, diagnostic("first"))
	if _, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, first, false, client.Collector{}); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 8<<20)
	_, _ = rand.Read(big)
	_, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, big, false, client.Collector{})
	if e := apiError(t, err); e.Code != "chunk_conflict" {
		t.Errorf("other bytes under an old number: %v", err)
	}
	if got, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, first, false, client.Collector{}); err != nil || !got.Duplicate {
		t.Errorf("the same bytes again: %+v %v", got, err)
	}
}

// The answer to a request is read up to a megabyte and no further: a service, or something in
// front of it, that answers with more is not buffered whole.
func TestAnAnswerOverAMegabyteIsNotReadWhole(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	r.svc.Queue(fakeservice.Job{Collector: "minimal"})
	job, _ := r.c.Jobs(context.Background(), tok)
	pad := strings.Repeat("x", 3<<20)
	r.svc.Reply(fakeservice.Chunk(0), 1, http.StatusCreated, `{"status":"stored","final":false,"pad":"`+pad+`"}`)
	got, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, chunkOf(t, diagnostic("a")), false, client.Collector{})
	if err == nil {
		t.Fatalf("a 3 MiB answer was read to the end and believed: %+v", got)
	}
	// Under the limit the same answer is fine.
	r.svc.Reply(fakeservice.Chunk(1), 1, http.StatusCreated, `{"status":"stored","final":false,"pad":"`+strings.Repeat("x", 1000)+`"}`)
	if _, err := r.c.PutChunk(context.Background(), tok, job.Stream, 1, chunkOf(t, diagnostic("b")), false, client.Collector{}); err != nil {
		t.Errorf("an answer under the limit: %v", err)
	}
}

func TestTheEventsTheEarlierStreamsContributeAreReadFromTheJob(t *testing.T) {
	r := enrolled(t)
	tok := r.token(t)
	r.svc.Queue(fakeservice.Job{Collector: "minimal", ResumeEvents: 100})
	job, err := r.c.Jobs(context.Background(), tok)
	if err != nil || job == nil || job.ResumeEvents != 100 {
		t.Fatalf("%+v %v", job, err)
	}
	// The stream ends early with a checkpoint after its second event and a third that follows it: the
	// next offer says the earlier stream contributes the two.
	if _, err := r.c.PutChunk(context.Background(), tok, job.Stream, 0, chunkOf(t, diagnostic("a"), checkpoint("1"), diagnostic("b")), true, client.Collector{}); err != nil {
		t.Fatal(err)
	}
	var next *client.Job
	for range 100 {
		if next, err = r.c.Jobs(context.Background(), tok); next != nil || err != nil {
			break
		}
	}
	if err != nil || next == nil || next.ResumeEvents != 102 {
		t.Fatalf("%+v %v", next, err)
	}
}
