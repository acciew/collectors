package collect

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

// At the service's own numbers: records stop with the reserve intact, and an
// event that is not a record keeps room for the diagnostic that says why the
// stream stopped and for the completion. The completion is the 1,000,000th event
// at most, which the service accepts (it refuses more than).
func TestRoomAtTheServicesNumbers(t *testing.T) {
	defer LowerEventLimit(serviceEventLimit, eventReserve)()
	l := &limited{}
	for _, c := range []struct {
		n    int
		kind eventKind
		want bool
	}{
		{989_997, recordEvent, true},
		{989_998, recordEvent, false},
		{999_997, ordinaryEvent, true},
		{999_998, ordinaryEvent, false},
	} {
		l.n = c.n
		if got := l.room(c.kind, 0); got != c.want {
			t.Errorf("n=%d kind=%d: room=%v, want %v", c.n, c.kind, got, c.want)
		}
	}
}

// The bytes bound sits beside the events bound: a record fits only if both do.
func TestRoomInBytes(t *testing.T) {
	defer LowerEventLimit(1000, 0)()
	defer LowerByteLimit(1000, 100)()
	l := &limited{}
	if !l.room(recordEvent, 800) || l.room(recordEvent, 900) {
		t.Error("a record fits in bytes only while the reserve is intact")
	}
	if l.room(recordEvent, 890) {
		t.Error("a record fit that leaves the reserve intact only if its framing is not counted")
	}
	l.bytes = 850
	if l.room(recordEvent, 100) {
		t.Error("a record fit past the bytes already sent")
	}
	if !l.room(ordinaryEvent, 100) {
		t.Error("an event that is not a record was held to the bytes reserve")
	}
}

// stub is a stream that takes everything and says nothing.
type stub struct{ collector.Stream }

func (stub) Checkpoint([]byte) error                               { return nil }
func (stub) Progress(string, *collector.RateLimit) error           { return nil }
func (stub) Diagnostic(collectorv1.Severity, string, string) error { return nil }

// What is not a record is costed as it is marshalled, as a record is, and not by
// the length of its strings: a diagnostic carries a severity, a progress carries
// its counts, and a checkpoint a cursor in a message of its own.
func TestEventsThatAreNotRecordsAreCostedAsMarshalled(t *testing.T) {
	l := &limited{Stream: stub{}}

	cp := []byte(`{"v":1}`)
	_ = l.Checkpoint(cp)
	want := proto.Size(&collectorv1.Checkpoint{Cursor: &collectorv1.Cursor{Token: cp}}) + eventOverhead
	if l.bytes != want {
		t.Errorf("a checkpoint cost %d, want %d", l.bytes, want)
	}

	l.bytes = 0
	_ = l.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.x", "a message")
	want = proto.Size(&collectorv1.Diagnostic{Severity: collectorv1.Severity_SEVERITY_WARNING, Code: "entra.x", Message: "a message"}) + eventOverhead
	if l.bytes != want {
		t.Errorf("a diagnostic cost %d, want %d", l.bytes, want)
	}

	l.bytes = 0
	_ = l.say(collectorv1.Severity_SEVERITY_ERROR, "entra.limit.events", "stopped")
	want = proto.Size(&collectorv1.Diagnostic{Severity: collectorv1.Severity_SEVERITY_ERROR, Code: "entra.limit.events", Message: "stopped"}) + eventOverhead
	if l.bytes != want {
		t.Errorf("the limit's diagnostic cost %d, want %d", l.bytes, want)
	}

	// A progress event is sent with the counts of what has been sent, which the
	// stream here does not know, so it is costed with the most they can come to.
	l.bytes = 0
	_ = l.Progress("users", &collector.RateLimit{RetryAfter: 3 * time.Second})
	least := proto.Size(&collectorv1.Progress{Phase: "users", RateLimit: &collectorv1.RateLimit{RetryAfter: durationpb.New(3 * time.Second)}}) + eventOverhead
	if l.bytes < least+maxCountsBytes {
		t.Errorf("a progress event cost %d, want at least %d: its phase, its rate limit and the most its counts take", l.bytes, least+maxCountsBytes)
	}
}
