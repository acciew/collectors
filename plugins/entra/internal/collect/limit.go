package collect

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

// The service refuses a collection of more than a million events, or of more than
// two gibibytes, as not well formed, and since a collection starts again from the
// beginning, every retry would read the whole tenant to meet the same wall. So the
// stream counts what it sends, stops reading at its allowance, and ends not
// complete, saying why. No event goes past the limit.
//
// Records and the events that are not records are held to different allowances,
// so that what ends a stream always fits:
//
//   - a record (a node, an edge, an activity) stops at the limit less a reserve and
//     less two more events;
//   - any other event (progress, a diagnostic) stops two before the limit;
//   - the diagnostic that says why the stream stopped is not held to either: after
//     either of them at most the limit less two events have been sent, so it fits,
//     and the completion after it is the limit's last.
//
// The scope node and the first checkpoint are not held to any of it: the outcome
// that ends the stream names the scope.
const (
	// serviceEventLimit is the most events the service accepts in one collection.
	serviceEventLimit = 1_000_000
	// eventReserve is held back from records for the events that end a stream.
	eventReserve = 10_000
	// serviceByteLimit is the most bytes, inflated, the service accepts in one
	// collection, and byteReserve is held back from records for the events that
	// end a stream.
	serviceByteLimit = 2 << 30
	byteReserve      = 100 << 20
	// eventOverhead is what the framing of an event costs beyond its message.
	eventOverhead = 16
)

// The limits are variables so that a test can lower them.
var (
	eventLimit = serviceEventLimit
	eventHeld  = eventReserve
	byteLimit  = serviceByteLimit
	byteHeld   = byteReserve
)

// errEventLimit and errByteLimit are what an emitter is told when the stream has
// no room for another record. They unwind the part that was reading, like any
// other error.
var (
	errEventLimit = errors.New("the stream has reached the number of events a collection may send")
	errByteLimit  = errors.New("the stream has reached the number of bytes a collection may send")
)

type eventKind int

const (
	recordEvent eventKind = iota
	ordinaryEvent
)

// limited counts the events and bytes that go past and refuses the ones that
// would go over.
type limited struct {
	collector.Stream
	n     int
	bytes int
}

// room says whether another event of a kind, of this many bytes, fits.
func (l *limited) room(kind eventKind, size int) bool {
	if kind == recordEvent {
		return l.n+eventHeld+2 < eventLimit && l.bytes+size+eventOverhead+byteHeld < byteLimit
	}
	return l.n+2 < eventLimit
}

// refusal is why a record does not fit, as the error to unwind with.
func (l *limited) refusal(size int) error {
	if l.n+eventHeld+2 >= eventLimit {
		return errEventLimit
	}
	return errByteLimit
}

func (l *limited) count(m proto.Message) {
	l.n++
	l.bytes += proto.Size(m) + eventOverhead
}

func (l *limited) Node(n *collectorv1.Node) error {
	if size := proto.Size(n); !l.room(recordEvent, size) {
		return l.refusal(size)
	}
	l.count(n)
	return l.Stream.Node(n)
}

func (l *limited) Edge(e *collectorv1.Edge) error {
	if size := proto.Size(e); !l.room(recordEvent, size) {
		return l.refusal(size)
	}
	l.count(e)
	return l.Stream.Edge(e)
}

func (l *limited) Activity(a *collectorv1.Activity) error {
	if size := proto.Size(a); !l.room(recordEvent, size) {
		return l.refusal(size)
	}
	l.count(a)
	return l.Stream.Activity(a)
}

// writeScope sends the tenant's scope node whatever the limits: the outcome that
// ends the stream names it.
func (l *limited) writeScope(n *collectorv1.Node) error {
	l.count(n)
	return l.Stream.Node(n)
}

func (l *limited) Checkpoint(cursor []byte) error {
	l.count(&collectorv1.Checkpoint{Cursor: &collectorv1.Cursor{Token: cursor}})
	return l.Stream.Checkpoint(cursor)
}

// maxCountsBytes is the most the counts that go with a progress event can take:
// seven numbers, each a tag and a varint of ten bytes. The stream adds them when
// it sends the event, and this one does not know them.
const maxCountsBytes = 7 * (1 + 10)

func (l *limited) Progress(phase string, rl *collector.RateLimit) error {
	if !l.room(ordinaryEvent, 0) {
		return nil
	}
	p := &collectorv1.Progress{Phase: phase}
	if rl != nil {
		p.RateLimit = &collectorv1.RateLimit{
			Remaining: rl.Remaining, Limit: rl.Limit, RetryAfter: durationpb.New(rl.RetryAfter),
		}
		if !rl.ResetsAt.IsZero() {
			p.RateLimit.ResetsAt = timestamppb.New(rl.ResetsAt)
		}
	}
	l.count(p)
	l.bytes += maxCountsBytes
	return l.Stream.Progress(phase, rl)
}

func (l *limited) Diagnostic(sev collectorv1.Severity, code, message string) error {
	if !l.room(ordinaryEvent, 0) {
		return nil
	}
	l.count(&collectorv1.Diagnostic{Severity: sev, Code: code, Message: message})
	return l.Stream.Diagnostic(sev, code, message)
}

// say sends the diagnostic that says why the stream stopped. It is not checked
// for room, because there is room by construction: a record leaves two events,
// and an ordinary one leaves two, so n is at most the limit less two when a stream
// stops for the limit.
func (l *limited) say(sev collectorv1.Severity, code, message string) error {
	l.count(&collectorv1.Diagnostic{Severity: sev, Code: code, Message: message})
	return l.Stream.Diagnostic(sev, code, message)
}

// limitReached ends the collection at a limit: the part that was being read
// failed for want of room, and the rest of the tenant was not read. It is a
// configuration to lower, so it says what to turn off.
func (st *state) limitReached(part string, cause error) error {
	var code, what string
	if errors.Is(cause, errByteLimit) {
		code, what = "entra.limit.bytes", fmt.Sprintf("%d bytes", byteLimit)
	} else {
		code, what = "entra.limit.events", fmt.Sprintf("%d events", eventLimit)
	}
	text := fmt.Sprintf("the collection reached the %s a collection may send while reading the %s part, "+
		"so the rest of the tenant was not collected. Turn off what is not needed under \"collect\" "+
		"(service_principals, app_roles, pim, administrative_units, oauth2_grants), or withhold AuditLog.Read.All "+
		"so that users are read without their sign-in activity, which costs about four events a user",
		what, part)
	if err := st.lim.say(collectorv1.Severity_SEVERITY_ERROR, code, text); err != nil {
		return err
	}
	st.problem("limit", &faulted{text: text, fault: collector.FaultConfig})
	return st.stop(collector.ScopeUnreachable)
}
