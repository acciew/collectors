// Command testcollector is a collector for testing the agent. It is written against the
// contract directly, not the SDK, because the SDK refuses to send what the contract forbids
// and some tests need a collector that does.
//
// What it does is chosen by its configuration: {"mode": "ok"|"slow"|"violate"|"crash"|
// "no_completion"|"big"|"incomplete", "records": N, "delay_ms": N, "payload": N, "pid_file": path,
// "secret_file": path, "env_probe": [names], "issue": "message"}.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	pluginv1 "go.acciew.io/collector/api/plugin/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

type config struct {
	Mode       string   `json:"mode"`
	Records    int      `json:"records"`
	DelayMS    int      `json:"delay_ms"`
	Payload    int      `json:"payload"`
	PIDFile    string   `json:"pid_file"`
	SecretFile string   `json:"secret_file"`
	EnvProbe   []string `json:"env_probe"`
	Issue      string   `json:"issue"`
	Token      string   `json:"token"`
	// Leak makes the collector put the secret it read into an event, as a careless collector
	// would: the agent cannot stop that, and a test uses it to show a search for it works.
	Leak bool `json:"leak"`
	// LeakAs puts the secret into an event in one of these forms: raw, json, quoted, b64std, b64url,
	// b64rawstd, b64rawurl, hex, query, b64embedded.
	LeakAs string `json:"leak_as"`
	// LeakFileOfEnv names a variable that holds the path of a file whose text the collector says.
	LeakFileOfEnv string `json:"leak_file_of_env"`
	// CheckpointEvery offers a checkpoint after every N items and not after each (the default),
	// so that a stream cut short has events after its last one.
	CheckpointEvery int `json:"checkpoint_every"`
	// CrashAfter is the item the "crash" mode dies after (default 2), on a first start only: a
	// resumed one gets past it.
	CrashAfter int `json:"crash_after"`
	// CrashOnResume makes the "crash" mode die on a resumed start too.
	CrashOnResume bool `json:"crash_on_resume"`
	// CompletionPad makes an incomplete completion's message this long.
	CompletionPad int `json:"completion_pad"`
	// IssueFieldFromSecret makes the configuration issue's field a long path that ends in the secret.
	IssueFieldFromSecret bool `json:"issue_field_from_secret"`
	// IssueCodeFromSecret does the same for the issue's code. IssueSep is what joins the secret's words
	// (default a space) and IssuePad how many letters come before it.
	IssueCodeFromSecret bool   `json:"issue_code_from_secret"`
	IssueSep            string `json:"issue_sep"`
	IssuePad            int    `json:"issue_pad"`
	// RejectCursor makes the collector say it cannot use the cursor it is given and start over.
	RejectCursor bool `json:"reject_cursor"`
	// LeakEnv puts the value of this environment variable of the collector's own into an event.
	LeakEnv string `json:"leak_env"`
	// FailValidate makes ValidateConfig an error and BadIssue makes it answer with an issue the contract forbids.
	FailValidate bool `json:"fail_validate"`
	BadIssue     bool `json:"bad_issue"`
}

const scope = "test"

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			ProtocolVersion: pluginv1.MechanismVersion, MagicCookieKey: pluginv1.MagicCookieKey, MagicCookieValue: pluginv1.MagicCookieValue,
		},
		Plugins: map[string]plugin.Plugin{
			pluginv1.HandshakeEntry: &serving{register: func(s *grpc.Server) { pluginv1.RegisterHandshakeServiceServer(s, hello{}) }},
			pluginv1.Entry(collectorv1.Kind, collectorv1.ProtocolVersion): &serving{register: func(s *grpc.Server) {
				collectorv1.RegisterCollectorServiceServer(s, &service{})
			}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

type serving struct {
	plugin.NetRPCUnsupportedPlugin
	register func(*grpc.Server)
}

func (p *serving) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error { p.register(s); return nil }
func (p *serving) GRPCClient(context.Context, *plugin.GRPCBroker, *grpc.ClientConn) (any, error) {
	return nil, fmt.Errorf("server only")
}

type hello struct {
	pluginv1.UnimplementedHandshakeServiceServer
}

func (hello) Hello(context.Context, *pluginv1.HelloRequest) (*pluginv1.HelloResponse, error) {
	if os.Getenv("TESTCOLLECTOR_OFFER") == "error" {
		return nil, fmt.Errorf("the handshake is broken")
	}
	offer := []*pluginv1.Offering{{Kind: collectorv1.Kind, ProtocolVersion: collectorv1.ProtocolVersion}}
	switch os.Getenv("TESTCOLLECTOR_OFFER") {
	case "exporter":
		offer = []*pluginv1.Offering{{Kind: "exporter", ProtocolVersion: 1}}
	case "nothing":
		offer = nil
	}
	return &pluginv1.HelloResponse{PluginName: "testcollector", PluginVersion: "0.0.1", Offerings: offer}, nil
}

type service struct {
	collectorv1.UnimplementedCollectorServiceServer
}

func (*service) ValidateConfig(_ context.Context, req *collectorv1.ValidateConfigRequest) (*collectorv1.ValidateConfigResponse, error) {
	var c config
	if err := json.Unmarshal(req.GetConfig(), &c); err != nil {
		return &collectorv1.ValidateConfigResponse{Issues: []*collectorv1.ConfigIssue{{
			Severity: collectorv1.Severity_SEVERITY_ERROR, Code: "test.malformed", Message: "not JSON: " + err.Error(),
		}}}, nil
	}
	if c.FailValidate {
		return nil, fmt.Errorf("the validator is broken")
	}
	if c.BadIssue {
		return &collectorv1.ValidateConfigResponse{Issues: []*collectorv1.ConfigIssue{{Severity: collectorv1.Severity_SEVERITY_ERROR}}}, nil
	}
	if c.Issue != "" {
		msg := c.Issue
		if c.SecretFile != "" && c.Issue == "echo" {
			// A collector that puts what it was handed in its complaint.
			b, _ := os.ReadFile(strings.TrimPrefix(c.SecretFile, "file:"))
			msg = "the credential " + string(b) + " is not accepted (" + c.SecretFile + ")"
		}
		field, code := "/token", "test.issue"
		fromSecret := func() string {
			b, _ := os.ReadFile(strings.TrimPrefix(c.SecretFile, "file:"))
			sep := c.IssueSep
			if sep == "" {
				sep = " "
			}
			return strings.Repeat("a", c.IssuePad) + strings.Join(strings.Fields(string(b)), sep)
		}
		if c.IssueFieldFromSecret {
			field = "/" + fromSecret()
		}
		if c.IssueCodeFromSecret {
			code = fromSecret()
		}
		return &collectorv1.ValidateConfigResponse{Issues: []*collectorv1.ConfigIssue{{
			Field: field, Severity: collectorv1.Severity_SEVERITY_ERROR, Code: code, Message: msg,
		}}}, nil
	}
	return &collectorv1.ValidateConfigResponse{}, nil
}

// form writes a value the way a careless collector or a library under it might.
func form(how, v string) string {
	switch how {
	case "json":
		out, _ := json.Marshal(v)
		return strings.Trim(string(out), `"`)
	case "quoted":
		return strings.Trim(strconv.Quote(v), `"`)
	case "b64std":
		return base64.StdEncoding.EncodeToString([]byte(v))
	case "b64url":
		return base64.URLEncoding.EncodeToString([]byte(v))
	case "b64rawstd":
		return base64.RawStdEncoding.EncodeToString([]byte(v))
	case "b64rawurl":
		return base64.RawURLEncoding.EncodeToString([]byte(v))
	case "b64embedded":
		return base64.StdEncoding.EncodeToString([]byte("user:" + v + ":x"))
	case "hex":
		return hex.EncodeToString([]byte(v))
	case "query":
		return url.QueryEscape(v)
	}
	return v
}

func wrap(e *collectorv1.CollectResponse) *collectorv1.CollectResponse { return e }

func diag(code, msg string) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Diagnostic{Diagnostic: &collectorv1.Diagnostic{
		Severity: collectorv1.Severity_SEVERITY_INFO, Code: code, Message: msg,
	}}}
}

func (*service) Collect(req *collectorv1.CollectRequest, srv collectorv1.CollectorService_CollectServer) error {
	var c config
	if err := json.Unmarshal(req.GetConfig(), &c); err != nil {
		return err
	}
	if c.PIDFile != "" {
		_ = os.WriteFile(c.PIDFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
	}
	var counts collectorv1.Counters
	send := func(e *collectorv1.CollectResponse) error {
		switch ev := e.GetEvent().(type) {
		case *collectorv1.CollectResponse_Node:
			counts.CountNode(ev.Node)
		case *collectorv1.CollectResponse_Edge:
			counts.Edges++
		}
		return srv.Send(e)
	}
	node := func(n *collectorv1.Node) error {
		return send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Node{Node: n}})
	}
	checkpoint := func(i int) error {
		return send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Checkpoint{
			Checkpoint: &collectorv1.Checkpoint{Cursor: &collectorv1.Cursor{Token: []byte(strconv.Itoa(i))}},
		}})
	}

	if c.SecretFile != "" {
		b, err := os.ReadFile(strings.TrimPrefix(c.SecretFile, "file:"))
		if err != nil {
			return err
		}
		if err := send(diag("test.secret_read", fmt.Sprintf("read %d bytes from the secret file", len(b)))); err != nil {
			return err
		}
		if c.Leak {
			if err := send(diag("test.leak", string(b))); err != nil {
				return err
			}
		}
		if c.LeakAs != "" {
			text := strings.TrimRight(string(b), "\r\n")
			if err := send(diag("test.leak", "see: "+form(c.LeakAs, text)+" (end)")); err != nil {
				return err
			}
		}
	}
	if c.LeakFileOfEnv != "" {
		b, err := os.ReadFile(os.Getenv(c.LeakFileOfEnv)) //nolint:gosec // a test collector reading the file a test names
		if err != nil {
			return err
		}
		if err := send(diag("test.leak_file", "file says: "+strings.TrimSpace(string(b)))); err != nil {
			return err
		}
	}
	if c.LeakEnv != "" {
		if err := send(diag("test.leak_env", "using "+os.Getenv(c.LeakEnv))); err != nil {
			return err
		}
	}
	for _, name := range c.EnvProbe {
		state := "absent"
		if _, ok := os.LookupEnv(name); ok {
			state = "present"
		}
		if err := send(diag("test.env", name+"="+state)); err != nil {
			return err
		}
	}

	realm := collector.Scope(scope, scope)
	// The inventory as a list, so that a cursor is an index into it, as the reference collector's is.
	total := 1 + c.Records
	item := func(i int) error {
		if i == 0 {
			return node(collector.ScopeNode(realm, "the test scope", "test_scope"))
		}
		u := i - 1
		name := "user-" + strconv.Itoa(u)
		if c.Payload > 0 {
			junk := make([]byte, c.Payload/2)
			_, _ = rand.Read(junk)
			name += "-" + hex.EncodeToString(junk)
		}
		return node(collector.Identity(collector.IdentityKey(scope, "u"+strconv.Itoa(u)), name, "user", collector.Human, collector.Active))
	}

	from := 0
	firstStart := len(req.GetResumeFrom().GetToken()) == 0
	if token := req.GetResumeFrom().GetToken(); len(token) > 0 && c.RejectCursor {
		if err := send(diag("cursor.rejected", "the cursor could not be read, so the collection started from the beginning")); err != nil {
			return err
		}
	} else if len(token) > 0 {
		n, err := strconv.Atoi(string(token))
		if err != nil || n < 1 || n > total {
			if err := send(diag("cursor.rejected", "the cursor could not be read, so the collection started from the beginning")); err != nil {
				return err
			}
		} else {
			from = n
			if err := send(diag("test.resumed", "resumed after item "+strconv.Itoa(n))); err != nil {
				return err
			}
		}
	}
	for i := from; i < total; i++ {
		if err := item(i); err != nil {
			return err
		}
		if c.CheckpointEvery <= 1 || (i+1)%c.CheckpointEvery == 0 {
			if err := checkpoint(i + 1); err != nil {
				return err
			}
		}
		if c.DelayMS > 0 {
			select {
			case <-time.After(time.Duration(c.DelayMS) * time.Millisecond):
			case <-srv.Context().Done():
				return srv.Context().Err()
			}
		}
		switch {
		case c.Mode == "violate" && i == 2:
			// A node without a key: the contract forbids it, and the SDK would not send it.
			return send(wrap(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Node{Node: &collectorv1.Node{Name: "no key"}}}))
		case c.Mode == "crash" && (firstStart || c.CrashOnResume) && i == max(c.CrashAfter, 2):
			time.Sleep(200 * time.Millisecond) // what was sent is on its way before the process goes
			os.Exit(3)
		case c.Mode == "bare_checkpoint" && i == 2:
			return send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Checkpoint{Checkpoint: &collectorv1.Checkpoint{}}})
		case c.Mode == "huge_checkpoint" && i == 2:
			return send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Checkpoint{
				Checkpoint: &collectorv1.Checkpoint{Cursor: &collectorv1.Cursor{Token: make([]byte, 64<<10+1)}},
			}})
		}
	}
	if from > 0 && c.Mode != "resume_complete" {
		// A stream that resumed carries the rest and not the whole: it says so, and the agent does not change it.
		return send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Completion{Completion: &collectorv1.Completion{
			Verdict: collectorv1.Verdict_VERDICT_INCOMPLETE, Cause: collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM,
			Counts: counts.Proto(),
			Scopes: []*collectorv1.ScopeOutcome{{Scope: realm, Status: collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL, Error: &collectorv1.Error{
				Code: collectorv1.ErrorCode_ERROR_CODE_SOURCE_ERROR, Message: "this stream resumed and carries the rest"}}},
			Error: &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_SOURCE_ERROR, Message: "resumed after item " + strconv.Itoa(from)},
		}}})
	}
	switch c.Mode {
	case "no_completion":
		return nil
	case "incomplete":
		return send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Completion{Completion: &collectorv1.Completion{
			Verdict: collectorv1.Verdict_VERDICT_INCOMPLETE, Cause: collectorv1.IncompleteCause_INCOMPLETE_CAUSE_RATE_LIMITED,
			Counts: counts.Proto(),
			Scopes: []*collectorv1.ScopeOutcome{{Scope: realm, Status: collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL, Error: &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_RATE_LIMITED, Message: "rate limited"}}},
			Error:  &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_RATE_LIMITED, Message: "rate limited" + strings.Repeat(".", c.CompletionPad)},
		}}})
	case "miscount":
		counts.Identities += 7
	}
	return send(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Completion{Completion: &collectorv1.Completion{
		Verdict: collectorv1.Verdict_VERDICT_COMPLETE, Counts: counts.Proto(),
		Scopes: []*collectorv1.ScopeOutcome{{Scope: realm, Status: collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED}},
	}}})
}
