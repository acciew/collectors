// Package host starts a collector as a child process and talks to it over the local
// connection the SDK serves (ADR-0002). It is the agent's side of what core's
// internal/pluginhost is for a collector that runs beside the service.
package host

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	pluginv1 "go.acciew.io/collector/api/plugin/v1"
)

var handshake = goplugin.HandshakeConfig{
	ProtocolVersion:  pluginv1.MechanismVersion,
	MagicCookieKey:   pluginv1.MagicCookieKey,
	MagicCookieValue: pluginv1.MagicCookieValue,
}

var collectorEntry = pluginv1.Entry(collectorv1.Kind, collectorv1.ProtocolVersion)

// Options says how a collector is started.
type Options struct {
	// Env is the whole of the collector's environment. Nothing of the agent's is added.
	Env []string
	// Dir is where it starts.
	Dir string
	// Log receives the collector's own log lines, through Scrub.
	Log   *slog.Logger
	Scrub func(string) string
	// StartTimeout bounds the wait for the collector to say it is ready; zero is a minute.
	StartTimeout time.Duration
}

// ChildEnv is all a collector is given: a PATH, and the named variables of the agent's that
// are set (proxy and certificate settings, usually). lookup nil is os.LookupEnv.
func ChildEnv(pass []string, lookup func(string) (string, bool)) []string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	for _, name := range pass {
		if v, ok := lookup(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// Plugin is a running collector.
type Plugin struct {
	// Name and Version are what the collector says it is.
	Name, Version string

	client *goplugin.Client
	rpc    collectorv1.CollectorServiceClient
}

// Launch starts the binary and agrees a contract with it. The process is killed when ctx ends.
func Launch(ctx context.Context, path string, o Options) (*Plugin, error) {
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = append([]string{}, o.Env...)
	cmd.Dir = o.Dir
	client := goplugin.NewClient(&goplugin.ClientConfig{
		// With an environment given, the collector gets that and nothing of its parent's.
		SkipHostEnv:     true,
		HandshakeConfig: handshake,
		Plugins: map[string]goplugin.Plugin{
			pluginv1.HandshakeEntry: &handshakeClient{},
			collectorEntry:          &collectorClient{},
		},
		Cmd:              cmd,
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		StartTimeout:     o.StartTimeout,
		Logger: hclog.New(&hclog.LoggerOptions{
			Name: "collector", Level: hclog.Info, Output: logWriter{log: log, scrub: o.Scrub},
		}),
	})
	rpc, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("starting the collector: %w", err)
	}
	raw, err := rpc.Dispense(pluginv1.HandshakeEntry)
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("the collector does not speak the Acciew handshake: %w", err)
	}
	hs, ok := raw.(pluginv1.HandshakeServiceClient)
	if !ok {
		client.Kill()
		return nil, errors.New("the collector's handshake entry is not a handshake service")
	}
	hello, err := hs.Hello(ctx, &pluginv1.HelloRequest{HostSupports: []*pluginv1.Offering{{Kind: collectorv1.Kind, ProtocolVersion: collectorv1.ProtocolVersion}}})
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("handshake with the collector: %w", plain(err))
	}
	if err := CheckOffering(hello); err != nil {
		client.Kill()
		return nil, err
	}
	raw, err = rpc.Dispense(collectorEntry)
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("the collector does not serve %s: %w", collectorEntry, err)
	}
	svc, ok := raw.(collectorv1.CollectorServiceClient)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("the collector's %s entry is not a collector", collectorEntry)
	}
	return &Plugin{Name: hello.GetPluginName(), Version: hello.GetPluginVersion(), client: client, rpc: svc}, nil
}

// CheckOffering says whether a binary speaks the one contract this agent does, and if not,
// names both sides' contracts: "handshake failed" sends an operator nowhere.
func CheckOffering(hello *pluginv1.HelloResponse) error {
	for _, o := range hello.GetOfferings() {
		if o.GetKind() == collectorv1.Kind && o.GetProtocolVersion() == collectorv1.ProtocolVersion {
			return nil
		}
	}
	var offered []string
	for _, o := range hello.GetOfferings() {
		offered = append(offered, fmt.Sprintf("%s/%d", o.GetKind(), o.GetProtocolVersion()))
	}
	if len(offered) == 0 {
		offered = []string{"nothing"}
	}
	return fmt.Errorf("the collector %q offers %s but this agent speaks %s", hello.GetPluginName(), strings.Join(offered, ", "), collectorEntry)
}

// ValidateConfig asks the collector to check a configuration. It never contacts the source.
func (p *Plugin) ValidateConfig(ctx context.Context, config []byte) ([]*collectorv1.ConfigIssue, error) {
	resp, err := p.rpc.ValidateConfig(ctx, &collectorv1.ValidateConfigRequest{Config: config})
	if err != nil {
		return nil, fmt.Errorf("asking the collector to validate its configuration: %w", plain(err))
	}
	if vs := ConfigIssueViolations(resp.GetIssues()); len(vs) > 0 {
		return nil, fmt.Errorf("the collector broke the contract answering ValidateConfig: %s", vs[0])
	}
	return resp.GetIssues(), nil
}

// ConfigIssueViolations is the contract's check of an answer to ValidateConfig.
func ConfigIssueViolations(issues []*collectorv1.ConfigIssue) []collectorv1.Violation {
	return collectorv1.ValidateConfigIssues(issues)
}

// Collect starts a collection and returns its stream of events.
func (p *Plugin) Collect(ctx context.Context, req *collectorv1.CollectRequest) (collectorv1.CollectorService_CollectClient, error) {
	s, err := p.rpc.Collect(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("starting the collection: %w", plain(err))
	}
	return s, nil
}

// Close stops the collector process.
func (p *Plugin) Close() { p.client.Kill() }

// Code is the transport's status code of an error a collector returned, as a word ("Unknown",
// "Unavailable"): what can be said of a failure without repeating what the collector wrote.
func Code(err error) string {
	if st, ok := status.FromError(err); ok {
		return st.Code().String()
	}
	return "Unknown"
}

// Plain strips the transport's envelope from an error a collector returned, leaving the
// sentence the collector wrote for an operator.
func Plain(err error) error { return plain(err) }

func plain(err error) error {
	if st, ok := status.FromError(err); ok && st.Code() != codes.OK {
		return errors.New(st.Message())
	}
	return err
}

type logWriter struct {
	log   *slog.Logger
	scrub func(string) string
}

func (w logWriter) Write(b []byte) (int, error) {
	line := strings.TrimRight(string(b), "\n")
	if w.scrub != nil {
		line = w.scrub(line)
	}
	if line != "" {
		w.log.Info("collector", slog.String("line", line))
	}
	return len(b), nil
}

type collectorClient struct {
	goplugin.NetRPCUnsupportedPlugin
}

func (collectorClient) GRPCServer(*goplugin.GRPCBroker, *grpc.Server) error { return nil }
func (collectorClient) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return collectorv1.NewCollectorServiceClient(c), nil
}

type handshakeClient struct {
	goplugin.NetRPCUnsupportedPlugin
}

func (handshakeClient) GRPCServer(*goplugin.GRPCBroker, *grpc.Server) error { return nil }
func (handshakeClient) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return pluginv1.NewHandshakeServiceClient(c), nil
}
