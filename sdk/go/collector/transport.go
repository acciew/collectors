package collector

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	pluginv1 "go.acciew.io/collector/api/plugin/v1"
)

// Everything in this file exists so that nothing in the rest of the SDK, and
// nothing at all in a plugin, has to know what the transport is. If a plugin
// author ever has to read this file, the abstraction has failed.
//
// See docs/adr/0002-plugin-transport.md: gRPC over a Unix socket is today's
// answer, chosen for lifecycle and typing, and it is isolated precisely
// because HTTP may turn out to be the better answer for who can write a
// plugin.

// handshake is built from the constants in the contract module, which is
// where both sides read them from. The transport library's config type stays
// on this side of the boundary so the contract keeps no transport dependency.
var handshake = plugin.HandshakeConfig{
	ProtocolVersion:  pluginv1.MechanismVersion,
	MagicCookieKey:   pluginv1.MagicCookieKey,
	MagicCookieValue: pluginv1.MagicCookieValue,
}

// collectorEntry is where this kind's contract is served.
var collectorEntry = pluginv1.Entry(collectorv1.Kind, collectorv1.ProtocolVersion)

// Serve runs a collector until the host shuts it down. It does not return,
// except to answer --version, which needs no host.
//
// This is the whole of a plugin's main:
//
//	func main() { collector.Serve(&myCollector{}) }
func Serve(c Collector) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		if err := printVersion(os.Stdout, c); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			pluginv1.HandshakeEntry: &handshakePlugin{impl: c},
			collectorEntry:          &collectorPlugin{impl: c},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// collectorPlugin registers the collector contract on the plugin's gRPC
// server.
type collectorPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	impl Collector
}

func (p *collectorPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	collectorv1.RegisterCollectorServiceServer(s, &service{impl: p.impl})
	return nil
}

func (p *collectorPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return collectorv1.NewCollectorServiceClient(c), nil
}

// handshakePlugin registers the kind-agnostic handshake. Every plugin binary
// serves it, whatever else it does, so the host can ask what a binary is
// before it knows how to talk to it.
type handshakePlugin struct {
	plugin.NetRPCUnsupportedPlugin
	impl Collector
}

func (p *handshakePlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterHandshakeServiceServer(s, &handshakeService{impl: p.impl})
	return nil
}

func (p *handshakePlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return pluginv1.NewHandshakeServiceClient(c), nil
}

type handshakeService struct {
	pluginv1.UnimplementedHandshakeServiceServer
	impl Collector
}

// Hello answers before the host knows what this binary is, and before any
// configuration exists. It reports identity and what contracts this binary
// speaks; everything else waits for Describe.
func (h *handshakeService) Hello(ctx context.Context, _ *pluginv1.HelloRequest) (*pluginv1.HelloResponse, error) {
	out := &pluginv1.HelloResponse{
		Offerings: []*pluginv1.Offering{{
			Kind:            collectorv1.Kind,
			ProtocolVersion: collectorv1.ProtocolVersion,
		}},
	}
	// Name and version come from the collector itself so there is one source
	// of truth for them; a plugin that disagreed with its own Describe would
	// be a confusing thing to debug.
	if d, err := h.impl.Describe(ctx); err == nil {
		out.PluginName, out.PluginVersion = d.Name, d.Version
	}
	return out, nil
}

// printVersion writes "<name> <version>", as the collector describes itself.
func printVersion(w io.Writer, c Collector) error {
	d, err := c.Describe(context.Background())
	if err != nil {
		return fmt.Errorf("describing the collector: %w", err)
	}
	_, err = fmt.Fprintf(w, "%s %s\n", d.Name, d.Version)
	return err
}
