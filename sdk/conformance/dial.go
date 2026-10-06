package conformance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"

	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	pluginv1 "go.acciew.io/collector/api/plugin/v1"
)

// A second client, and a deliberate one.
//
// The core's client lives in internal/pluginhost, and the import rules stop
// this module reaching it: a plugin author's library may not depend on the
// server's internals, and the server may not depend on a plugin author's
// library. Sharing this code would mean weakening one of those, which is a
// bad trade for sixty lines.
//
// The rules the suite actually enforces are not duplicated: they live once in
// the contract module, and both clients call the same implementation.

// Client is a running collector under test.
type Client struct {
	client *goplugin.Client
	rpc    collectorv1.CollectorServiceClient
}

// Dial starts a collector binary and returns a Plugin to exercise.
func Dial(ctx context.Context, path string) (*Client, error) {
	c := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: goplugin.HandshakeConfig{
			ProtocolVersion:  pluginv1.MechanismVersion,
			MagicCookieKey:   pluginv1.MagicCookieKey,
			MagicCookieValue: pluginv1.MagicCookieValue,
		},
		Plugins: map[string]goplugin.Plugin{
			pluginv1.Entry(collectorv1.Kind, collectorv1.ProtocolVersion): &collectorClient{},
		},
		Cmd:              exec.CommandContext(ctx, path),
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
	})

	rpc, err := c.Client()
	if err != nil {
		c.Kill()
		return nil, err
	}
	raw, err := rpc.Dispense(pluginv1.Entry(collectorv1.Kind, collectorv1.ProtocolVersion))
	if err != nil {
		c.Kill()
		return nil, fmt.Errorf("the binary does not serve %s: %w",
			pluginv1.Entry(collectorv1.Kind, collectorv1.ProtocolVersion), err)
	}
	svc, ok := raw.(collectorv1.CollectorServiceClient)
	if !ok {
		c.Kill()
		return nil, fmt.Errorf("the binary's collector entry is not a collector service")
	}
	return &Client{client: c, rpc: svc}, nil
}

// Close stops the collector process.
func (c *Client) Close() { c.client.Kill() }

func (c *Client) Describe(ctx context.Context) (*collectorv1.DescribeResponse, error) {
	return c.rpc.Describe(ctx, &collectorv1.DescribeRequest{})
}

func (c *Client) ValidateConfig(ctx context.Context, config []byte) ([]*collectorv1.ConfigIssue, error) {
	resp, err := c.rpc.ValidateConfig(ctx, &collectorv1.ValidateConfigRequest{Config: config})
	return resp.GetIssues(), err
}

func (c *Client) TestConnection(ctx context.Context, config []byte) ([]*collectorv1.ScopeProbe, error) {
	resp, err := c.rpc.TestConnection(ctx, &collectorv1.TestConnectionRequest{Config: config})
	return resp.GetScopes(), err
}

func (c *Client) Revoke(ctx context.Context, req *collectorv1.RevokeRequest) (*collectorv1.RevokeResponse, error) {
	return c.rpc.Revoke(ctx, req)
}

// Collect drains the whole stream into memory. That is fine here and would
// not be in the host: a conformance run is against a fixture, and the suite
// needs every event at once to check properties that span the stream.
func (c *Client) Collect(ctx context.Context, req *collectorv1.CollectRequest) ([]*collectorv1.CollectResponse, error) {
	stream, err := c.rpc.Collect(ctx, req)
	if err != nil {
		return nil, err
	}
	var out []*collectorv1.CollectResponse
	for {
		e, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, e)
	}
}

type collectorClient struct {
	goplugin.NetRPCUnsupportedPlugin
}

func (collectorClient) GRPCServer(*goplugin.GRPCBroker, *grpc.Server) error { return nil }

func (collectorClient) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, cc *grpc.ClientConn) (any, error) {
	return collectorv1.NewCollectorServiceClient(cc), nil
}
