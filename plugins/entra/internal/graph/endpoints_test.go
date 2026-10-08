package graph_test

import (
	"testing"

	"go.acciew.io/collector/plugins/entra/internal/graph"
)

// Tokens from one cloud are refused by every other, so a wrong host is a
// credential that works nowhere rather than one that works against the wrong
// tenant. The hosts are Microsoft's, from its national-cloud deployments page.
func TestEachCloudHasItsOwnLoginAndGraphHost(t *testing.T) {
	for _, c := range []struct {
		cloud        graph.Cloud
		login, graph string
	}{
		{graph.Global, "https://login.microsoftonline.com", "https://graph.microsoft.com"},
		{graph.USGov, "https://login.microsoftonline.us", "https://graph.microsoft.us"},
		{graph.USGovDoD, "https://login.microsoftonline.us", "https://dod-graph.microsoft.us"},
		{graph.China, "https://login.chinacloudapi.cn", "https://microsoftgraph.chinacloudapi.cn"},
	} {
		got, ok := graph.EndpointsFor(c.cloud)
		if !ok || got.Login != c.login || got.Graph != c.graph {
			t.Errorf("%s = %+v (known %v), want login %s graph %s", c.cloud, got, ok, c.login, c.graph)
		}
	}
	if _, ok := graph.EndpointsFor("mars"); ok {
		t.Error("an unknown cloud resolved to hosts")
	}
}
