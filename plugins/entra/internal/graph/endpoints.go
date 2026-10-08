// Package graph is a small client for the Microsoft Graph API.
//
// It covers what the collector needs and nothing else: an application token
// from a client secret or a certificate, paged reads and a faithful account of
// why a read failed. A general-purpose Graph SDK would be a far larger
// dependency tree and attack surface for endpoints the collector never calls.
//
// Read-only by design: there is no method here that writes, and there should
// never be one.
package graph

// Cloud names a Microsoft cloud. Tokens are not interchangeable between them.
type Cloud string

// The clouds a tenant can live in.
const (
	Global   Cloud = "global"
	USGov    Cloud = "usgov"
	USGovDoD Cloud = "usgov-dod"
	China    Cloud = "china"
)

// Endpoints are the two hosts a cloud has: where tokens come from and where
// Graph answers.
type Endpoints struct {
	Login string
	Graph string
}

// EndpointsFor returns the hosts of a cloud, from Microsoft's national-cloud
// deployments page.
func EndpointsFor(c Cloud) (Endpoints, bool) {
	switch c {
	case Global:
		return Endpoints{"https://login.microsoftonline.com", "https://graph.microsoft.com"}, true
	case USGov:
		return Endpoints{"https://login.microsoftonline.us", "https://graph.microsoft.us"}, true
	case USGovDoD:
		return Endpoints{"https://login.microsoftonline.us", "https://dod-graph.microsoft.us"}, true
	case China:
		return Endpoints{"https://login.chinacloudapi.cn", "https://microsoftgraph.chinacloudapi.cn"}, true
	}
	return Endpoints{}, false
}
