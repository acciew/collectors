module go.acciew.io/collector/sdk/examples/minimal

go 1.26.0

require (
	go.acciew.io/collector/api v0.1.1
	go.acciew.io/collector/sdk/conformance v0.1.1
	go.acciew.io/collector/sdk/go v0.1.1
)

require (
	github.com/fatih/color v1.13.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-plugin v1.8.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/oklog/run v1.1.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// Local development: modules in this repository resolve to their directories.
// Whoever imports a module ignores these; every module is tagged together.
replace go.acciew.io/collector/api => ../../../api

replace go.acciew.io/collector/sdk/conformance => ../../conformance

replace go.acciew.io/collector/sdk/go => ../../go
