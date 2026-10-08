// Command acciew-agent runs collectors in a customer's network and uploads what
// they find to the Acciew service over outbound HTTPS. See README.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.acciew.io/collector/cmd/acciew-agent/internal/cli"
)

// version is stamped at build time; the default is what a local build reports.
var version = "0.1.1-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.Env{Version: version, Stdout: os.Stdout, Stderr: os.Stderr})
	stop()
	os.Exit(code)
}
