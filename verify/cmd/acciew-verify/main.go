// Command acciew-verify checks the evidence Acciew exports: an evidence pack, a
// collection log, or a workflow log, against themselves. It reads files and
// writes nothing; it makes no network calls and runs nothing.
//
//	acciew-verify pack <folder|archive.zip>
//	acciew-verify history <folder> [--source NAME]
//	acciew-verify workflow <folder> [--name NAME]
//	acciew-verify version
//
// The exit status is 0 when what was checked verifies, 1 when it does not, and 2
// when it could not be checked (unreadable, a format this verifier does not know,
// a bound exceeded, or a mistake in the command line).
package main

import (
	"os"

	"go.acciew.io/collector/verify/internal/cli"
)

// version is set by the linker at release: -X main.version=0.2.0.
var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, version))
}
