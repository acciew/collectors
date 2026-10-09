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
	"regexp"
	"runtime/debug"
	"strings"

	"go.acciew.io/collector/verify/internal/cli"
)

// version is set by the linker at release (-X main.version=0.2.0). What it holds is
// what a build that is not stamped reports, and `task release:bump` moves it.
var version = "0.3.0-dev"

func main() {
	info, _ := debug.ReadBuildInfo()
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, reportedVersion(version, info)))
}

// release is a version tag of these modules: v0 or v1, with a pre-release if it has
// one, and no build metadata.
var release = regexp.MustCompile(`^v[01]\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$`)

// pseudo is the end of a version that names a commit and not a tag.
var pseudo = regexp.MustCompile(`[0-9]{14}-[0-9a-f]{12}$`)

// reportedVersion is the version to report. The release workflow stamps a number
// into the binary, and that is the one. A binary built by `go install ...@vX` is
// not stamped, and has the built-in number, which ends in -dev; Go records the version
// it fetched the module at, and when that is a tag it is what the binary is.
func reportedVersion(builtIn string, info *debug.BuildInfo) string {
	if !strings.HasSuffix(builtIn, "-dev") || info == nil {
		return builtIn
	}
	if v := info.Main.Version; release.MatchString(v) && !pseudo.MatchString(v) {
		return strings.TrimPrefix(v, "v")
	}
	return builtIn
}
