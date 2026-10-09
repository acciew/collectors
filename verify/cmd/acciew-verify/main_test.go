package main

import (
	"runtime/debug"
	"testing"
)

func info(version string) *debug.BuildInfo {
	return &debug.BuildInfo{Main: debug.Module{Path: "go.acciew.io/collector/verify", Version: version}}
}

// A binary the release workflow built is stamped with the release's number. One that
// `go install ...@vX` built is not, and says so by its built-in number ending in -dev;
// then the version the module was fetched at is the one to report.
func TestTheVersionReportedIsTheReleaseNotTheBuiltInNumberOfAnInstalledModule(t *testing.T) {
	cases := []struct {
		name    string
		builtIn string
		info    *debug.BuildInfo
		want    string
	}{
		{"installed at a release", "0.1.1-dev", info("v0.2.0"), "0.2.0"},
		{"installed at a pre-release", "0.1.1-dev", info("v0.2.0-rc.1"), "0.2.0-rc.1"},
		{"installed at a later patch", "0.2.0-dev", info("v0.2.3"), "0.2.3"},
		{"built in a checkout", "0.2.0-dev", info("(devel)"), "0.2.0-dev"},
		{"built with no version recorded", "0.2.0-dev", info(""), "0.2.0-dev"},
		{"built from a commit that is no tag", "0.2.0-dev", info("v0.0.0-20261009020109-894f7ab2419c"), "0.2.0-dev"},
		{"built from a commit after a tag", "0.2.0-dev", info("v0.2.1-0.20261009020109-894f7ab2419c"), "0.2.0-dev"},
		{"built from a commit after a pre-release", "0.2.0-dev", info("v0.2.0-rc.1.0.20261009020109-894f7ab2419c"), "0.2.0-dev"},
		{"built from a tag with changes", "0.2.0-dev", info("v0.2.0+dirty"), "0.2.0-dev"},
		{"a version that is not one of these modules'", "0.2.0-dev", info("v2.0.0"), "0.2.0-dev"},
		{"a version that is not one at all", "0.2.0-dev", info("latest"), "0.2.0-dev"},
		{"no build information", "0.2.0-dev", nil, "0.2.0-dev"},
		{"stamped by the release build", "0.2.0", info("v0.0.0-20261009020109-894f7ab2419c"), "0.2.0"},
		{"stamped, and installed at another version", "0.2.0", info("v0.3.0"), "0.2.0"},
		{"stamped as a pre-release", "0.2.0-rc.1", info("(devel)"), "0.2.0-rc.1"},
	}
	for _, tc := range cases {
		if got := reportedVersion(tc.builtIn, tc.info); got != tc.want {
			t.Errorf("%s: reportedVersion(%q) = %q, want %q", tc.name, tc.builtIn, got, tc.want)
		}
	}
}
