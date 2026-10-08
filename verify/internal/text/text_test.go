package text_test

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"go.acciew.io/collector/verify/internal/text"
)

func TestShowLeavesWhatATerminalShowsPlainly(t *testing.T) {
	for _, s := range []string{"", "x", "acme keycloak", "a.b-c_d", "\xc3\xa9quipe \xe6\x97\xa5\xe6\x9c\xac"} {
		if got := text.Show(s); got != s {
			t.Errorf("Show(%q) = %q", s, got)
		}
	}
}

func TestShowQuotesWhatATerminalWouldObey(t *testing.T) {
	for _, s := range []string{"a\nb", "a\x1b[2Jb", "a\xe2\x80\xaeb", "a\xffb", "a\x00b", "a\xc2\x85b"} {
		got := text.Show(s)
		if got == s || !strings.HasPrefix(got, `"`) || strings.ContainsAny(got, "\n\x1b\x00") ||
			strings.Contains(got, "\xe2\x80\xae") || strings.Contains(got, "\xff") {
			t.Errorf("Show(%q) = %q", s, got)
		}
	}
}

func TestPlainIsWhatAnErrorSaysWithoutThePathItCarries(t *testing.T) {
	boom := errors.New("input/output error")
	path := &fs.PathError{Op: "open", Path: "/tmp/a\x1b[2Jb\xe2\x80\xaec", Err: boom}
	cases := map[string]struct {
		err  error
		want string
	}{
		"a path error":                            {path, "input/output error"},
		"a wrapped path error":                    {fmt.Errorf("while reading: %w", path), "input/output error"},
		"another error":                           {boom, "input/output error"},
		"an error with a control character in it": {errors.New("bad\x1bthing"), `"bad\x1bthing"`},
	}
	for name, tc := range cases {
		if got := text.Plain(tc.err); got != tc.want {
			t.Errorf("%s: Plain = %q, want %q", name, got, tc.want)
		}
	}
}
