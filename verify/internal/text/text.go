// Package text renders what came from outside for a message that a person reads
// on a terminal: a file name, a value from a file, the words of an error.
package text

import (
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Show renders a string as it is if every character in it is one a terminal
// shows plainly, and quoted if not, so that an escape or a direction override in
// a name cannot act on the reader's terminal.
func Show(s string) string {
	if !utf8.ValidString(s) {
		return strconv.Quote(s)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

// Plain is what an error says, without the path an error from the file system
// carries: the path is the caller's to show, through Show, and an error that
// repeats it raw defeats that.
func Plain(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return Show(err.Error())
}

// Quote renders a string inside double quotes, once, and so that where it ends is not
// in doubt: as it is if it is plain, with a quote or a backslash in it escaped, and as
// Show has quoted it if it is not plain.
func Quote(s string) string {
	if q := Show(s); q != s {
		return q
	}
	if strings.ContainsAny(s, `"\\`) {
		return strconv.Quote(s)
	}
	return `"` + s + `"`
}
