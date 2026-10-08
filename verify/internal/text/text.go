// Package text renders what came from outside for a message that a person reads
// on a terminal: a file name, a value from a file, the words of an error.
package text

import (
	"errors"
	"io/fs"
	"strconv"
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
