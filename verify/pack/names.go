package pack

import (
	"errors"
	"regexp"
	"strings"
)

// maxDepth is the most parts a path in a pack has; real ones have three.
const maxDepth = 8

// plainName is what one part of a path in a pack may be: letters, digits, dot,
// dash and underscore, starting with a letter or digit. Names come from sources
// and from the customer, and end up in an archive, a file system and the line
// format sha256sum reads.
var plainName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// reserved are the names Windows will not make a file of, with any extension.
var reserved = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])$`)

// plainPart is true for one plain part of a path.
func plainPart(part string) bool {
	base, _, _ := strings.Cut(part, ".")
	return plainName.MatchString(part) && !reserved.MatchString(base)
}

// checkPath says why a path in a pack is not one: it is a series of plain parts
// joined by "/", with no empty part, no "." and no "..", no backslash, nothing
// absolute, and not deeper than maxDepth.
func checkPath(p string) error {
	if p == "" {
		return errors.New("is empty")
	}
	parts := strings.Split(p, "/")
	if len(parts) > maxDepth {
		return errors.New("is nested more deeply than a pack is")
	}
	for _, part := range parts {
		if !plainPart(part) {
			return errors.New("is not a plain name: letters, digits, dot, dash and underscore, " +
				"starting with a letter or digit, joined by slashes, with nothing that climbs or is absolute")
		}
	}
	return nil
}
