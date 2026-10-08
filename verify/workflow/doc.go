// Package workflow reads and checks a workflow log: the record of what was done
// in a review, one event per entry, chained so that the log can be checked
// against itself.
//
// An entry carries its event as the text the digest was taken over, and the
// digest is taken over exactly those bytes, so a file can be checked without
// reading the event as anything but text. The line it is in must be the one form
// lines are written in. docs/evidence-format.md specifies the form precisely
// enough to be written again from the document alone.
package workflow
