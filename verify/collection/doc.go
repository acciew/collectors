// Package collection reads and checks a collection log: the record of what a
// collector found, one entry per collection, chained so that the log can be
// checked against itself.
//
// The types here are the wire shape of the log, not the in-memory model of the
// service that writes it: enumerations are the numbers on the wire, and a key is
// three fields. The digest of an entry is taken over the canonical form of its
// run, which docs/evidence-format.md specifies precisely enough to be written
// again from the document alone.
package collection
