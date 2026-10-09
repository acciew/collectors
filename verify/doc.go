// Package verify is the open-source checker for the evidence Acciew exports.
//
// It reads the exported files and nothing else, and it depends on the Go
// standard library alone: no code from the rest of this repository, and none
// from anyone else. What the formats are is written down in
// docs/evidence-format.md; the packages below implement that document.
//
//   - chain: the hash chain over log entries and the anchor that names its end.
//   - collection: the collection log, its canonical form and digest, and its reader.
//   - workflow: the workflow log, whose events are digested as the text they are written in.
//   - pack: an evidence pack, its files, its logs and what they say about one another.
//
// A check that passes shows that the files agree with each other. It does not
// show who wrote them or when, and the README says what else it cannot show.
package verify
