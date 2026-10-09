package pack

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/collection"
	"go.acciew.io/collector/verify/internal/jsonobj"
	"go.acciew.io/collector/verify/internal/text"
	"go.acciew.io/collector/verify/workflow"
)

// The reasons a pack check can name. Those of the logs and their anchors are the
// reasons of the collection, workflow and chain packages and are used as they
// are. They are stable: a caller may switch on them.
const (
	// Errors: the pack could not be checked.

	// ReasonUnreadable: the pack, or its manifest, cannot be read as one.
	ReasonUnreadable = "unreadable"
	// ReasonFormat: the manifest is of a version this verifier does not know.
	ReasonFormat = "format"
	// ReasonLimit: the pack expands past the limits.
	ReasonLimit = "limit"

	// Findings: the pack was checked and does not agree with itself.

	// ReasonName: an entry has a name no pack has, and is not read.
	ReasonName = "name"
	// ReasonNotPlain: an entry is a link or another file that is not plain.
	ReasonNotPlain = "notplain"
	// ReasonDuplicate: an archive holds a name more than once.
	ReasonDuplicate = "duplicate"
	// ReasonManifest: the manifest is not in a form this verifier reads, or does
	// not list what the cross-references need.
	ReasonManifest = "manifest"
	// ReasonMissing: a listed file is not in the pack.
	ReasonMissing = "missing"
	// ReasonSize: a listed file has another size than the manifest lists.
	ReasonSize = "size"
	// ReasonSHA256: a listed file has another digest than the manifest lists.
	ReasonSHA256 = "sha256"
	// ReasonUnlisted: a file is in the pack and the manifest does not list it.
	ReasonUnlisted = "unlisted"
	// ReasonList: manifest.sha256 is not the list the manifest gives.
	ReasonList = "list"
	// ReasonCollection: an entry the manifest names is not in its collection log.
	ReasonCollection = "collection"
	// ReasonHead: a log ends where the manifest does not say it does.
	ReasonHead = "head"
	// ReasonCampaign: campaign.json and the manifest name different facts.
	ReasonCampaign = "campaign"
	// ReasonLocked: the workflow log does not hold the lock the manifest names.
	ReasonLocked = "locked"
	// ReasonCompleted: the workflow log holds a collection that is not the one the
	// collection log has for that entry, or does not hold one the lock names.
	ReasonCompleted = "completed"

	// ReasonNote is the reason of a note, which is not a finding: a pack with
	// notes can still verify.
	ReasonNote = "note"
)

// Error is why a pack could not be checked at all. Its text says what, and
// nothing about the pack's contents.
type Error struct {
	Reason string
	msg    string
	err    error
}

func (e *Error) Error() string { return e.msg }
func (e *Error) Unwrap() error { return e.err }

// ReasonOf is the reason code of an error from this package, or "" for any other.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// Finding is one way the pack does not agree with itself.
type Finding struct {
	Reason string
	// Path is the file the finding is about, as the pack names it. It came from
	// outside: show it with text.Show or through String.
	Path string
	// Message says what is wrong, with any name in it already made safe to print.
	Message string
}

// String is the finding as one line, with the path made safe to print.
func (f Finding) String() string { return text.Show(f.Path) + ": " + f.Message }

// Log is a log that was checked and held.
type Log struct {
	Path    string
	Entries int
	// Head is the chain value of the last entry.
	Head string
}

// Report is what a check of a pack found.
type Report struct {
	// ManifestSHA256 is the digest of manifest.json. The service records the digest
	// of each manifest it hands out; this is what to compare it with.
	ManifestSHA256 string
	// Files is how many listed files are in the pack, with the size and digest listed.
	Files int
	// Collections are the collection logs that held, in the order the manifest lists them.
	Collections []Log
	// Workflow is the workflow log, if it held.
	Workflow Log
	// Findings are the ways the pack does not agree with itself. None means the
	// check passed.
	Findings []Finding
	// Notes are things that were seen and do not count against the pack. A folder
	// that was opened holds what the operating system left in it (.DS_Store,
	// Thumbs.db, __MACOSX); they are not read, and the pack is checked as it was
	// handed over, as an archive. An archive has no notes.
	Notes []Finding
	// More is how many findings were left out after the first two hundred.
	More int
}

// Verified says whether the pack agrees with itself.
func (r *Report) Verified() bool { return len(r.Findings) == 0 && r.More == 0 }

// Options say how a pack is verified.
type Options struct {
	Limits Limits
}

// maxFindings bounds the report: a hostile pack could have a finding for every
// line of a gigabyte.
const maxFindings = 200

// VerifyDir checks the pack in a folder. The folder is opened through os.Root,
// so nothing outside it is read, and a link, or any file that is not plain, is
// named and not followed.
func VerifyDir(dir string, opts Options) (*Report, error) {
	d, err := openDir(dir)
	if err != nil {
		return nil, err
	}
	defer d.close()
	return check(d, opts.Limits.withDefaults())
}

// VerifyZip checks the pack in a ZIP archive, in place: each file is read from
// the archive as it is needed and nothing is extracted.
func VerifyZip(r io.ReaderAt, size int64, opts Options) (*Report, error) {
	z, err := openZip(r, size)
	if err != nil {
		return nil, err
	}
	return check(z, opts.Limits.withDefaults())
}

type verifier struct {
	rd      *reader
	rep     *Report
	present map[string]entry
	// held are the listed files that are as the manifest lists them.
	held map[string]bool
}

func (v *verifier) add(f Finding) {
	if len(v.rep.Findings) >= maxFindings {
		v.rep.More++
		return
	}
	v.rep.Findings = append(v.rep.Findings, f)
}

func (v *verifier) addf(reason, path, format string, args ...any) {
	v.add(Finding{Reason: reason, Path: path, Message: fmt.Sprintf(format, args...)})
}

// logOutcome is what became of reading a log.
type logOutcome struct {
	ran     bool
	summary collection.Summary
	err     error
	got     map[uint64]chain.Entry
}

func check(src source, lim Limits) (*Report, error) {
	v := &verifier{rd: &reader{src: src, lim: lim}, rep: &Report{}, present: map[string]entry{}, held: map[string]bool{}}
	entries, findings, notes, err := src.list(lim)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		v.add(f)
	}
	v.rep.Notes = notes
	for _, e := range entries {
		v.present[e.path] = e
	}

	if _, ok := v.present["manifest.json"]; !ok {
		return nil, notReadable(nil, "manifest.json is not there: this is not an evidence pack")
	}
	raw, manifestRes, err := v.rd.readAll("manifest.json")
	if err != nil {
		return nil, err
	}
	if manifestRes.err != nil {
		return nil, manifestRes.err
	}
	v.rep.ManifestSHA256 = manifestRes.sum
	m, problems, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		for _, p := range problems {
			v.addf(ReasonManifest, "manifest.json", "%s", p)
		}
		return v.rep, nil
	}

	listed, order := v.listed(m)
	need := v.needed(m, listed)

	// The anchors first: a log is checked against its anchor from the start. An
	// anchor is read as far as an anchor can be and the rest only for the digest.
	results := map[string]result{}
	heads := map[string][]byte{}
	for _, c := range m.collections {
		if err := v.readHead(historyPath(c, ".head"), heads, results); err != nil {
			return nil, err
		}
	}
	if err := v.readHead(workflowHead, heads, results); err != nil {
		return nil, err
	}
	campaignRaw := map[string][]byte{}

	// The workflow log first, with the events the cross-references read, so that
	// each entry of a collection log can be held to what the workflow log says of it.
	wf := &workflowRun{campaign: m.campaignID, wanted: map[string]bool{}, packed: map[string]uint64{}}
	for _, c := range m.collections {
		wf.wanted[completionKey(c.connection, c.seq)] = true
		wf.packed[c.connection] = max(wf.packed[c.connection], c.headSeq)
	}
	if need.ok(workflowLog) {
		res, err := v.rd.read(workflowLog, func(in io.Reader) error {
			wf.ran = true
			opts := workflow.Options{Limits: workflow.Limits{MaxLineBytes: lim.MaxLineBytes}, Entry: wf.entry}
			wf.summary, wf.err = workflow.VerifyWith("workflow", in, headReader(heads, workflowHead), opts)
			return nil
		})
		if err != nil {
			return nil, err
		}
		results[workflowLog] = res
		if wf.overflow {
			return nil, limitError("the workflow log holds more than %d collection.completed events for the collections of this pack, which is more than a pack does", maxCompletions)
		}
	}

	// Each history log once, whichever collections name it.
	wanted := map[string]map[uint64]bool{}
	connection := map[string]string{}
	var logPaths []string
	for _, c := range m.collections {
		p := historyPath(c, ".jsonl")
		if wanted[p] == nil {
			wanted[p] = map[uint64]bool{}
			logPaths = append(logPaths, p)
		}
		wanted[p][c.seq] = true
		connection[p] = c.connection
	}
	outcomes := map[string]*logOutcome{}
	for _, p := range logPaths {
		out := &logOutcome{got: map[uint64]chain.Entry{}}
		outcomes[p] = out
		if !need.ok(p) {
			continue
		}
		headPath := strings.TrimSuffix(p, ".jsonl") + ".head"
		res, err := v.rd.read(p, func(in io.Reader) error {
			out.ran = true
			opts := collection.Options{Limits: collection.Limits{MaxLineBytes: lim.MaxLineBytes}, Entry: func(e collection.Entry) {
				if wanted[p][e.Sequence] {
					out.got[e.Sequence] = e.Entry
				}
				v.holdToCompletions(wf, p, connection[p], e.Entry)
			}}
			out.summary, out.err = collection.VerifyWith(strings.TrimSuffix(p, ".jsonl"), in, headReader(heads, headPath), opts)
			return nil
		})
		if err != nil {
			return nil, err
		}
		results[p] = res
	}

	// campaign.json, and everything else that is listed, by digest.
	for _, f := range order {
		if _, done := results[f.path]; done {
			continue
		}
		if _, there := v.present[f.path]; !there {
			continue
		}
		if f.path == campaignPath {
			body, res, err := v.rd.readAll(f.path)
			if err != nil {
				return nil, err
			}
			campaignRaw[f.path] = body
			results[f.path] = res
			continue
		}
		res, err := v.rd.read(f.path, nil)
		if err != nil {
			return nil, err
		}
		results[f.path] = res
	}

	v.compareFiles(order, results)
	v.unlisted(listed)
	v.compareList(m, manifestRes.sum)
	v.logs(m, outcomes)
	v.workflowLog(m, wf)
	v.campaign(m, need, campaignRaw)
	v.lock(m, wf)
	return v.rep, nil
}

func headReader(heads map[string][]byte, path string) io.Reader {
	if b, ok := heads[path]; ok {
		return bytes.NewReader(b)
	}
	return nil
}

const (
	campaignPath = "campaign.json"
	workflowLog  = "workflow/workflow.jsonl"
	workflowHead = "workflow/workflow.head"
)

func historyPath(c manifestCollection, ext string) string {
	return "history/" + c.connection + "/" + c.plugin + ext
}

// needs is the set of files that are listed and so may be relied on.
type needs map[string]bool

func (n needs) ok(p string) bool { return n[p] }

// listed indexes the manifest's files, naming what cannot be one.
func (v *verifier) listed(m *manifest) (map[string]manifestFile, []manifestFile) {
	listed := map[string]manifestFile{}
	var order []manifestFile
	for _, f := range m.files {
		switch {
		case f.path == "manifest.json" || f.path == "manifest.sha256":
			v.addf(ReasonManifest, "manifest.json", "lists %s, which cannot hold its own digest", quote(f.path))
		case checkPath(f.path) != nil:
			v.addf(ReasonManifest, "manifest.json", "lists %s, which is not a plain name", quote(f.path))
		case listedAlready(listed, f.path):
			v.addf(ReasonManifest, "manifest.json", "lists %s more than once", quote(f.path))
		default:
			listed[f.path] = f
			order = append(order, f)
		}
	}
	return listed, order
}

func listedAlready(l map[string]manifestFile, p string) bool { _, ok := l[p]; return ok }

// needed names what the cross-references rely on and the manifest must therefore
// list, and returns the files that can be relied on: listed ones.
func (v *verifier) needed(m *manifest, listed map[string]manifestFile) needs {
	n := needs{}
	for p := range listed {
		n[p] = true
	}
	require := func(p, why string) {
		if _, ok := listed[p]; !ok {
			v.addf(ReasonManifest, "manifest.json", "does not list %s, which %s needs", quote(p), why)
		}
	}
	require(campaignPath, "the campaign check")
	require(workflowLog, "the workflow check")
	for i, c := range m.collections {
		why := fmt.Sprintf("collection %d", i+1)
		require(historyPath(c, ".jsonl"), why)
		if checkPath(c.snapshot) != nil {
			v.addf(ReasonManifest, "manifest.json", "%s has a snapshot that is not a plain name: %s", why, quote(c.snapshot))
		} else {
			require(c.snapshot, why)
		}
	}
	return n
}

// readHead reads an anchor as far as an anchor can be, to check a log against,
// and the rest of the file only for its digest.
func (v *verifier) readHead(p string, heads map[string][]byte, results map[string]result) error {
	if _, ok := v.present[p]; !ok {
		return nil
	}
	if _, again := results[p]; again {
		return nil
	}
	var head []byte
	res, err := v.rd.read(p, func(in io.Reader) error {
		var err error
		head, err = io.ReadAll(io.LimitReader(in, chain.MaxAnchorBytes+1))
		return err
	})
	if err != nil {
		return err
	}
	heads[p], results[p] = head, res
	return nil
}

// compareFiles checks each listed file against the manifest, in the manifest's order.
func (v *verifier) compareFiles(order []manifestFile, results map[string]result) {
	for _, f := range order {
		res, read := results[f.path]
		switch {
		case !v.has(f.path):
			v.addf(ReasonMissing, f.path, "is listed in the manifest and is not in the pack")
		case !read:
			// Not read: it is not one the checks could rely on, which was said already.
		case res.err != nil:
			v.add(Finding{Reason: ReasonUnreadable, Path: f.path, Message: res.err.Error()})
		case !same(res.size, f.bytes):
			v.addf(ReasonSize, f.path, "has %d bytes and the manifest lists %d", res.size, f.bytes)
		case res.sum != f.sha256:
			v.addf(ReasonSHA256, f.path, "is not the file the manifest lists: its SHA-256 is %s and the manifest says %s", res.sum, f.sha256)
		default:
			v.rep.Files++
			v.held[f.path] = true
		}
	}
}

func (v *verifier) has(p string) bool { _, ok := v.present[p]; return ok }

// unlisted names what is in the pack and the manifest does not list: what
// sha256sum -c cannot see.
func (v *verifier) unlisted(listed map[string]manifestFile) {
	var extra []string
	for p := range v.present {
		if _, ok := listed[p]; !ok && p != "manifest.json" && p != "manifest.sha256" {
			extra = append(extra, p)
		}
	}
	sort.Strings(extra)
	for _, p := range extra {
		v.addf(ReasonUnlisted, p, "is in the pack and the manifest does not list it")
	}
}

// compareList checks manifest.sha256 against the list the manifest gives.
func (v *verifier) compareList(m *manifest, manifestSum string) {
	if !v.has("manifest.sha256") {
		v.addf(ReasonMissing, "manifest.sha256", "is not in the pack")
		return
	}
	got, _, err := v.rd.readAll("manifest.sha256")
	if err != nil {
		v.add(Finding{Reason: ReasonUnreadable, Path: "manifest.sha256", Message: err.Error()})
		return
	}
	want := expectedList(m.files, manifestSum)
	if string(got) == want {
		return
	}
	gl, wl := strings.SplitAfter(string(got), "\n"), strings.SplitAfter(want, "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			v.addf(ReasonList, "manifest.sha256", "is not the list of digests the manifest gives: line %d differs (it has %d lines and the manifest gives %d)", i+1, len(gl), len(wl))
			return
		}
	}
}

// logs checks each collection against its log.
func (v *verifier) logs(m *manifest, outcomes map[string]*logOutcome) {
	reported := map[string]bool{}
	for i, c := range m.collections {
		p := historyPath(c, ".jsonl")
		out := outcomes[p]
		if out == nil || !out.ran {
			continue
		}
		if out.err != nil {
			if !reported[p] {
				reported[p] = true
				v.logFault(p, out.err)
			}
			continue
		}
		if !reported[p] {
			reported[p] = true
			v.rep.Collections = append(v.rep.Collections, Log{Path: p, Entries: out.summary.Entries, Head: out.summary.Head})
		}
		where := fmt.Sprintf("collection %d", i+1)
		switch e, ok := out.got[c.seq]; {
		case !ok:
			v.addf(ReasonCollection, p, "the manifest names entry %d of this log for %s, and the log ends at entry %d", c.seq, where, out.summary.Entries)
		case e.Digest != c.digest || e.Chain != c.chain:
			v.addf(ReasonCollection, p, "entry %d of this log has the digest %s and the chain value %s, and the manifest names %s and %s for %s",
				c.seq, short(e.Digest), short(e.Chain), short(c.digest), short(c.chain), where)
		}
		if !same(int64(out.summary.Entries), c.headSeq) || out.summary.Head != c.headChain {
			v.addf(ReasonHead, p, "the log ends at entry %d (%s) and the manifest says it ends at entry %d (%s)",
				out.summary.Entries, short(out.summary.Head), c.headSeq, short(c.headChain))
		}
	}
}

func (v *verifier) logFault(p string, err error) {
	reason := collection.ReasonOf(err)
	if reason == "" {
		reason = ReasonUnreadable
	}
	inner := errors.Unwrap(err)
	if inner == nil {
		inner = err
	}
	v.add(Finding{Reason: reason, Path: p, Message: inner.Error()})
}

func short(s string) string {
	if len(s) > 12 {
		s = s[:12]
	}
	return quote(s)
}

// workflowRun gathers, as the workflow log is read, the events the pack is
// cross-referenced with.
type workflowRun struct {
	campaign string
	wanted   map[string]bool
	// packed is, for each connection the pack carries, how far its log goes.
	packed map[string]uint64
	// overflow says the log held more completions than are kept.
	overflow bool

	ran     bool
	summary workflow.Summary
	err     error

	problems  []Finding
	locks     []lockEvent
	completed map[string][]completedEvent
	kept      int
}

// maxCompletions bounds what is kept of the workflow log: one event for each
// entry of the collection logs of the pack, and a pack has few of those.
const maxCompletions = 1_000_000

// holdToCompletions checks an entry of a collection log against the
// collection.completed events the workflow log holds for it. An event for an
// entry has to say what the log says of that entry, wherever the review was locked
// from, so replacing an entry later means rewriting the workflow chain too.
func (v *verifier) holdToCompletions(w *workflowRun, logPath, connection string, e chain.Entry) {
	if !w.ran || w.err != nil {
		return
	}
	for _, ev := range w.completed[completionKey(connection, e.Sequence)] {
		if ev.digest != e.Digest || ev.chain != e.Chain {
			v.addf(ReasonCompleted, workflowLog, "entry %d: the collection.completed event for %s, entry %d, has the digest %s and the chain value %s, "+
				"and %s has %s and %s", ev.seq, quote(connection), e.Sequence, short(ev.digest), short(ev.chain), quote(logPath), short(e.Digest), short(e.Chain))
		}
	}
}

type lockEvent struct {
	seq     uint64
	digest  string
	sources []campaignSource
	err     string
}

type completedEvent struct {
	seq           uint64
	digest, chain string
}

func completionKey(connection string, seq uint64) string {
	return fmt.Sprintf("%d:%s:%d", len(connection), connection, seq)
}

// entry is called with each event that has passed the checks of a workflow log.
func (w *workflowRun) entry(e workflow.Entry, ev workflow.Event) {
	if ev.Type != "campaign.locked" && ev.Type != "collection.completed" {
		return
	}
	data, err := jsonobj.Members(ev.Data)
	if ev.Data == nil {
		err = errors.New("has no data")
	}
	bad := func(format string, args ...any) {
		w.problems = append(w.problems, Finding{Reason: string(workflow.ReasonEvent), Path: workflowLog,
			Message: fmt.Sprintf("entry %d: the data of the %s event %s", e.Sequence, ev.Type, fmt.Sprintf(format, args...))})
	}
	if err != nil {
		bad("%v", err)
		return
	}
	var problems []string
	problem := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	switch ev.Type {
	case "campaign.locked":
		id := stringMember(data, "the event", "campaign", problem)
		if len(problems) > 0 {
			bad("cannot be read: %s", strings.Join(problems, "; "))
			return
		}
		if id != w.campaign {
			return
		}
		l := lockEvent{seq: e.Sequence, digest: stringMember(data, "the event", "digest", problem)}
		if raw, ok := data["sources"]; !ok {
			problem("the event has no sources")
		} else if items, err := jsonobj.Array(raw); err != nil {
			problem("sources %v", err)
		} else {
			for i, item := range items {
				s, err := jsonobj.Members(item)
				if err != nil {
					problem("source %d %v", i+1, err)
					continue
				}
				where := fmt.Sprintf("source %d", i+1)
				l.sources = append(l.sources, campaignSource{
					connection: stringMember(s, where, "connection", problem),
					seq:        uintMember(s, where, "seq", problem),
					digest:     stringMember(s, where, "digest", problem),
					chain:      stringMember(s, where, "chain_value", problem),
				})
			}
		}
		l.err = strings.Join(problems, "; ")
		w.locks = append(w.locks, l)
	case "collection.completed":
		c := completedEvent{
			digest: stringMember(data, "the event", "digest", problem),
			chain:  stringMember(data, "the event", "chain_value", problem),
		}
		connection := stringMember(data, "the event", "connection", problem)
		c.seq = uintMember(data, "the event", "seq", problem)
		if len(problems) > 0 {
			bad("cannot be read: %s", strings.Join(problems, "; "))
			return
		}
		// Kept: those of the entries the review was locked from, and of every entry
		// of a connection the pack carries that its log had when it was exported.
		key := completionKey(connection, c.seq)
		head, packed := w.packed[connection]
		if !w.wanted[key] && (!packed || c.seq > head) {
			return
		}
		if w.completed == nil {
			w.completed = map[string][]completedEvent{}
		}
		if w.kept++; w.kept > maxCompletions {
			w.overflow = true
			return
		}
		w.completed[key] = append(w.completed[key], completedEvent{seq: e.Sequence, digest: c.digest, chain: c.chain})
	}
}

// workflowLog reports the workflow log's own fault, or that it held, and checks
// where it ends against the manifest.
func (v *verifier) workflowLog(m *manifest, w *workflowRun) {
	if !w.ran {
		return
	}
	if w.err != nil {
		v.logFault(workflowLog, w.err)
		return
	}
	v.rep.Workflow = Log{Path: workflowLog, Entries: w.summary.Entries, Head: w.summary.Head}
	if !same(int64(w.summary.Entries), m.workflow.seq) || w.summary.Head != m.workflow.chain {
		v.addf(ReasonHead, workflowLog, "the log ends at entry %d (%s) and the manifest says it ends at entry %d (%s)",
			w.summary.Entries, short(w.summary.Head), m.workflow.seq, short(m.workflow.chain))
	}
	for _, p := range w.problems {
		v.add(p)
	}
}

// campaign checks campaign.json against the manifest.
func (v *verifier) campaign(m *manifest, need needs, raw map[string][]byte) {
	body, ok := raw[campaignPath]
	if !ok || !v.held[campaignPath] {
		return
	}
	c, problems := parseCampaign(body)
	for _, p := range problems {
		v.addf(ReasonCampaign, campaignPath, "%s", p)
	}
	if len(problems) > 0 || c == nil {
		return
	}
	if c.id != m.campaignID {
		v.addf(ReasonCampaign, campaignPath, "names the campaign %s and the manifest names %s", quote(c.id), quote(m.campaignID))
	}
	if c.lockDigest != m.lockDigest {
		v.addf(ReasonCampaign, campaignPath, "has the lock digest %s and the manifest has %s", short(c.lockDigest), short(m.lockDigest))
	}
	missing, surplus := compareSources(m, c.sources, func(s campaignSource) string {
		return fmt.Sprintf("%q|%q|%d|%q|%q", s.connection, s.plugin, s.seq, s.digest, s.chain)
	}, func(c manifestCollection) string {
		return fmt.Sprintf("%q|%q|%d|%q|%q", c.connection, c.plugin, c.seq, c.digest, c.chain)
	})
	if len(missing) > 0 || surplus > 0 {
		v.addf(ReasonCampaign, campaignPath, "does not name the collections the manifest names%s", describeSources(missing, surplus))
	}
}

// compareSources matches the collections a document names with the manifest's,
// as sets with counts, and returns those of the manifest's it lacks and how many
// it names that the manifest does not.
func compareSources(m *manifest, sources []campaignSource, keyOf func(campaignSource) string, keyOfCollection func(manifestCollection) string) (missing []manifestCollection, surplus int) {
	have := map[string]int{}
	for _, s := range sources {
		have[keyOf(s)]++
	}
	for _, c := range m.collections {
		k := keyOfCollection(c)
		if have[k] == 0 {
			missing = append(missing, c)
			continue
		}
		have[k]--
	}
	for _, n := range have {
		surplus += n
	}
	return missing, surplus
}

func describeSources(missing []manifestCollection, surplus int) string {
	var parts []string
	for _, c := range missing {
		parts = append(parts, fmt.Sprintf("%s, entry %d, is not among them", quote(c.connection), c.seq))
	}
	if surplus > 0 {
		parts = append(parts, fmt.Sprintf("and it names %d the manifest does not", surplus))
	}
	return ": " + strings.Join(parts, "; ")
}

// lock checks the workflow log for the lock and the collections it names.
func (v *verifier) lock(m *manifest, w *workflowRun) {
	if !w.ran || w.err != nil {
		return
	}
	var lock *lockEvent
	switch len(w.locks) {
	case 0:
		v.addf(ReasonLocked, workflowLog, "holds no campaign.locked event for the campaign %s", quote(m.campaignID))
	case 1:
		lock = &w.locks[0]
	default:
		v.addf(ReasonLocked, workflowLog, "holds %d campaign.locked events for the campaign %s, and a review is locked once", len(w.locks), quote(m.campaignID))
	}
	if lock != nil {
		switch {
		case lock.err != "":
			v.addf(ReasonLocked, workflowLog, "entry %d: the campaign.locked event cannot be read: %s", lock.seq, lock.err)
		default:
			if lock.digest != m.lockDigest {
				v.addf(ReasonLocked, workflowLog, "entry %d: the campaign.locked event has the digest %s and the manifest has the lock digest %s",
					lock.seq, short(lock.digest), short(m.lockDigest))
			}
			missing, surplus := compareSources(m, lock.sources, func(s campaignSource) string {
				return fmt.Sprintf("%q|%d|%q|%q", s.connection, s.seq, s.digest, s.chain)
			}, func(c manifestCollection) string {
				return fmt.Sprintf("%q|%d|%q|%q", c.connection, c.seq, c.digest, c.chain)
			})
			if len(missing) > 0 || surplus > 0 {
				v.addf(ReasonLocked, workflowLog, "entry %d: the campaign.locked event does not name the collections the manifest names%s",
					lock.seq, describeSources(missing, surplus))
			}
		}
	}
	for _, c := range m.collections {
		found := false
		for _, e := range w.completed[completionKey(c.connection, c.seq)] {
			if e.digest == c.digest && e.chain == c.chain && (lock == nil || e.seq < lock.seq) {
				found = true
			}
		}
		if !found {
			v.addf(ReasonCompleted, workflowLog, "holds no collection.completed event for %s, entry %d with the digest and chain value the manifest names%s",
				quote(c.connection), c.seq, beforeLock(lock))
		}
	}
}

func beforeLock(l *lockEvent) string {
	if l == nil {
		return ""
	}
	return fmt.Sprintf(", before the lock at entry %d", l.seq)
}

// same says whether a size or a position that was counted is the number a
// document gives.
func same(counted int64, given uint64) bool {
	return counted >= 0 && uint64(counted) == given
}
