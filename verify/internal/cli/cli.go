// Package cli is the acciew-verify command: its arguments, what it prints and the
// status it exits with.
//
// Everything it prints that came from outside (a file name, a path, a message
// built from a file) is made safe for a terminal first.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"go.acciew.io/collector/verify/collection"
	"go.acciew.io/collector/verify/internal/text"
	"go.acciew.io/collector/verify/pack"
	"go.acciew.io/collector/verify/workflow"
)

// The words the command says about what a pass shows, and does not. The README
// holds the same ones; a test fails if the two differ.
const (
	// PackShows is what a pass of a pack shows.
	PackShows = "What a pass shows: the files are the ones this manifest names; each collection log and the workflow log is " +
		"hash-chained and checkable against itself and its anchor; and the manifest, campaign.json and the workflow log name " +
		"the same collections and the same lock, and each log ends where the manifest says it does."

	// PackDoesNotShow is what a pass of a pack does not.
	PackDoesNotShow = "What it does not show: that Acciew made the pack. Nothing inside a pack ties its manifest to anything " +
		"outside it, so files, logs, anchors and manifest rewritten together pass. To know that this is the manifest Acciew " +
		"made, compare the manifest digest this check prints with the pack.built record Acciew keeps for it, obtained from " +
		"Acciew directly and not from whoever handed over the pack; that record is itself on a log Acciew holds, so it shows " +
		"what Acciew says it handed out, and nothing more. Nothing is signed. It does not show that a collection was complete " +
		"or true, when anything was made, or who is behind an actor id or a typed name; that a stored collection in " +
		"snapshots/ is the one its log entry records, since it is tied to the manifest's digest of the file and no further; " +
		"or that the register, the report or the document say what document.json says."

	// LogShows is what a pass of a log shows and does not.
	LogShows = "What a pass shows: each log is hash-chained and checkable against itself and its anchor: every entry holds the " +
		"digest of its content, every link names the entry before it, and the last entry is the one the anchor names. It does " +
		"not show who wrote a log or when, that what it records is true, or that whoever holds both a log and its anchor did " +
		"not rewrite both."

	// Disagreement is said when something does not verify.
	Disagreement = "A check that fails says the files disagree with each other. It does not say who changed anything, or when."
)

const usage = `usage: acciew-verify <command> [arguments]

commands:
  pack <folder|archive.zip>          check an evidence pack, in place
  history <folder> [--source NAME]   check collection logs (NAME.jsonl and NAME.head)
  workflow <folder> [--name NAME]    check a workflow log (NAME.jsonl and NAME.head)
  version                            print the version

options:
  --max-bytes N        pack: let the pack, and each file in it, expand to N bytes
  --max-line-bytes N   take lines of a log up to N bytes (default 64 MiB)

exit status: 0 verified, 1 did not verify, 2 could not be checked (unreadable, a
format this verifier does not know, a member of a file that it does not know, a bound
exceeded, or a mistake in the command).
-h or help print this and exit 0.
`

// maxBytesOption is the largest --max-bytes: a petabyte is more than any pack, and a
// number near the largest the language holds would overflow what is added to it.
const maxBytesOption = 1 << 50

// Exit statuses.
const (
	exitVerified = 0
	exitFailed   = 1
	exitUnable   = 2
)

// Run runs the command and returns the status to exit with.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUnable
	}
	rest := args[1:]
	switch args[0] {
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "acciew-verify %s\n", version)
		return exitVerified
	case "help", "-h", "--help", "-help":
		fmt.Fprint(stdout, usage)
		return exitVerified
	case "pack":
		return runPack(rest, stdout, stderr)
	case "history":
		return runLogs(rest, stdout, stderr, collections)
	case "workflow":
		return runLogs(rest, stdout, stderr, workflows)
	}
	fmt.Fprintf(stderr, "acciew-verify: unknown command %s\n\n%s", text.Quote(args[0]), usage)
	return exitUnable
}

// newFlags makes the options of a command. The flag package says nothing of its own:
// what it would say goes through text.Show, and its usage is the command's.
func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parse reads the options of a command, which may come before or after what it
// is about, and returns what is left. A mistake in them is said on stderr, and -h
// prints the usage on stdout; the second result is the status to exit with when the
// command is not to go on.
func parse(fs *flag.FlagSet, args []string, stdout, stderr io.Writer) (places []string, status int, done bool) {
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(stdout, usage)
				return nil, exitVerified, true
			}
			fmt.Fprintf(stderr, "acciew-verify: %s\n\n%s", text.Show(err.Error()), usage)
			return nil, exitUnable, true
		}
		if fs.NArg() == 0 {
			return places, 0, false
		}
		places = append(places, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func count(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// ---- pack

func runPack(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("pack")
	maxBytes := fs.Int64("max-bytes", 0, "")
	maxLine := fs.Int("max-line-bytes", 0, "")
	places, status, done := parse(fs, args, stdout, stderr)
	if done {
		return status
	}
	if len(places) != 1 {
		fmt.Fprintf(stderr, "acciew-verify: pack needs one folder or archive to check\n\n%s", usage)
		return exitUnable
	}
	if *maxBytes < 0 || *maxLine < 0 {
		fmt.Fprintf(stderr, "acciew-verify: --max-bytes and --max-line-bytes are numbers of bytes and are not negative\n")
		return exitUnable
	}
	if *maxBytes > maxBytesOption {
		fmt.Fprintf(stderr, "acciew-verify: --max-bytes is at most %d (%s)\n", int64(maxBytesOption), size(maxBytesOption))
		return exitUnable
	}
	opts := pack.Options{Limits: pack.Limits{MaxLineBytes: *maxLine}}
	if *maxBytes > 0 {
		opts.Limits.MaxTotalBytes, opts.Limits.MaxFileBytes = *maxBytes, *maxBytes
	}

	place := places[0]
	info, err := os.Stat(place)
	if err != nil {
		fmt.Fprintf(stderr, "acciew-verify: %s cannot be opened: %s\n", text.Show(place), text.Plain(err))
		return exitUnable
	}
	var rep *pack.Report
	switch {
	case info.IsDir():
		rep, err = pack.VerifyDir(place, opts)
	case info.Mode().IsRegular():
		var f *os.File
		if f, err = os.Open(place); err != nil { //nolint:gosec // the command's own argument, opened to read
			fmt.Fprintf(stderr, "acciew-verify: %s cannot be opened: %s\n", text.Show(place), text.Plain(err))
			return exitUnable
		}
		defer f.Close()
		rep, err = pack.VerifyZip(f, info.Size(), opts)
	default:
		fmt.Fprintf(stderr, "acciew-verify: %s is neither a folder nor an archive\n", text.Show(place))
		return exitUnable
	}
	if err != nil {
		fmt.Fprintf(stderr, "acciew-verify: %v\n", err)
		if pack.ReasonOf(err) == pack.ReasonLimit {
			fmt.Fprintln(stderr, "  The pack was not checked. If it is meant to be this large, raise the bound with --max-bytes.")
			first, second := bounds(opts.Limits.Resolved())
			fmt.Fprintf(stderr, "  bounds in force: %s; %s\n", first, second)
		} else {
			fmt.Fprintln(stderr, "  The pack was not checked.")
		}
		return exitUnable
	}
	return printPack(stdout, place, rep, opts.Limits.Resolved())
}

// unable says whether a reason is one for which nothing is said of the files: it
// was not found that they disagree, only that they could not be checked, or that
// the verifier is older than they are.
func unable(reason string) bool {
	switch reason {
	case pack.ReasonUnreadable, pack.ReasonFormat, pack.ReasonLimit, pack.ReasonUnknownMember:
		return true
	}
	return false
}

func printPack(w io.Writer, place string, rep *pack.Report, lim pack.Limits) int {
	row := func(label, format string, args ...any) {
		fmt.Fprintf(w, "  %-30s %s\n", label, fmt.Sprintf(format, args...))
	}
	fmt.Fprintf(w, "pack %s\n\n", text.Show(place))
	row("manifest.json", "SHA-256 %s", rep.ManifestSHA256)
	row("listed files", "%s match the manifest", count(rep.Files, "file"))
	for _, c := range rep.Collections {
		row(text.Show(c.Path), "%s, consistent with its own chain", count(c.Entries, "collection"))
	}
	if rep.Workflow.Path != "" {
		row(text.Show(rep.Workflow.Path), "%s, consistent with its own chain", count(rep.Workflow.Entries, "event"))
	}
	if rep.Verified() {
		row("one against another", "the manifest, campaign.json and the workflow log agree; each log ends where the manifest says")
	}
	first, second := bounds(lim)
	row("bounds in force", "%s", first)
	row("", "%s", second)
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "  note  %s\n", n)
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(w, "! %s\n", f)
	}
	if rep.More > 0 {
		fmt.Fprintf(w, "! and %s more, not shown\n", count(rep.More, "finding"))
	}
	fmt.Fprintln(w)
	if rep.Verified() {
		fmt.Fprintf(w, "%s\n\n%s\n", wrap(PackShows), wrap(PackDoesNotShow))
		return exitVerified
	}
	// A pack whose only findings are that something could not be read, is in a
	// format this verifier does not know, or goes past a bound, was not found to
	// disagree with itself: it was not fully checked.
	disagrees := false
	for _, f := range rep.Findings {
		if !unable(f.Reason) {
			disagrees = true
		}
	}
	status := exitUnable
	if disagrees {
		fmt.Fprintf(w, "%s. The pack does not verify.\n\n%s\n", count(len(rep.Findings)+rep.More, "finding"), wrap(Disagreement))
		status = exitFailed
	} else {
		fmt.Fprintf(w, "%s could not be checked. The pack is not verified, and nothing is said of whether its files agree.\n",
			count(len(rep.Findings)+rep.More, "thing"))
	}
	if hasReason(rep, pack.ReasonLimit) {
		fmt.Fprintln(w, "If a log is meant to have lines this long, raise the bound with --max-line-bytes.")
	}
	return status
}

// bounds says the bounds in force, in two parts.
func bounds(lim pack.Limits) (first, second string) {
	first = fmt.Sprintf("%d files and folders; %s a file; %s in all; %d times its size for an archive entry past 1 MiB",
		lim.MaxEntries, size(lim.MaxFileBytes), size(lim.MaxTotalBytes), lim.MaxRatio)
	second = fmt.Sprintf("%s a line of a log; %s each for manifest.json, manifest.sha256 and campaign.json",
		size(int64(lim.MaxLineBytes)), size(pack.MaxDocumentBytes))
	return first, second
}

func hasReason(rep *pack.Report, reason string) bool {
	for _, f := range rep.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

// size renders a number of bytes: in GiB, MiB or KiB when it is a whole number of them.
func size(n int64) string {
	switch {
	case n >= 1<<50 && n%(1<<50) == 0:
		return fmt.Sprintf("%d PiB", n>>50)
	case n >= 1<<40 && n%(1<<40) == 0:
		return fmt.Sprintf("%d TiB", n>>40)
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GiB", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

// wrap breaks a paragraph into lines of about 100 characters.
func wrap(s string) string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line != "" && len(line)+1+len(word) > 98 {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// ---- logs

// logKind is what differs between the commands that check a folder of logs.
type logKind struct {
	command string // the command, and what is said when there are none
	option  string // the option that names one log
	unit    string // what an entry is called
	check   func(dir, name string, limits int) (entries int, reason string, err error)
}

var collections = logKind{command: "history", option: "source", unit: "collection",
	check: func(dir, name string, maxLine int) (int, string, error) {
		sum, err := collection.VerifyDir(dir, name, collection.Limits{MaxLineBytes: maxLine})
		return sum.Entries, collection.ReasonOf(err), err
	}}

var workflows = logKind{command: "workflow", option: "name", unit: "event",
	check: func(dir, name string, maxLine int) (int, string, error) {
		sum, err := workflow.VerifyDir(dir, name, workflow.Limits{MaxLineBytes: maxLine})
		return sum.Entries, workflow.ReasonOf(err), err
	}}

func runLogs(args []string, stdout, stderr io.Writer, kind logKind) int {
	fs := newFlags(kind.command)
	one := fs.String(kind.option, "", "")
	maxLine := fs.Int("max-line-bytes", 0, "")
	places, status, done := parse(fs, args, stdout, stderr)
	if done {
		return status
	}
	if len(places) != 1 || *maxLine < 0 {
		fmt.Fprintf(stderr, "acciew-verify: %s needs one folder to check, and --max-line-bytes is not negative\n\n%s", kind.command, usage)
		return exitUnable
	}
	dir := places[0]

	var err error
	names := []string{*one}
	if *one == "" {
		if names, err = discover(dir); err != nil {
			fmt.Fprintf(stderr, "acciew-verify: %s cannot be read: %s\n", text.Show(dir), text.Plain(err))
			return exitUnable
		}
		if len(names) == 0 {
			fmt.Fprintf(stderr, "acciew-verify: no %s logs in %s (a log is NAME.jsonl with NAME.head beside it)\n", kind.command, text.Show(dir))
			return exitUnable
		}
	}

	var failed, unabled int
	var limited bool
	for _, name := range names {
		entries, reason, err := kind.check(dir, name, *maxLine)
		switch {
		case err == nil:
			fmt.Fprintf(stdout, "  %-16s %s, consistent with its own chain\n", text.Show(name), count(entries, kind.unit))
		case unable(reason) || reason == string(collection.ReasonName):
			unabled++
			limited = limited || reason == string(collection.ReasonLimit)
			fmt.Fprintf(stdout, "! %-16s %s\n", text.Show(name), message(name, err))
		default:
			failed++
			fmt.Fprintf(stdout, "! %-16s %s\n", text.Show(name), message(name, err))
		}
	}
	lineBound := *maxLine
	if lineBound == 0 {
		lineBound = collection.DefaultMaxLineBytes
	}
	fmt.Fprintf(stdout, "\nbound in force: %s a line (--max-line-bytes)\n\n", size(int64(lineBound)))
	switch {
	case failed > 0:
		fmt.Fprintln(stdout, wrap(Disagreement))
		return exitFailed
	case unabled > 0:
		fmt.Fprintf(stdout, "%s could not be checked. Nothing is said of it.\n", count(unabled, "log"))
		if limited {
			fmt.Fprintln(stdout, "If a log is meant to have lines this long, raise the bound with --max-line-bytes.")
		}
		return exitUnable
	}
	fmt.Fprintln(stdout, wrap(LogShows))
	return exitVerified
}

// message is what a check says of a log without the name it is listed under, which
// the line it is on already gives: the checks begin what they find with the name of
// the file, or of the log, it was found in.
func message(name string, err error) string {
	msg := err.Error()
	for _, prefix := range []string{name + ".jsonl", name + ".head", name} {
		if rest, ok := strings.CutPrefix(msg, text.Show(prefix)+": "); ok {
			return rest
		}
	}
	return msg
}

// discover names the logs in a folder: every NAME of a NAME.jsonl or a NAME.head, so
// that a log with its anchor gone, or an anchor with its log gone, is said and not
// left out. What begins with a dot is what file managers leave beside a copy.
func discover(dir string) ([]string, error) {
	found, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var names []string
	for _, f := range found {
		base := strings.TrimSuffix(strings.TrimSuffix(f.Name(), ".jsonl"), ".head")
		if f.IsDir() || strings.HasPrefix(f.Name(), ".") || base == f.Name() || seen[base] {
			continue
		}
		seen[base] = true
		names = append(names, base)
	}
	sort.Strings(names)
	return names, nil
}
