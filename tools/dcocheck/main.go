// Command dcocheck fails if a commit in a range is not signed off by its
// author under the Developer Certificate of Origin.
//
// Usage:
//
//	dcocheck -range base..head
//
// A commit passes when git reads a "Signed-off-by: Name <email>" trailer in it
// whose email is the author's. Merge commits are not checked, and neither are
// bot authors. This guards against forgetting, not against lying: a sign-off
// is the contributor's own statement, so it is not made harder to fake.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type commit struct {
	sha, email, subject string
	signers             []string // the values of its Signed-off-by trailers
}

const botSuffix = "[bot]@users.noreply.github.com"

// emailOf is the address in "Name <email>", or "" if there is none.
func emailOf(value string) string {
	i := strings.LastIndex(value, "<")
	if i < 0 {
		return ""
	}
	addr, _, ok := strings.Cut(value[i+1:], ">")
	if !ok {
		return ""
	}
	return strings.TrimSpace(addr)
}

func signedOff(c commit) bool {
	if strings.HasSuffix(strings.ToLower(c.email), botSuffix) {
		return true
	}
	if c.email == "" {
		return false
	}
	for _, s := range c.signers {
		if strings.EqualFold(emailOf(s), c.email) {
			return true
		}
	}
	return false
}

// format asks git for each commit's trailers itself, so what counts as a
// trailer is git's reading and not ours. Fields are separated by NUL, which a
// commit message cannot contain, and records by NUL too (with -z); a record that
// does not have all four fields is an error and not a commit that is skipped.
const format = "--format=%H%x00%ae%x00%s%x00%(trailers:key=Signed-off-by,valueonly,separator=%x1f)"

const fieldsPerCommit = 4

func parseLog(log string) ([]commit, error) {
	fields := strings.Split(log, "\x00")
	// Every record ends in a NUL, so there is one empty field after the last.
	if fields[len(fields)-1] != "" || (len(fields)-1)%fieldsPerCommit != 0 {
		return nil, fmt.Errorf("git log gave %d fields, not a whole number of commits", len(fields)-1)
	}
	fields = fields[:len(fields)-1]
	var out []commit
	for i := 0; i < len(fields); i += fieldsPerCommit {
		c := commit{sha: fields[i], email: fields[i+1], subject: fields[i+2]}
		for _, v := range strings.Split(fields[i+3], "\x1f") {
			if v = strings.TrimSpace(v); v != "" {
				c.signers = append(c.signers, v)
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func commits(dir, rng string) ([]commit, error) {
	out, err := exec.CommandContext(context.Background(), "git", "-C", dir, //nolint:gosec // the range is the caller's own
		"log", "--no-merges", "-z", "--encoding=UTF-8", "--no-show-signature", format, rng).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, err
	}
	return parseLog(string(out))
}

// hint says what to do about a commit whose subject is its own sign-off: git
// reads that as the subject and not a trailer, and `git rebase --signoff`
// would leave it as it is.
func hint(c commit) string {
	if strings.HasPrefix(strings.ToLower(c.subject), "signed-off-by:") {
		return "the sign-off is this commit's subject; give it a subject line above the sign-off"
	}
	return ""
}

func main() {
	rng := flag.String("range", "", "commit range to check, as base..head")
	flag.Parse()
	if *rng == "" {
		fmt.Fprintln(os.Stderr, "dcocheck: -range is required")
		os.Exit(2)
	}
	cs, err := commits(".", *rng)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dcocheck: git log %s: %v\n", *rng, err)
		os.Exit(2)
	}
	bad := 0
	for _, c := range cs {
		if signedOff(c) {
			continue
		}
		fmt.Printf("%s %s: no Signed-off-by from %s\n", c.sha[:min(len(c.sha), 12)], c.subject, c.email)
		if h := hint(c); h != "" {
			fmt.Println("  " + h)
		}
		bad++
	}
	if bad > 0 {
		fmt.Println("dcocheck: sign off with `git commit -s`; for a pull request already open:\n" +
			"  git rebase --signoff origin/main && git push --force-with-lease\n" +
			"(see CONTRIBUTING.md)")
		os.Exit(1)
	}
	fmt.Println("dcocheck: ok")
}
