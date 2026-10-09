package pack

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"go.acciew.io/collector/verify/internal/jsonobj"
	"go.acciew.io/collector/verify/internal/text"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// manifest is what the verifier reads of manifest.json.
type manifest struct {
	campaignID  string
	lockDigest  string
	files       []manifestFile
	collections []manifestCollection
	workflow    struct {
		seq   uint64
		chain string
	}
}

type manifestFile struct {
	path   string
	sha256 string
	bytes  uint64
}

type manifestCollection struct {
	connection, plugin string
	seq                uint64
	digest, chain      string
	snapshot           string
	headSeq            uint64
	headChain          string
}

// topLevel are the members of a manifest. Those marked false are about the
// review and are not read here.
var topLevel = map[string]bool{
	"version": true, "generated_at": false, "campaign": true, "completeness": false, "finalization": false,
	"document": false, "files": true, "collections": true, "heads": true, "attestations": false,
}

// issue is one way a document is not in a shape this verifier reads. An unknown
// one is a member the verifier does not know, which a later revision of the format
// may have added: it is not a disagreement.
type issue struct {
	unknown bool
	msg     string
}

// issues collects them: add for a shape that is wrong, unknown for a member that
// is not known.
type issues struct{ list []issue }

func (p *issues) add(format string, args ...any) {
	p.list = append(p.list, issue{msg: fmt.Sprintf(format, args...)})
}

func (p *issues) unknown(where, name string) {
	p.list = append(p.list, issue{unknown: true, msg: fmt.Sprintf("%s holds a member %s that this verifier does not know: the file may be newer than this verifier", where, quote(name))})
}

// parseManifest reads manifest.json. A version that is not 1, and a document
// that is not JSON or not an object, are errors: the pack cannot be checked. A
// manifest in a shape this verifier does not know is returned as problems, each
// worded to be a finding.
func parseManifest(raw []byte) (*manifest, []issue, error) {
	members, err := jsonobj.Members(raw)
	if err != nil {
		return nil, nil, notReadable(err, "manifest.json %v", err)
	}
	// The version is read first, before anything else is judged, so that a
	// manifest from a newer format is said to be that and never to be altered.
	if v, ok := members["version"]; !ok || string(v) != "1" {
		return nil, nil, formatError(members["version"])
	}
	m := &manifest{}
	var ps issues
	problem := ps.add

	for _, name := range sortedNames(members) {
		if _, known := topLevel[name]; !known {
			ps.unknown("the manifest", name)
		}
	}
	require := func(name string) json.RawMessage {
		raw, ok := members[name]
		if !ok {
			problem("has no %s", name)
		}
		return raw
	}

	if raw := require("campaign"); raw != nil {
		c, err := jsonobj.Members(raw)
		if err != nil {
			problem("campaign %v", err)
		} else {
			m.campaignID = stringMember(c, "campaign", "id", problem)
			m.lockDigest = stringMember(c, "campaign", "lock_digest", problem)
			for _, name := range sortedNames(c) {
				switch name {
				case "id", "name", "lock_digest", "locked_at", "items":
				default:
					ps.unknown("campaign", name)
				}
			}
		}
	}

	if raw := require("files"); raw != nil {
		items, err := jsonobj.Array(raw)
		if err != nil {
			problem("files %v", err)
		}
		for i, item := range items {
			f, err := jsonobj.Members(item)
			if err != nil {
				problem("file %d %v", i+1, err)
				continue
			}
			where := fmt.Sprintf("file %d", i+1)
			var mf manifestFile
			mf.path = stringMember(f, where, "path", problem)
			mf.sha256 = stringMember(f, where, "sha256", problem)
			mf.bytes = uintMember(f, where, "bytes", problem)
			if mf.sha256 != "" && !hex64.MatchString(mf.sha256) {
				problem("%s has a sha256 that is not 64 lowercase hexadecimal characters", where)
			}
			onlyMembers(f, where, &ps, "path", "sha256", "bytes")
			m.files = append(m.files, mf)
		}
		if err == nil && len(items) == 0 {
			problem("lists no files")
		}
	}

	if raw := require("collections"); raw != nil {
		items, err := jsonobj.Array(raw)
		if err != nil {
			problem("collections %v", err)
		}
		for i, item := range items {
			c, err := jsonobj.Members(item)
			if err != nil {
				problem("collection %d %v", i+1, err)
				continue
			}
			where := fmt.Sprintf("collection %d", i+1)
			mc := manifestCollection{
				connection: stringMember(c, where, "connection", problem),
				plugin:     stringMember(c, where, "plugin", problem),
				seq:        uintMember(c, where, "seq", problem),
				digest:     stringMember(c, where, "digest", problem),
				chain:      stringMember(c, where, "chain_value", problem),
				snapshot:   stringMember(c, where, "snapshot", problem),
				headSeq:    uintMember(c, where, "head_seq", problem),
				headChain:  stringMember(c, where, "head_chain_value", problem),
			}
			onlyMembers(c, where, &ps, "connection", "plugin", "seq", "digest", "chain_value", "snapshot", "head_seq", "head_chain_value")
			for _, part := range []struct{ name, v string }{{"connection", mc.connection}, {"plugin", mc.plugin}} {
				if part.v != "" && !plainPart(part.v) {
					problem("%s has a %s that is not a plain name, and names a file", where, part.name)
				}
			}
			m.collections = append(m.collections, mc)
		}
		if err == nil && len(items) == 0 {
			problem("lists no collections")
		}
	}

	if raw := require("heads"); raw != nil {
		h, err := jsonobj.Members(raw)
		if err != nil {
			problem("heads %v", err)
		} else {
			onlyMembers(h, "heads", &ps, "workflow")
			if wraw, ok := h["workflow"]; !ok {
				problem("heads has no workflow")
			} else if w, err := jsonobj.Members(wraw); err != nil {
				problem("the workflow head %v", err)
			} else {
				m.workflow.seq = uintMember(w, "the workflow head", "seq", problem)
				m.workflow.chain = stringMember(w, "the workflow head", "chain_value", problem)
				onlyMembers(w, "the workflow head", &ps, "seq", "chain_value")
			}
		}
	}
	return m, ps.list, nil
}

func formatError(version json.RawMessage) *Error {
	what := "does not say which version it is"
	if version != nil {
		what = "says version " + quote(string(version))
		if len(version) > 24 {
			what = "says a version that is not one"
		}
	}
	return &Error{Reason: ReasonFormat, msg: "manifest.json " + what + ", which is not a format this verifier knows (it reads version 1): " +
		"a newer verifier may read it, and this one cannot say whether the pack holds together"}
}

func stringMember(m map[string]json.RawMessage, where, name string, problem func(string, ...any)) string {
	raw, ok := m[name]
	if !ok {
		problem("%s has no %s", where, name)
		return ""
	}
	s, err := jsonobj.String(raw)
	if err != nil || s == "" {
		problem("%s has a %s that is not a non-empty string", where, name)
		return ""
	}
	return s
}

func uintMember(m map[string]json.RawMessage, where, name string, problem func(string, ...any)) uint64 {
	raw, ok := m[name]
	if !ok {
		problem("%s has no %s", where, name)
		return 0
	}
	n, err := jsonobj.Uint64(raw)
	if err != nil {
		problem("%s has a %s that %v", where, name, err)
		return 0
	}
	return n
}

// onlyMembers adds an unknown-member problem for each member that is not one of
// those listed.
func onlyMembers(m map[string]json.RawMessage, where string, ps *issues, known ...string) {
	for _, name := range sortedNames(m) {
		var ok bool
		for _, k := range known {
			ok = ok || k == name
		}
		if !ok {
			ps.unknown(where, name)
		}
	}
}

func sortedNames(m map[string]json.RawMessage) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func quote(s string) string { return text.Quote(s) }

// expectedList is manifest.sha256 as the manifest gives it: a line for each file
// the manifest lists, in its order, and then the manifest itself.
func expectedList(files []manifestFile, manifestSum string) string {
	var b strings.Builder
	for _, f := range files {
		fmt.Fprintf(&b, "%s  %s\n", f.sha256, f.path)
	}
	fmt.Fprintf(&b, "%s  manifest.json\n", manifestSum)
	return b.String()
}

// campaignFile is what the verifier reads of campaign.json.
type campaignFile struct {
	id, lockDigest string
	sources        []campaignSource
}

type campaignSource struct {
	connection, plugin string
	seq                uint64
	digest, chain      string
}

// parseCampaign reads campaign.json: the review's own facts, of which the
// verifier reads the id, the lock digest and the collections it was locked from.
// Another member is allowed and not read.
func parseCampaign(raw []byte) (*campaignFile, []issue) {
	var ps issues
	problem := ps.add
	members, err := jsonobj.Members(raw)
	if err != nil {
		return nil, []issue{{msg: "is not a JSON object that can be read: " + err.Error()}}
	}
	c := &campaignFile{
		id:         stringMember(members, "the campaign", "id", problem),
		lockDigest: stringMember(members, "the campaign", "lock_digest", problem),
	}
	sraw, ok := members["sources"]
	if !ok {
		problem("the campaign has no sources")
		return c, ps.list
	}
	items, err := jsonobj.Array(sraw)
	if err != nil {
		problem("sources %v", err)
	}
	for i, item := range items {
		s, err := jsonobj.Members(item)
		if err != nil {
			problem("source %d %v", i+1, err)
			continue
		}
		where := fmt.Sprintf("source %d", i+1)
		c.sources = append(c.sources, campaignSource{
			connection: stringMember(s, where, "connection", problem),
			plugin:     stringMember(s, where, "plugin", problem),
			seq:        uintMember(s, where, "seq", problem),
			digest:     stringMember(s, where, "digest", problem),
			chain:      stringMember(s, where, "chain_value", problem),
		})
		if raw, ok := s["name"]; !ok {
			problem("%s has no name", where)
		} else if _, err := jsonobj.String(raw); err != nil {
			problem("%s has a name that is not a string", where)
		}
		onlyMembers(s, where, &ps, "connection", "name", "plugin", "seq", "digest", "chain_value")
	}
	return c, ps.list
}
