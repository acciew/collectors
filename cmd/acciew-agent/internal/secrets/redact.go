package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Redactor finds the secrets this host resolved in anything that is about to leave it, and
// removes them from text. It looks for each value as it is and in the forms a collector, or a
// library under one, might write it in: quoted for JSON or Go, in base64 (both alphabets, with
// and without padding, and inside longer data at any of the three alignments), in hex, and
// escaped for a URL. It also looks for the parts of a value that unlock it on their own: each
// long line of a multi-line value; the password of a URL or a connection string; the signature
// and payload of a token; each string of a JSON credential under a field named like a secret;
// and the first and last 16 bytes of a long plain value.
//
// Everything it is given is looked for, or Add refuses it: nothing is dropped to make room. The
// patterns are indexed by their first 8 bytes, so what an event costs does not depend on how many
// there are.
//
// What it does not find: a part from the middle of a value, a value with its case changed (hex
// is looked for in both cases, not mixed), a value split over more than a short stretch of
// text, or one run through any transformation not listed here.
type Redactor struct {
	entries []entry          // the patterns of 8 bytes or more, which events are searched for
	index   map[uint64][]int // the first 8 bytes of a pattern to the patterns that start so
	bloom   []uint64         // a bit for each hashed first 8 bytes, so most positions cost no lookup
	seen    map[string]bool
	short   []shortEntry // 4 to 7 bytes: scrubbed from text, never searched for in events
	sources []string
	maxLen  int
	dir     string

	// MaxPatterns is the most patterns that are watched for; zero is the package's MaxPatterns.
	MaxPatterns int
}

type entry struct {
	text   string
	source int
	part   string
	form   string
}

type shortEntry struct {
	text   string
	source int
}

// Hit is what was found: which reference it came from, and how it was written.
type Hit struct {
	// Source is the reference the credential came from, as the job spelled it (env:NAME, file:/path).
	Source string
	// Part is the piece of the credential, when it is not the whole of it ("a line of it").
	Part string
	// Form is how it was written ("as it is", "base64").
	Form string
}

// Describe says what was found without saying what it is.
func (h Hit) Describe() string {
	var how []string
	for _, x := range []string{h.Part, h.Form} {
		if x != "" {
			how = append(how, x)
		}
	}
	if len(how) == 0 {
		return h.Source
	}
	return h.Source + " (" + strings.Join(how, ", ") + ")"
}

const (
	// minRedact is the shortest value worth scrubbing: replacing every "ab" in a message makes it
	// unreadable and protects nothing.
	minRedact = 4
	// MinEnforced is the shortest value an event is refused for holding. A shorter one is found
	// by chance in ordinary data, and refusing every event with "pass" in it would refuse all of them.
	MinEnforced = 8
	// minFragment is the shortest piece of a value's base64 that is looked for inside other data.
	// The characters at either end of the encoding of a longer text depend on what is beside the
	// value, so only the middle is certain; a fragment of 8 characters is 48 bits, and is what an
	// 8-byte value leaves at any of the three alignments.
	minFragment = 8
	// minLine and minField are the shortest line of a multi-line value, and string of a JSON one,
	// looked for by themselves.
	minLine  = 16
	minField = 16
	// minSegment is the shortest segment of a token looked for by itself.
	minSegment = 32
	// partLen is the length of the head and the tail looked for in a long plain value.
	partLen = 16
	// minForParts is the shortest plain value whose head and tail are looked for by themselves.
	minForParts = 24
	// minEntropy is the fewest bits per byte of a JSON string that is taken for a secret on its own.
	minEntropy = 3.0
	// MaxPatterns is the most patterns one run's credentials may come to. The references are capped at
	// 32 and 4 MiB between them; a bundle of sixty certificates is about 25,000 patterns. A job whose
	// credentials come to more is refused.
	MaxPatterns = 200_000
	// maxTail is the most text kept of one field from one event to join to the next. A value
	// printed in two pieces is found when the first is no longer than this.
	maxTail   = 64 << 10
	bloomBits = 22
)

// ErrTooLarge is a credential that comes to more patterns than can be watched for.
var ErrTooLarge = errors.New("too large to be watched for")

// Add makes a value one to look for, when it is long enough to be one. source is how a hit is
// named: the reference it came from.
func (r *Redactor) Add(source, value string) error { return r.add([]byte(value), source) }

// AddURLCredentials makes the password of an address that carries one (a proxy of the form
// http://user:password@host, or user:password@host) one to look for. An address with none is a
// setting, which a collector may say it uses.
func (r *Redactor) AddURLCredentials(source, value string) error {
	pws, token := loginsOf(value)
	for _, pw := range pws {
		if err := r.add([]byte(pw), source); err != nil {
			return err
		}
	}
	if token != "" {
		return r.add([]byte(token), source)
	}
	return nil
}

func (r *Redactor) sourceID(source string) int {
	if i := slices.Index(r.sources, source); i >= 0 {
		return i
	}
	r.sources = append(r.sources, source)
	return len(r.sources) - 1
}

func (r *Redactor) add(value []byte, source string) error {
	src := r.sourceID(source)
	for _, v := range []string{string(value), strings.TrimSpace(string(value))} {
		if len(v) < minRedact {
			continue
		}
		parts, scrubOnly := partsOf(v)
		for _, s := range scrubOnly {
			r.scrubOnly(s, src)
		}
		if len(v) < MinEnforced {
			r.scrubOnly(v, src)
		}
		for _, part := range parts {
			for _, f := range formsOf(part.text) {
				if err := r.pattern(f.text, src, part.kind, f.name); err != nil {
					return fmt.Errorf("%s is %w (more than %d patterns)", source, ErrTooLarge, r.limit())
				}
			}
		}
	}
	return nil
}

func (r *Redactor) scrubOnly(text string, src int) {
	if len(text) < minRedact || len(text) >= MinEnforced {
		return
	}
	for _, e := range r.short {
		if e.text == text {
			return
		}
	}
	r.short = append(r.short, shortEntry{text, src})
}

var errFull = errors.New("full")

func (r *Redactor) limit() int {
	if r.MaxPatterns > 0 {
		return r.MaxPatterns
	}
	return MaxPatterns
}

// Patterns is how many patterns are watched for.
func (r *Redactor) Patterns() int { return len(r.entries) }

func (r *Redactor) pattern(text string, src int, part, form string) error {
	if r.seen[text] {
		return nil
	}
	if len(r.entries) >= r.limit() {
		return errFull
	}
	if r.seen == nil {
		r.seen = map[string]bool{}
		r.index = map[uint64][]int{}
		r.bloom = make([]uint64, 1<<(bloomBits-6))
	}
	r.seen[text] = true
	r.entries = append(r.entries, entry{text, src, part, form})
	key := binary.LittleEndian.Uint64([]byte(text[:8]))
	r.index[key] = append(r.index[key], len(r.entries)-1)
	h := hashKey(key)
	r.bloom[h>>6] |= 1 << (h & 63)
	r.maxLen = max(r.maxLen, len(text))
	return nil
}

func hashKey(k uint64) uint64 { return (k * 0x9E3779B97F4A7C15) >> (64 - bloomBits) }

// scan calls yield with each pattern found in b, until it returns false.
func (r *Redactor) scan(b []byte, yield func(start int, e *entry) bool) {
	if r == nil || len(r.entries) == 0 {
		return
	}
	for i := 0; i+8 <= len(b); i++ {
		k := binary.LittleEndian.Uint64(b[i:])
		h := hashKey(k)
		if r.bloom[h>>6]&(1<<(h&63)) == 0 {
			continue
		}
		for _, ix := range r.index[k] {
			e := &r.entries[ix]
			if len(b)-i >= len(e.text) && string(b[i:i+len(e.text)]) == e.text {
				if !yield(i, e) {
					return
				}
			}
		}
	}
}

// Find says an event, as it will be sent, holds a resolved value in any of the forms, and which.
func (r *Redactor) Find(event []byte) (Hit, bool) {
	var hit Hit
	var found bool
	r.scan(event, func(_ int, e *entry) bool {
		hit, found = Hit{Source: r.sources[e.source], Part: e.part, Form: e.form}, true
		return false
	})
	return hit, found
}

// Leaks is Find without the answer to which.
func (r *Redactor) Leaks(event []byte) bool {
	_, ok := r.Find(event)
	return ok
}

// Scrub replaces every resolved value, in every form, with [redacted] and the run's directory
// with <run>.
func (r *Redactor) Scrub(s string) string {
	if r == nil {
		return s
	}
	type span struct{ from, to int }
	var spans []span
	b := []byte(s)
	r.scan(b, func(start int, e *entry) bool {
		spans = append(spans, span{start, start + len(e.text)})
		return true
	})
	for _, e := range r.short {
		for from := 0; ; {
			i := strings.Index(s[from:], e.text)
			if i < 0 {
				break
			}
			spans = append(spans, span{from + i, from + i + len(e.text)})
			from += i + len(e.text)
		}
	}
	if len(spans) > 0 {
		sort.Slice(spans, func(i, j int) bool { return spans[i].from < spans[j].from })
		var out strings.Builder
		at := 0
		for i := 0; i < len(spans); {
			from, to := spans[i].from, spans[i].to
			for i++; i < len(spans) && spans[i].from <= to; i++ {
				to = max(to, spans[i].to)
			}
			out.WriteString(s[at:from])
			out.WriteString("[redacted]")
			at = to
		}
		out.WriteString(s[at:])
		s = out.String()
	}
	if r.dir != "" {
		s = strings.ReplaceAll(s, r.dir, "<run>")
	}
	return s
}

// Line is a text made into one tidy line and scrubbed: scrubbed as it is, with its whitespace collapsed,
// and scrubbed again. The second pass is the point of it: collapsing a tab or a newline or a double
// space into one space can make the credential out of text that did not hold it, and anything done to
// a text after it is scrubbed (cutting it to length is safe, collapsing it is not) must be done
// before the last scrub or have no way to build a credential.
func (r *Redactor) Line(s string) string {
	return r.Scrub(strings.Join(strings.Fields(r.Scrub(s)), " "))
}

// ---- what a value is made of
//
// The value of a reference, as it is and in the encodings formsOf lists, is what is guaranteed never to
// reach the service. What is read out of the structure of a value (the fields of a JSON file, the login
// of an address, the parameters of a query or a connection string, the lines of a private key) is
// best effort: a part is taken only when it is clearly the part that unlocks, so that a collector can
// still name the endpoint, the account and the settings it was configured with.

type part struct{ text, kind string }

var (
	// jwtShape is a signed token: a header that starts {" and two more segments.
	jwtShape = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	// settingRe finds name=value in a connection string (a;b), a query (a&b), a keyword string
	// (a b), and the braces and quotes a value may be in. A name may have spaces in it ("Shared
	// Access Key"), so the words before the = are tried from the longest.
	settingRe = regexp.MustCompile(`(?:^|[\s;&?,#({\[])([A-Za-z][A-Za-z0-9_. -]{0,48}?)[ \t]*=[ \t]*('[^']*'|"[^"]*"|\{(?:[^{}]|\}\})*\}|[^\s;&'"]*)`)
	schemeRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
	// driverTail is where a driver address's login ends: user:password@tcp(host:3306)/db.
	driverTail = regexp.MustCompile(`@[A-Za-z][A-Za-z0-9]*\(`)
	hostTail   = regexp.MustCompile(`^[A-Za-z0-9.\[\]-]+(:[0-9]+)?$`)
	loginUser  = regexp.MustCompile(`^[A-Za-z0-9._\\$%+-]*$`)
	hostLike   = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	tldLike    = regexp.MustCompile(`^[A-Za-z]{2,24}$`)
)

// partsOf is the value, if it is long enough to be looked for in events, and the pieces of it
// that are credentials in their own right. Pieces of 4 to 7 bytes are only scrubbed.
func partsOf(v string) (parts []part, scrubOnly []string) {
	trimmed := strings.TrimSpace(v)
	if len(v) >= MinEnforced {
		parts = append(parts, part{v, ""})
	}
	d := &derivation{}
	// The start and end of these are the same in every one of them (a scheme and a host, a token's
	// header, an armour line, a brace, the options of a connection string) and a collector will say
	// them, so they are not looked for.
	structured := false
	var doc any
	switch {
	case (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) && json.Unmarshal([]byte(trimmed), &doc) == nil:
		structured = true
		walkJSON(doc, "", d.jsonString)
	case jwtShape.MatchString(trimmed):
		structured = true
		for _, seg := range strings.Split(trimmed, ".")[1:] {
			if len(seg) >= minSegment {
				d.add(seg, "a segment of it")
			}
		}
	default:
		structured = d.derive(trimmed)
		if strings.Contains(trimmed, "\n") {
			structured = true
			if !strings.Contains(trimmed, "-----BEGIN") {
				for _, line := range linesOf(trimmed) {
					d.add(line, "a line of it")
				}
			}
		}
	}
	if !structured && len(v) >= minForParts {
		d.add(v[:partLen], "its start")
		d.add(v[len(v)-partLen:], "its end")
	}
	return append(parts, d.parts...), d.scrub
}

// derivation collects the pieces read out of the structure of a value.
type derivation struct {
	parts []part
	scrub []string
}

func (d *derivation) add(text, kind string) {
	if ordinary(text) {
		return
	}
	switch {
	case len(text) >= MinEnforced:
		d.parts = append(d.parts, part{text, kind})
	case len(text) >= minRedact:
		d.scrub = append(d.scrub, text)
	}
}

// ordinaryWords are what a flag or a setting holds under a name that sounds like a password's
// (has_password, proxy_pass): they are never taken for one, not even to scrub them, or every one of
// them in every reason and log line would be hidden.
var ordinaryWords = map[string]bool{
	"true": true, "false": true, "yes": true, "no": true, "none": true, "null": true, "nil": true,
	"on": true, "off": true, "enabled": true, "disabled": true,
}

// ordinary says a piece is a boolean, a null, a plain word of that kind or a number too short to be
// looked for in events.
func ordinary(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	return ordinaryWords[t] || (len(t) < MinEnforced && allDigits(t))
}

// addDecoded adds a piece of an address as it is written and as it reads, if it was URL-escaped.
func (d *derivation) addDecoded(text, kind string) {
	d.add(text, kind)
	if plain, err := url.PathUnescape(text); err == nil && plain != text {
		d.add(plain, kind)
	}
}

// jsonString is called with each string of a JSON document and the name of the field it is in.
func (d *derivation) jsonString(key, s string) {
	switch classOfName(key) {
	case strongName:
		d.addDecoded(s, "a string in it")
	case looseName:
		if looksLikeSecret(s) {
			d.add(s, "a string in it")
		}
	}
	d.derive(s)
	if classOfName(key) != notSecret && strings.Contains(s, "\n") && !strings.Contains(s, "-----BEGIN") {
		for _, line := range linesOf(s) {
			d.add(line, "a line of it")
		}
	}
}

// derive reads the pieces out of one string: the private keys in it, the login of an address, the
// parameters of a connection string or a query. It says whether it is one of those, which
// is to say that its start and end are public text.
func (d *derivation) derive(s string) (structured bool) {
	if strings.Contains(s, "-----BEGIN") {
		structured = true
		for _, line := range privateKeyLines(s) {
			d.add(line, "a line of it")
		}
	}
	pws, tokenLogin := loginsOf(s)
	for _, pw := range pws {
		structured = true
		d.addDecoded(pw, "its password")
	}
	if tokenLogin != "" {
		structured = true
		d.addDecoded(tokenLogin, "its login")
	}
	if strings.Contains(s, "://") {
		structured = true
	}
	for _, st := range settingsOf(s) {
		structured = true
		switch st.class {
		case strongName:
			d.addDecoded(st.value, "a parameter of it")
		case looseName, queryName:
			if looksLikeSecret(st.value) {
				d.addDecoded(st.value, "a parameter of it")
			}
		}
	}
	return structured
}

type setting struct {
	class nameClass
	value string
}

// settingsOf is the name=value pairs of a string that look like settings. A pair is returned with
// the class of its name, which is notSecret for most.
func settingsOf(s string) []setting {
	var out []setting
	for _, m := range settingRe.FindAllStringSubmatch(s, -1) {
		value := m[2]
		switch {
		case len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0]:
			value = value[1 : len(value)-1]
		case len(value) >= 2 && value[0] == '{' && value[len(value)-1] == '}':
			value = strings.ReplaceAll(value[1:len(value)-1], "}}", "}")
		}
		if strings.Trim(value, "=") == "" {
			continue // padding at the end of a base64 token is not a setting
		}
		out = append(out, setting{classOfName(m[1]), value})
	}
	return out
}

// loginsOf is the password in the login of an address, as it is written: http://user:password@host,
// redis://:password@host, user:password@host, a driver's user:password@tcp(host:3306)/db (where the
// password may hold a slash), and, for an address with a scheme, a token used as the login
// (https://token@host). A name that is an email address in a JSON file is not a login.
func loginsOf(s string) (passwords []string, tokenLogin string) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return nil, ""
	}
	rest, scheme := s, false
	if loc := schemeRe.FindStringIndex(s); loc != nil {
		rest, scheme = s[loc[1]:], true
	}
	var userinfo string
	if loc := driverTail.FindStringIndex(rest); loc != nil {
		userinfo = rest[:loc[0]]
	} else {
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		authority := rest[:end]
		at := strings.LastIndex(authority, "@")
		if at <= 0 {
			return nil, ""
		}
		userinfo = authority[:at]
		if !hostTail.MatchString(authority[at+1:]) {
			return nil, ""
		}
	}
	user, pw, hasPassword := strings.Cut(userinfo, ":")
	switch {
	case hasPassword && pw != "" && loginUser.MatchString(user) && (user != "" || scheme):
		return []string{pw}, ""
	case !hasPassword && scheme && tokenLike(userinfo):
		return nil, userinfo
	}
	return nil, ""
}

// tokenLike says a login is a token and not a name: long, with letters and digits in it, and varied.
func tokenLike(s string) bool {
	var letter, digit bool
	for _, c := range s {
		letter = letter || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		digit = digit || (c >= '0' && c <= '9')
	}
	return len(s) >= 20 && letter && digit && entropy(s) >= 3.5
}

// privateKeyLines is the lines of the private keys in a text (PRIVATE KEY, ENCRYPTED PRIVATE KEY, RSA,
// EC, OPENSSH): not those of a certificate, which is public, and not the armour.
func privateKeyLines(text string) []string {
	var out []string
	for rest := text; ; {
		i := strings.Index(rest, "-----BEGIN ")
		if i < 0 {
			return out
		}
		rest = rest[i+len("-----BEGIN "):]
		label, after, ok := strings.Cut(rest, "-----")
		if !ok {
			return out
		}
		end := strings.Index(after, "-----END "+label+"-----")
		if end < 0 {
			end = len(after)
		}
		if strings.HasSuffix(label, "PRIVATE KEY") {
			for _, line := range strings.Split(after[:end], "\n") {
				if line = strings.TrimSpace(line); len(line) >= minLine && !strings.Contains(line, ":") {
					out = append(out, line)
				}
			}
		}
		rest = after[end:]
	}
}

// linesOf is the lines of a value that are long enough to be credentials, without the armour a
// PEM block starts and ends with.
func linesOf(v string) []string {
	var out []string
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= minLine && !strings.HasPrefix(line, "-----") && line != strings.TrimSpace(v) {
			out = append(out, line)
		}
	}
	return out
}

// ---- names

type nameClass int

const (
	notSecret nameClass = iota
	// strongName is a name that says what its value is: a password, a secret. Whatever it holds
	// is one, an address or a word or a number as well.
	strongName
	// looseName is the name of a key or a token, which holds one when it holds something long
	// and varied and not an address, a host or a number.
	looseName
	// queryName is a name that is a secret's only in a query or a connection string (key, code, sig).
	queryName
)

// nameClasses are the names, compared without case, underscores, dashes, dots and spaces:
// client_secret, clientSecret, ClientSecret and "Client Secret" are one name. A name that ends in one
// of them as a word is that name's too (bind_password, githubToken). token_endpoint_auth_method and
// key_vault hold settings, and a collector will mention them.
var nameClasses = map[string]nameClass{
	"password": strongName, "passwd": strongName, "pwd": strongName, "pw": strongName, "pass": strongName,
	"passphrase": strongName, "secret": strongName, "clientsecret": strongName,

	"token": looseName, "accesstoken": looseName, "refreshtoken": looseName, "idtoken": looseName,
	"authtoken": looseName, "bearertoken": looseName, "sessiontoken": looseName, "securitytoken": looseName,
	"apikey": looseName, "apisecret": looseName, "sharedsecret": looseName, "secretkey": looseName,
	"secretaccesskey": looseName, "signingkey": looseName, "privatekey": looseName,
	"accountkey": looseName, "sharedaccesskey": looseName, "sharedaccesssignature": looseName,
	"accesskey": looseName, "masterkey": looseName, "credential": looseName, "credentials": looseName,

	"key": queryName, "code": queryName, "sig": queryName, "signature": queryName,
}

// classOfName is the class of a name, from the longest run of its last words (up to three) that is a
// listed name.
func classOfName(key string) nameClass {
	words := nameWords(key)
	for n := min(3, len(words)); n >= 1; n-- {
		if class := nameClasses[strings.ToLower(strings.Join(words[len(words)-n:], ""))]; class != notSecret {
			return class
		}
	}
	return notSecret
}

// nameWords splits a name at its separators and where the case changes: bindPassword, APIKey and
// bind_password are two words each.
func nameWords(key string) []string {
	var words []string
	start := 0
	runes := []rune(key)
	flush := func(end int) {
		if end > start {
			words = append(words, string(runes[start:end]))
		}
		start = end
	}
	for i, c := range runes {
		switch {
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			flush(i)
			start = i + 1
		case i > start && unicode.IsUpper(c) && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1]) ||
			(unicode.IsUpper(runes[i-1]) && i+1 < len(runes) && unicode.IsLower(runes[i+1]))):
			flush(i)
		}
	}
	flush(len(runes))
	return words
}

// walkJSON calls f with each string in a decoded JSON document and the name of the field it is in
// (the field of the list or object it is in, however deep).
func walkJSON(v any, key string, f func(key, s string)) {
	switch x := v.(type) {
	case string:
		f(key, x)
	case []any:
		for _, e := range x {
			walkJSON(e, key, f)
		}
	case map[string]any:
		for k, e := range x {
			walkJSON(e, k, f)
		}
	}
}

// looksLikeSecret says a string under a key's or a token's name is one: long enough, not an address
// or a host or a number, and not one letter over and over.
func looksLikeSecret(s string) bool {
	switch {
	case len(s) < minField:
		return false
	case strings.Contains(s, "://"), strings.Contains(s, "@"):
		return false
	case allDigits(s):
		return false
	case isHost(s), awsKeyID.MatchString(s), isPath(s):
		return false
	}
	return entropy(s) >= minEntropy
}

// awsKeyID is the id of an access key, which names the key and unlocks nothing alone.
var awsKeyID = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`)

// isPath says a string is the path of a file: it starts as one does and is mostly lower case. A secret that happens to start with a slash is mixed case and digits (more than half of base64
// is), which a path hardly ever is.
func isPath(s string) bool {
	rooted := strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `\\`) ||
		(len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') && unicode.IsLetter(rune(s[0])))
	if !rooted {
		return false
	}
	capitals := 0
	for _, c := range s {
		if unicode.IsUpper(c) || unicode.IsDigit(c) {
			capitals++
		}
	}
	return capitals*4 <= len(s)
}

func isHost(s string) bool {
	if !hostLike.MatchString(s) {
		return false
	}
	return tldLike.MatchString(s[strings.LastIndex(s, ".")+1:])
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// entropy is the Shannon entropy of the bytes of s, in bits per byte.
func entropy(s string) float64 {
	var counts [256]int
	for i := range len(s) {
		counts[s[i]]++
	}
	var h float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// ---- the forms a value is written in

type form struct{ text, name string }

// asciiJSON is the text of a JSON string with every character outside ASCII written as \uXXXX, a pair
// for one outside the first plane.
func asciiJSON(text, hexFormat string) string {
	var b strings.Builder
	for _, r := range text {
		if r < utf8.RuneSelf {
			b.WriteRune(r)
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&b, `\u`+hexFormat, u)
		}
	}
	return b.String()
}

// formsOf is the value as it is and written the ways listed on Redactor, those long enough to
// look for in events.
func formsOf(v string) []form {
	var forms []form
	add := func(text, name string) {
		if len(text) >= MinEnforced {
			forms = append(forms, form{text, name})
		}
	}
	add(v, "as it is")
	jsonText, _ := json.Marshal(v)
	add(strings.Trim(string(jsonText), `"`), "JSON-quoted")
	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	noHTML := strings.Trim(strings.TrimSpace(plain.String()), `"`)
	add(noHTML, "JSON-quoted")
	// Other writers escape the slash (PHP, some Java) or write only ASCII, with the lower or the upper
	// case of the digits (Python, PHP; Java, .NET).
	for _, text := range []string{noHTML, strings.ReplaceAll(noHTML, "/", `\/`)} {
		add(text, "JSON-quoted")
		add(asciiJSON(text, "%04x"), "JSON-quoted")
		add(asciiJSON(text, "%04X"), "JSON-quoted")
	}
	add(strings.Trim(strconv.Quote(v), `"`), "Go-quoted")
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		add(e.EncodeToString([]byte(v)), "base64")
	}
	// Inside longer data the value starts 0, 1 or 2 bytes into a group of three. Encode it with that
	// much in front, and keep what no neighbour can change: not the characters that mix in the
	// bytes before (2 or 3 of them at alignments 1 and 2), nor the last two.
	for _, e := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for lead := range 3 {
			text := e.EncodeToString(append(make([]byte, lead), v...))
			from := [3]int{0, 2, 3}[lead]
			if to := len(text) - 2; to-from >= minFragment {
				add(text[from:to], "base64 inside longer data")
			}
		}
	}
	add(hex.EncodeToString([]byte(v)), "hex")
	add(strings.ToUpper(hex.EncodeToString([]byte(v))), "hex")
	add(url.QueryEscape(v), "URL-escaped")
	add(url.PathEscape(v), "URL-escaped")
	// A collector's log line goes through hclog, which writes a quote inside a quoted value as backslash
	// quote and leaves a backslash alone: a form with a quote in it reaches the log as another.
	for _, f := range slices.Clone(forms) {
		if strings.Contains(f.text, `"`) {
			add(strings.ReplaceAll(f.text, `"`, `\"`), "quoted in a log line")
		}
	}
	return forms
}

// ---- looking at a run's events

// Scanner looks at a run's events one after another, keeping the end of the text of each field so
// that a value printed in two pieces, in the same field of two events, is found when the second
// arrives. It is for one run and one goroutine.
type Scanner struct {
	r     *Redactor
	tails map[string]*tail
	// work is the bytes looked at over and above the events' own, for the tests.
	work int
}

// tail is the end of a field's text, and the places in it where a pattern may have begun: where what
// is left of the text is the start of a pattern, which the next event may finish.
type tail struct {
	data []byte
	open []int
}

// Scanner starts a scan of one run's events.
func (r *Redactor) Scanner() *Scanner { return &Scanner{r: r, tails: map[string]*tail{}} }

const (
	// maxTails is how many different fields keep a tail.
	maxTails = 64
	// maxOpen is how many places in a tail are followed at once. A pattern that is one byte over and over
	// would otherwise make every byte of a run of that byte one.
	maxOpen = 4096
)

// Leaks is Find without the answer to which.
func (s *Scanner) Leaks(event []byte, ev proto.Message) bool {
	_, ok := s.Find(event, ev)
	return ok
}

// Find says an event holds a resolved value, and which: in the bytes it will be sent as; in its text,
// every string and bytes field one after another (a value written as the code and the message of
// one diagnostic); or in a field's text joined to the same field of the events before it.
func (s *Scanner) Find(event []byte, ev proto.Message) (Hit, bool) {
	if s == nil || s.r == nil || len(s.r.entries) == 0 {
		return Hit{}, false
	}
	if hit, ok := s.r.Find(event); ok {
		return hit, true
	}
	fields := appendText(nil, "", ev.ProtoReflect())
	var all []byte
	for _, f := range fields {
		all = append(all, f.text...)
	}
	if len(all) == 0 {
		return Hit{}, false
	}
	if len(fields) > 1 {
		if hit, ok := s.r.Find(all); ok {
			return hit, true
		}
	}
	for _, f := range fields {
		if hit, ok := s.join(f); ok {
			return hit, true
		}
	}
	return Hit{}, false
}

// join looks at the text of a field joined to what was kept of the same field before, and keeps the
// end of it. Only the places a pattern may have begun in what was kept are looked at again; the rest
// of it was looked at when it came.
func (s *Scanner) join(f field) (Hit, bool) {
	t := s.tails[f.path]
	if t == nil {
		if len(s.tails) >= maxTails {
			// Nothing is kept of this field, so only its own text is looked at.
			t = &tail{}
			return s.look(t, f.text, false)
		}
		t = &tail{}
		s.tails[f.path] = t
	}
	return s.look(t, f.text, true)
}

func (s *Scanner) look(t *tail, text []byte, keep bool) (Hit, bool) {
	boundary := len(t.data)
	joined := text
	if keep {
		t.data = append(t.data, text...)
		joined = t.data
	}
	hit, open, found := s.r.cross(joined, t.open, boundary, &s.work)
	if found {
		t.data, t.open = joined, open
		return hit, true
	}
	if !keep {
		t.data, t.open = nil, nil
		return Hit{}, false
	}
	// Kept to the longest thing looked for less one byte, and to a bound: a pattern of that length that
	// began earlier is in the text already.
	limit := min(maxTail, s.r.maxLen-1)
	if drop := len(joined) - limit; drop > 0 {
		copy(joined, joined[drop:])
		joined = joined[:limit]
		kept := open[:0]
		for _, p := range open {
			if p -= drop; p >= 0 {
				kept = append(kept, p)
			}
		}
		open = kept
	}
	if cap(joined) > 2*limit+4096 {
		joined = slices.Clone(joined)
	}
	t.data, t.open = joined, open
	return Hit{}, false
}

// cross looks for patterns in the end of a joined text: those that begin in its last bytes or in the
// new part of it (from boundary), and those that begin at a place in the old part where the text so
// far is the start of one. It says which places in all of it are the start of a pattern that is not yet
// all there.
func (r *Redactor) cross(joined []byte, old []int, boundary int, work *int) (hit Hit, open []int, found bool) {
	note := func(p int) {
		if len(open) < maxOpen && (len(open) == 0 || open[len(open)-1] != p) {
			open = append(open, p)
		}
	}
	// check says what a pattern makes of the text from p on: it is all there, it is the start of the
	// pattern so far, or it is neither.
	check := func(p int, e *entry) (all, start bool) {
		rest := joined[p:]
		if len(rest) >= len(e.text) {
			return string(rest[:len(e.text)]) == e.text, false
		}
		return false, e.text[:len(rest)] == string(rest)
	}
	// Places that were the start of a pattern: it has grown, is finished, or is not one any more.
	for _, p := range old {
		*work += len(joined) - p
		for _, ix := range r.index[binary.LittleEndian.Uint64(joined[p:])] {
			e := &r.entries[ix]
			if all, start := check(p, e); all {
				return Hit{Source: r.sources[e.source], Part: e.part, Form: e.form}, nil, true
			} else if start {
				note(p)
			}
		}
	}
	// The new text and the last bytes before it, where the eight bytes of a key were not all there.
	from := max(0, boundary-7)
	*work += len(joined) - from
	for i := from; i+8 <= len(joined); i++ {
		k := binary.LittleEndian.Uint64(joined[i:])
		h := hashKey(k)
		if r.bloom[h>>6]&(1<<(h&63)) == 0 {
			continue
		}
		for _, ix := range r.index[k] {
			e := &r.entries[ix]
			if all, start := check(i, e); all {
				return Hit{Source: r.sources[e.source], Part: e.part, Form: e.form}, nil, true
			} else if start {
				note(i)
			}
		}
	}
	return Hit{}, open, false
}

// field is the text of one string or bytes field, and where it is: the numbers of the fields
// that lead to it.
type field struct {
	path string
	text []byte
}

// appendText adds every string and bytes value in a message, fields in order of number, nested
// messages and lists in place.
func appendText(dst []field, path string, m protoreflect.Message) []field {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if !m.Has(fd) {
			continue
		}
		here := path + "." + strconv.Itoa(int(fd.Number()))
		v := m.Get(fd)
		switch {
		case fd.IsMap():
			v.Map().Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
				dst = appendValue(dst, here+"k", fd.MapKey(), k.Value())
				dst = appendValue(dst, here+"v", fd.MapValue(), mv)
				return true
			})
		case fd.IsList():
			list := v.List()
			for j := range list.Len() {
				dst = appendValue(dst, here, fd, list.Get(j))
			}
		default:
			dst = appendValue(dst, here, fd, v)
		}
	}
	return dst
}

func appendValue(dst []field, path string, fd protoreflect.FieldDescriptor, v protoreflect.Value) []field {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return append(dst, field{path, []byte(v.String())})
	case protoreflect.BytesKind:
		return append(dst, field{path, v.Bytes()})
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return appendText(dst, path, v.Message())
	}
	return dst
}
