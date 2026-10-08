package secrets_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"google.golang.org/protobuf/proto"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
)

// A value with the characters that change shape when they are written into something else.
const awkward = `p"a\ss<w>&rd é/+=x9f3a-long-enough`

func redactorFor(t *testing.T, value string) *secrets.Redactor {
	t.Helper()
	p := strict(t, map[string]string{"S": value})
	p.AllowAny = true
	b, err := bindOne(p, "env:S")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b.Redact
}

// Each of the ways a collector, or a library under it, might write a value into an event.
// These are written independently of the code under test: from the encodings' own packages.
// asciiJSON is a JSON string as the encoders that write only ASCII write it: every other character as \uXXXX,
// one pair for a character outside the first plane.
func asciiJSON(plain, hexFormat string) string {
	var b strings.Builder
	for _, r := range plain {
		switch {
		case r < 0x80:
			b.WriteRune(r)
		default:
			for _, u := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(&b, `\u`+hexFormat, u)
			}
		}
	}
	return b.String()
}

func writtenAs(value string) map[string]string {
	jsonQuoted, _ := json.Marshal(value)
	var htmlOff bytes.Buffer
	enc := json.NewEncoder(&htmlOff)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(value)
	noHTML := strings.Trim(strings.TrimSpace(htmlOff.String()), `"`)
	slashes := strings.ReplaceAll(noHTML, "/", `\/`)
	return map[string]string{
		"raw":                         value,
		"JSON":                        strings.Trim(string(jsonQuoted), `"`),
		"JSON without HTML":           noHTML,
		"JSON, slashes escaped (PHP)": slashes,
		"JSON, ASCII only (Python)":   asciiJSON(noHTML, "%04x"),
		"JSON, ASCII only, capitals (Java, .NET)":        asciiJSON(noHTML, "%04X"),
		"JSON, ASCII only and slashes escaped (PHP)":     asciiJSON(slashes, "%04x"),
		"JSON, ASCII only and slashes escaped, capitals": asciiJSON(slashes, "%04X"),
		"Go %q":          strings.Trim(strconv.Quote(value), `"`),
		"base64 std":     base64.StdEncoding.EncodeToString([]byte(value)),
		"base64 std raw": base64.RawStdEncoding.EncodeToString([]byte(value)),
		"base64 url":     base64.URLEncoding.EncodeToString([]byte(value)),
		"base64 url raw": base64.RawURLEncoding.EncodeToString([]byte(value)),
		"hex":            hex.EncodeToString([]byte(value)),
		"HEX":            strings.ToUpper(hex.EncodeToString([]byte(value))),
		"query escaped":  url.QueryEscape(value),
		"path escaped":   url.PathEscape(value),
	}
}

func TestAnEventThatHoldsAResolvedValueInAnyOfTheseFormsIsCaught(t *testing.T) {
	r := redactorFor(t, awkward)
	for name, form := range writtenAs(awkward) {
		for _, around := range []struct{ before, after string }{{"", ""}, {"token=", ""}, {"", " was rejected"}, {"error: ", `"; code 7`}} {
			event := []byte("\x0a\x05name:" + around.before + form + around.after + "\x12\x01x")
			if !r.Leaks(event) {
				t.Errorf("%s (%q around): not caught in %q", name, around, event)
			}
		}
	}
}

// Base64 of something longer than the secret depends on where the secret falls: by 0, 1 or 2
// bytes into a group of three. All three are looked for.
func TestBase64OfTextThatContainsTheValueIsCaughtAtEveryAlignment(t *testing.T) {
	r := redactorFor(t, awkward)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		for before := range 7 {
			for after := range 4 {
				blob := strings.Repeat("a", before) + awkward + strings.Repeat("z", after)
				if !r.Leaks([]byte("data " + enc.EncodeToString([]byte(blob)) + " end")) {
					t.Errorf("%d bytes before and %d after, %T: not caught", before, after, enc)
				}
			}
		}
	}
}

func TestTextThatDoesNotHoldTheValueIsNotMistakenForIt(t *testing.T) {
	r := redactorFor(t, awkward)
	for _, text := range []string{
		"", "a perfectly ordinary event", "user alice, group platform",
		base64.StdEncoding.EncodeToString([]byte("an unrelated blob of text that is long enough to look like one")),
		strings.ToUpper(awkward[1:]),
	} {
		if r.Leaks([]byte(text)) {
			t.Errorf("%q was taken for the credential", text)
		}
	}
}

// A short value matches by chance: a four-letter password is in every other event.
func TestOnlyValuesOfEightBytesOrMoreAreLookedForInEvents(t *testing.T) {
	if redactorFor(t, "short12").Leaks([]byte("short12")) {
		t.Error("a 7-byte value was enforced")
	}
	if !redactorFor(t, "eight888").Leaks([]byte("xx eight888 xx")) {
		t.Error("an 8-byte value was not")
	}
	if !redactorFor(t, "eight888").Leaks([]byte(base64.StdEncoding.EncodeToString([]byte("eight888")))) {
		t.Error("the base64 of an 8-byte value was not")
	}
}

// A file ends in a newline the collector trims; what it echoes has none.
func TestTheValueWithoutTheNewlineAFileEndsInIsCaughtToo(t *testing.T) {
	r := redactorFor(t, "a-credential-from-a-file\n")
	if !r.Leaks([]byte("bad token a-credential-from-a-file here")) {
		t.Error("the trimmed value was not caught")
	}
	if !r.Leaks([]byte(base64.StdEncoding.EncodeToString([]byte("a-credential-from-a-file")))) {
		t.Error("the base64 of the trimmed value was not caught")
	}
}

func TestEveryFormIsScrubbedFromTextThatLeaves(t *testing.T) {
	r := redactorFor(t, awkward)
	for name, form := range writtenAs(awkward) {
		got := r.Scrub("before " + form + " after")
		if strings.Contains(got, form) || !strings.Contains(got, "[redacted]") || !strings.HasPrefix(got, "before ") {
			t.Errorf("%s: scrubbed = %q", name, got)
		}
	}
	blob := base64.StdEncoding.EncodeToString([]byte("xx" + awkward + "yy"))
	if got := r.Scrub(blob); got == blob {
		t.Errorf("base64 of text that holds the value was not scrubbed: %q", got)
	}
}

func TestNothingIsLookedForWhenNothingWasResolved(t *testing.T) {
	var none *secrets.Redactor
	if none.Leaks([]byte("anything")) || none.Scrub("anything") != "anything" {
		t.Error("a nil redactor changed something")
	}
	p := strict(t, nil)
	b, _ := p.Bind([]byte(`{}`))
	if b.Redact.Leaks([]byte("anything at all")) {
		t.Error("a redactor with no values found one")
	}
}

// ---- parts of a value, and a value in pieces

const token = "ghp_AbCdEf0123456789xyzXYZ_longtoken_0987654321qq" // 49 bytes

func TestAnEchoOfOnlyTheStartOrTheEndOfALongValueIsCaught(t *testing.T) {
	r := redactorFor(t, token)
	for name, echo := range map[string]string{
		"the first 30":   token[:30],
		"the last 20":    token[len(token)-20:],
		"a 16 byte head": token[:16],
		"a 16 byte tail": token[len(token)-16:],
	} {
		if !r.Leaks([]byte("saw " + echo + " in the response")) {
			t.Errorf("%s: not caught", name)
		}
	}
	// What is not caught: a piece from the middle, and a prefix shorter than 16 bytes.
	for name, echo := range map[string]string{"the middle": token[18:34], "ten bytes": token[:10]} {
		if r.Leaks([]byte(echo)) {
			t.Errorf("%s was caught: that is more than the agent promises, and a false positive waiting", name)
		}
	}
	// A value under 24 bytes is only looked for whole.
	short := redactorFor(t, "short-secret-of-20ch")
	if short.Leaks([]byte("short-secret")) {
		t.Error("the head of a 20-byte value was caught")
	}
}

const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n-----END PRIVATE KEY-----\n"

func TestOneLineOfAMultiLineValueIsCaughtAndItsArmourIsNot(t *testing.T) {
	r := redactorFor(t, pem)
	if !r.Leaks([]byte("key: MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu")) {
		t.Error("a line of the key was not caught")
	}
	if !r.Leaks([]byte(strings.ReplaceAll(pem, "\n", `\n`))) {
		t.Error("the whole key, with its newlines written out, was not caught")
	}
	// The armour is the same in every key, and a collector may say it was handed one.
	if r.Leaks([]byte("read a -----BEGIN PRIVATE KEY----- block")) {
		t.Error("the armour line was taken for the credential")
	}
}

const saFile = `{"type":"service_account","project_id":"my-project-12345","private_key_id":"0123456789abcdef0123456789abcdef01234567",` +
	`"private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----\n",` +
	`"client_email":"svc@my-project-12345.iam.gserviceaccount.com","client_id":"123456789012345678901","token_uri":"https://oauth2.googleapis.com/token"}`

func TestOneFieldOfAJSONCredentialIsCaughtButNotTheIdentifiersInIt(t *testing.T) {
	r := redactorFor(t, saFile)
	if !r.Leaks([]byte("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj")) {
		t.Error("a line of the private_key field was not caught")
	}
	// An address, a URL, a number and a word are what the file says about the account, not what
	// unlocks it, and a collector will mention them: the service account is a node of its own.
	for _, mention := range []string{"svc@my-project-12345.iam.gserviceaccount.com", "https://oauth2.googleapis.com/token", "123456789012345678901", "service_account", "my-project-12345"} {
		if r.Leaks([]byte("account " + mention)) {
			t.Errorf("%q was taken for the credential", mention)
		}
	}
}

func eventWithMessage(t *testing.T, msg string) (*collectorv1.CollectResponse, []byte) {
	t.Helper()
	ev := &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Diagnostic{Diagnostic: &collectorv1.Diagnostic{
		Severity: collectorv1.Severity_SEVERITY_INFO, Code: "test", Message: msg,
	}}}
	b, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return ev, b
}

// A value printed in two pieces, in two events, has the framing of each between its halves in the
// bytes of the stream. The text is what is joined.
func TestAValueSplitAcrossTwoEventsIsCaught(t *testing.T) {
	const value = "short-secret-of-20ch" // under 24 bytes: looked for whole, not by its head and tail
	r := redactorFor(t, value)
	scan := r.Scanner()
	half := len(value) / 2
	e1, b1 := eventWithMessage(t, "first part "+value[:half])
	e2, b2 := eventWithMessage(t, value[half:]+" is the rest")
	if scan.Leaks(b1, e1) {
		t.Fatal("the first half alone was caught")
	}
	if !scan.Leaks(b2, e2) {
		t.Error("the value, split over two events, was not caught")
	}
	// A scanner that has seen nothing of it does not carry anything over from another run's events.
	if fresh := r.Scanner(); fresh.Leaks(b2, e2) {
		t.Error("the second half alone was caught")
	}
	// Events that are not near each other are not joined.
	scan = r.Scanner()
	scan.Leaks(b1, e1)
	for range 20 {
		e, b := eventWithMessage(t, strings.Repeat("filler text ", 20))
		scan.Leaks(b, e)
	}
	if scan.Leaks(b2, e2) {
		t.Error("halves twenty events apart were joined")
	}
}

func TestTheValueInAnyOfItsFormsAcrossAFieldBoundaryOfOneEventIsCaught(t *testing.T) {
	const value = "short-secret-of-20ch"
	r := redactorFor(t, value)
	half := len(value) / 2
	ev := &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Diagnostic{Diagnostic: &collectorv1.Diagnostic{
		Severity: collectorv1.Severity_SEVERITY_INFO, Code: value[:half], Message: value[half:],
	}}}
	b, _ := proto.Marshal(ev)
	if !r.Scanner().Leaks(b, ev) {
		t.Error("a value written as the code and the message of one diagnostic was not caught")
	}
}

// Basic authorization is base64 of "user:password", the commonest place for a password to go.
func TestAShortPasswordInsideABasicAuthorizationHeaderIsCaught(t *testing.T) {
	for _, pw := range []string{"s3cr3tPw", "s3cr3tPw9", "Tr0ub4dor&3"} {
		r := redactorFor(t, pw)
		for _, user := range []string{"a", "ad", "adm", "admin", "root", "svc-keycloak", "administrator"} {
			header := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pw)) + "\r\n"
			if !r.Leaks([]byte(header)) {
				t.Errorf("%q with user %q: not caught in %q", pw, user, header)
			}
		}
	}
}

func TestAProxyAddressWithAPasswordInItIsScrubbedAndCaughtButOneWithoutIsNot(t *testing.T) {
	r := &secrets.Redactor{}
	for _, v := range []string{
		"http://svc-account:pr0xy-Pa55word@proxy.corp.example:3128",
		"http://proxy.corp.example:3128", // no credentials: not a secret, and a collector may say it uses it
		"not a url at all",
	} {
		if err := r.AddURLCredentials("env:HTTPS_PROXY", v); err != nil {
			t.Fatal(err)
		}
	}
	if !r.Leaks([]byte("proxy password pr0xy-Pa55word seen")) {
		t.Error("the proxy password was not caught")
	}
	if r.Leaks([]byte("using proxy http://proxy.corp.example:3128")) {
		t.Error("an address with no credentials was taken for one")
	}
	if got := r.Scrub("connecting as svc-account:pr0xy-Pa55word to it"); strings.Contains(got, "pr0xy-Pa55word") {
		t.Errorf("scrubbed = %q", got)
	}
}

// The other ways JSON is written, for values under 24 bytes, which are looked for whole: no head or
// tail of plain text is there to find. A character outside the first plane is written as a pair by an
// encoder that writes only ASCII.
func TestTheOtherWaysJSONIsWrittenAreCaughtForAShortValue(t *testing.T) {
	for _, value := range []string{"k-\U0001F600-\u00e9/r3st-of-it", "wJalrXUtnFEMI/K7MDENG/bPxRfi", "plain/slash/only/x9"} {
		r := redactorFor(t, value)
		for name, form := range writtenAs(value) {
			if !r.Leaks([]byte("event: " + form + " end")) {
				t.Errorf("%q, %s: %q not caught", value, name, form)
			}
			if got := r.Scrub("before " + form + " after"); strings.Contains(got, form) {
				t.Errorf("%q, %s: %q not scrubbed: %q", value, name, form, got)
			}
		}
	}
	const emoji = "\U0001F600"
	if !strings.Contains(asciiJSON(emoji, "%04x"), `\ud83d\ude00`) {
		t.Fatal("the test's own encoder is wrong")
	}
}

// varied is n bytes that are not one thing over and over; the same seed gives the same bytes.
func varied(n int, seed uint32) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	x := seed
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = alphabet[(x>>16)%uint32(len(alphabet))]
	}
	return string(b)
}

// The tail kept of a field is as long as the longest thing looked for, up to 64 KiB, so a value
// printed in two pieces is found whatever the length of the first, as long as it fits.
func TestAValueSplitAcrossTwoEventsIsCaughtWhateverTheLengthOfTheFirstPiece(t *testing.T) {
	for _, n := range []int{40, 2050, 4000, 30_000, 100_000} {
		// A password in a JSON file: a value whose start and end are not looked for by themselves.
		value := varied(n, 7)
		r := redactorFor(t, `{"user":"svc","password":"`+value+`"}`)
		scan := r.Scanner()
		e1, b1 := eventWithMessage(t, "first "+value[:n/2])
		e2, b2 := eventWithMessage(t, value[n/2:]+" last")
		if scan.Leaks(b1, e1) {
			t.Fatalf("%d bytes: the first half alone was caught", n)
		}
		if !scan.Leaks(b2, e2) {
			t.Errorf("%d bytes: the value, in two halves of %d, was not caught", n, n/2)
		}
	}
}

func TestWhatTheScannerKeepsOfAFieldIsTheLongestPatternOrSixtyFourKiBAndNoMore(t *testing.T) {
	big := redactorFor(t, `{"password":"`+varied(100_000, 7)+`"}`)
	scan := big.Scanner()
	for range 4 {
		e, b := eventWithMessage(t, varied(100_000, 99))
		scan.Leaks(b, e)
	}
	// The message is kept to 64 KiB; the few bytes over are the code of each event.
	if got := scan.Held(); got < 64<<10 || got > 64<<10+64 {
		t.Errorf("held %d bytes of a field against a value of 100,000 bytes, want %d", got, 64<<10)
	}
	small := redactorFor(t, `{"password":"short-secret-of-20ch"}`)
	scan = small.Scanner()
	for range 40 {
		e, b := eventWithMessage(t, strings.Repeat("filler text ", 20))
		scan.Leaks(b, e)
	}
	if got := scan.Held(); got == 0 || got > 512 {
		t.Errorf("held %d bytes of a field against a value of 20 bytes", got)
	}
}

// A value may arrive in many pieces, and may start anywhere in the first: the places it can be begun
// are kept from one event to the next and not looked for again from the start of what was kept.
func TestAValueInSeveralPiecesIsCaughtWhereverItIsCut(t *testing.T) {
	const value = "short-secret-of-20ch"
	r := redactorFor(t, value)
	for at := 1; at < len(value); at++ {
		scan := r.Scanner()
		e1, b1 := eventWithMessage(t, "first "+value[:at])
		e2, b2 := eventWithMessage(t, value[at:]+" last")
		if scan.Leaks(b1, e1) {
			t.Fatalf("cut at %d: the first piece alone was caught", at)
		}
		if !scan.Leaks(b2, e2) {
			t.Errorf("cut at %d: not caught in two pieces", at)
		}
	}
	for pieces := 3; pieces <= 20; pieces++ {
		scan := r.Scanner()
		caught := false
		for i := range pieces {
			from, to := i*len(value)/pieces, (i+1)*len(value)/pieces
			e, b := eventWithMessage(t, value[from:to])
			if scan.Leaks(b, e) {
				if i != pieces-1 {
					t.Fatalf("%d pieces: caught at piece %d", pieces, i)
				}
				caught = true
			}
		}
		if !caught {
			t.Errorf("%d pieces: not caught", pieces)
		}
	}
	// Other text between the pieces, in the same field, is not a piece.
	scan := r.Scanner()
	e1, b1 := eventWithMessage(t, "first "+value[:10])
	e2, b2 := eventWithMessage(t, "something else entirely "+value[10:])
	scan.Leaks(b1, e1)
	if scan.Leaks(b2, e2) {
		t.Error("two pieces with other text between them were joined")
	}
}

// Two values that begin the same way, in two pieces: the one that is there is found, and the one that
// is not is not.
func TestTwoValuesThatBeginTheSameWayAreToldApartAcrossEvents(t *testing.T) {
	r := &secrets.Redactor{}
	for _, v := range []string{"shared-start-one-AAAA", "shared-start-two-BBBB"} {
		if err := r.Add("env:"+v[:16], v); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		first, second string
		want          bool
	}{
		{"shared-start-t", "wo-BBBB", true},
		{"shared-start-o", "ne-AAAA", true},
		{"shared-start-t", "wo-CCCC", false},
		{"shared-start-o", "ne-BBBB", false},
		{"shared-star", "t-three-DDDD", false},
	} {
		scan := r.Scanner()
		e1, b1 := eventWithMessage(t, c.first)
		e2, b2 := eventWithMessage(t, c.second)
		scan.Leaks(b1, e1)
		if scan.Open() != 1 {
			t.Errorf("%q: %d places followed after the first piece, want the one", c.first, scan.Open())
		}
		if got := scan.Leaks(b2, e2); got != c.want {
			t.Errorf("%q then %q: caught = %v", c.first, c.second, got)
		}
	}
}

// What the scanner looks at, over and above the events, does not grow with how much it keeps of a field:
// a reference of 40 KiB keeps 64 KiB of every field, and looking through all of it for every event
// costs a millisecond or more.
func TestWhatTheScannerLooksAtDoesNotGrowWithWhatItKeeps(t *testing.T) {
	r := redactorFor(t, `{"password":"`+varied(40_000, 7)+`"}`)
	scan := r.Scanner()
	text := 0
	for i := range 600 {
		msg := "identity " + strconv.Itoa(i) + " of the directory, member of group platform-admins " + strings.Repeat("and so on ", 12)
		e, b := eventWithMessage(t, msg)
		text += len(msg) + len("test")
		if scan.Leaks(b, e) {
			t.Fatal("an ordinary event was caught")
		}
	}
	if scan.Held() < 64<<10 {
		t.Fatalf("held %d: the test did not keep enough to be one", scan.Held())
	}
	if work := scan.Work(); work > 20*text {
		t.Errorf("looked at %d bytes over and above the events for %d bytes of text (%.0f times)", work, text, float64(work)/float64(text))
	}
}

// BenchmarkAnEventAgainstALargeReference is the cost of an event against a reference of 40 KiB.
func BenchmarkAnEventAgainstALargeReference(b *testing.B) {
	p := strict(b, map[string]string{"S": `{"password":"` + varied(40_000, 7) + `"}`})
	p.AllowAny = true
	bound, err := bindOne(p, "env:S")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = bound.Close() })
	scan := bound.Redact.Scanner()
	ev := &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Node{Node: &collectorv1.Node{
		Name:    "alice@corp.example",
		Context: map[string]string{"department": "engineering", "manager": "bob@corp.example", "location": "Amsterdam"},
	}}}
	raw, _ := proto.Marshal(ev)
	b.ResetTimer()
	for range b.N {
		if scan.Leaks(raw, ev) {
			b.Fatal("caught")
		}
	}
}

// The text kept is cut at the front as new text arrives; the places followed in it move with it.
func TestAValueInThreePiecesAfterALotOfOtherTextIsCaught(t *testing.T) {
	value := varied(3000, 7)
	r := redactorFor(t, `{"user":"svc","password":"`+value+`"}`)
	scan := r.Scanner()
	for i, text := range []string{varied(9000, 5), "start " + value[:1000], value[1000:2000], value[2000:] + " end"} {
		e, b := eventWithMessage(t, text)
		got := scan.Leaks(b, e)
		if got != (i == 3) {
			t.Errorf("piece %d: caught = %v", i, got)
		}
	}
}

// A value that is one byte over and over would make every place in a run of it the start of one.
func TestAValueThatIsOneByteOverAndOverIsFollowedFromBeforeItIsCut(t *testing.T) {
	r := redactorFor(t, `{"password":"`+strings.Repeat("a", 8000)+`"}`)
	scan := r.Scanner()
	e, b := eventWithMessage(t, strings.Repeat("a", 5000))
	if scan.Leaks(b, e) {
		t.Fatal("5000 of 8000 bytes were caught")
	}
	if scan.Open() > 4096 {
		t.Errorf("%d places are followed", scan.Open())
	}
	e, b = eventWithMessage(t, strings.Repeat("a", 3000))
	if !scan.Leaks(b, e) {
		t.Error("the rest of the value was not caught")
	}
}
