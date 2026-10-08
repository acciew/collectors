package collection_test

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"go.acciew.io/collector/verify/collection"
)

// Expected text below writes a JSON unicode escape as "~u", which esc turns
// into the backslash form, so that the tables read as the bytes they stand for.
func esc(s string) string { return strings.ReplaceAll(s, "~u", "\\"+"u") }

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var when = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func key(typ int32, id string) collection.Key {
	return collection.Key{Scope: "realm-a", Type: typ, ID: id}
}

// run is the synthetic collection whose digest an earlier build wrote down,
// before this package existed. The enum values are the numbers on the wire:
// verdict 1, scope status 1, identity 1, grouping 2, entitlement 3, fidelity 2.
func run() collection.Run {
	return collection.Run{
		Source: "keycloak", StartedAt: when, Whole: true, Verdict: 1,
		Scopes: []collection.Scope{{ID: "realm-a", Status: 1, ActivityAvailable: true}},
		Counts: collection.Counts{Identities: 4, Groupings: 1, Entitlements: 2, Grants: 5},
		Observed: []collection.Grant{
			{Identity: key(1, "alice"), Entitlement: key(3, "admin"), Fidelity: 2, Via: []collection.Key{key(2, "platform")}},
		},
	}
}

const (
	// The digest recorded for run() before the verifier existed. If this stops
	// matching, the canonical form has drifted and every log already written
	// reads as altered.
	golden = "7b1fcc8b50238a323ca9dafdb2edf97507bca262746b1f2f4a833e2db44d0285"

	goldenCanonical = `{"source":"keycloak","started_at":"2026-09-05T12:00:00Z","whole":true,"verdict":1,"cause":0,` +
		`"scopes":[{"id":"realm-a","status":1,"reason":"","activity_available":true}],` +
		`"counts":{"identities":4,"groupings":1,"entitlements":2,"resources":0,"grants":5,"referenced":0},` +
		`"observed":[{"identity":"realm-a/identity/alice","entitlement":"realm-a/entitlement/admin","fidelity":2,` +
		`"via":["realm-a/grouping/platform"]}]}`
)

func TestTheGoldenDigestIsWhatAnEarlierBuildWrote(t *testing.T) {
	if got := collection.Digest(run()); got != golden {
		t.Errorf("Digest = %s, want %s", got, golden)
	}
}

// The golden text is checked here with the standard library alone, so neither
// the digest nor the canonical form is taken on this package's word.
func TestTheGoldenCanonicalFormIsTheTextTheDigestIsTakenOver(t *testing.T) {
	if got := sha(goldenCanonical); got != golden {
		t.Fatalf("the table is wrong: sha256 of the canonical text is %s, not %s", got, golden)
	}
	if got := string(collection.Canonical(run())); got != goldenCanonical {
		t.Errorf("Canonical =\n%s\nwant\n%s", got, goldenCanonical)
	}
}

func TestACollectionWithNothingInItHasAForm(t *testing.T) {
	want := `{"source":"","started_at":"0001-01-01T00:00:00Z","whole":false,"verdict":0,"cause":0,"scopes":null,` +
		`"counts":{"identities":0,"groupings":0,"entitlements":0,"resources":0,"grants":0,"referenced":0},"observed":null}`
	if got := string(collection.Canonical(collection.Run{})); got != want {
		t.Errorf("Canonical =\n%s\nwant\n%s", got, want)
	}
	// An empty list and an absent one are the same record.
	r := collection.Run{Scopes: []collection.Scope{}, Observed: []collection.Grant{}}
	if got := string(collection.Canonical(r)); got != want {
		t.Errorf("empty lists are not rendered as null:\n%s", got)
	}
}

func TestEveryFieldReachesTheDigest(t *testing.T) {
	base := collection.Digest(run())
	cases := map[string]func(*collection.Run){
		"source":            func(r *collection.Run) { r.Source = "github" },
		"started":           func(r *collection.Run) { r.StartedAt = when.Add(time.Nanosecond) },
		"whole":             func(r *collection.Run) { r.Whole = false },
		"verdict":           func(r *collection.Run) { r.Verdict = 2 },
		"cause":             func(r *collection.Run) { r.Cause = 1 },
		"scope id":          func(r *collection.Run) { r.Scopes[0].ID = "realm-b" },
		"scope status":      func(r *collection.Run) { r.Scopes[0].Status = 3 },
		"scope reason":      func(r *collection.Run) { r.Scopes[0].Reason = "why" },
		"activity":          func(r *collection.Run) { r.Scopes[0].ActivityAvailable = false },
		"activity unknown":  func(r *collection.Run) { r.Scopes[0].ActivityUndetermined = true },
		"identities":        func(r *collection.Run) { r.Counts.Identities = 5 },
		"groupings":         func(r *collection.Run) { r.Counts.Groupings = 2 },
		"entitlements":      func(r *collection.Run) { r.Counts.Entitlements = 3 },
		"resources":         func(r *collection.Run) { r.Counts.Resources = 1 },
		"grants":            func(r *collection.Run) { r.Counts.Grants = 6 },
		"referenced":        func(r *collection.Run) { r.Counts.Referenced = 1 },
		"grant fidelity":    func(r *collection.Run) { r.Observed[0].Fidelity = 1 },
		"grant route":       func(r *collection.Run) { r.Observed[0].Via = nil },
		"grant route key":   func(r *collection.Run) { r.Observed[0].Via[0].ID = "other" },
		"grant subject":     func(r *collection.Run) { r.Observed[0].Identity.ID = "bob" },
		"subject scope":     func(r *collection.Run) { r.Observed[0].Identity.Scope = "realm-b" },
		"subject type":      func(r *collection.Run) { r.Observed[0].Identity.Type = 2 },
		"grant entitlement": func(r *collection.Run) { r.Observed[0].Entitlement.ID = "read" },
		"extra grant":       func(r *collection.Run) { r.Observed = append(r.Observed, r.Observed[0]) },
	}
	for name, change := range cases {
		r := run()
		change(&r)
		if got := collection.Digest(r); got == base {
			t.Errorf("changing the %s did not change the digest", name)
		}
	}
}

func TestDigestIsTheSHA256OfCanonical(t *testing.T) {
	r := run()
	r.Source = "elsewhere"
	if got, want := collection.Digest(r), sha(string(collection.Canonical(r))); got != want {
		t.Errorf("Digest = %s, want %s", got, want)
	}
}

// An enum goes in as its number, never as a name: a name for a number this
// build does not know would be different in a build that does.
func TestEnumsAreHashedAsNumbers(t *testing.T) {
	r := run()
	r.Verdict, r.Cause = 77, 7
	r.Scopes[0].Status = 9
	r.Observed[0].Fidelity = 99
	got := string(collection.Canonical(r))
	for _, want := range []string{`"verdict":77`, `"cause":7`, `"status":9`, `"fidelity":99`} {
		if !strings.Contains(got, want) {
			t.Errorf("%s is missing from\n%s", want, got)
		}
	}
	if strings.Contains(got, "unrecognised(77)") || strings.Contains(got, "unrecognised(9)") || strings.Contains(got, "unrecognised(99)") {
		t.Errorf("an enum was rendered as a word:\n%s", got)
	}
}

func TestAKeyIsRenderedScopeTypeNameID(t *testing.T) {
	cases := []struct {
		typ  int32
		want string
	}{
		{1, "s/identity/x"}, {2, "s/grouping/x"}, {3, "s/entitlement/x"}, {4, "s/resource/x"}, {5, "s/scope/x"},
		{0, "s/unspecified/x"},
		{6, "s/unrecognised(6)/x"}, {7, "s/unrecognised(7)/x"}, {-1, "s/unrecognised(-1)/x"},
		{2147483647, "s/unrecognised(2147483647)/x"},
	}
	for _, tc := range cases {
		if got := (collection.Key{Scope: "s", Type: tc.typ, ID: "x"}).String(); got != tc.want {
			t.Errorf("type %d renders as %q, want %q", tc.typ, got, tc.want)
		}
	}
	// Nothing is escaped or checked: the three parts are joined by "/".
	if got := (collection.Key{Scope: "a/b", Type: 1, ID: "c/d"}).String(); got != "a/b/identity/c/d" {
		t.Errorf("got %q", got)
	}
}

// The words for key types are part of the form, because a key is hashed as its
// rendering. A type this build does not name is hashed as the number it is.
func TestAKeyOfAnUnknownTypeIsHashedAsUnrecognised(t *testing.T) {
	r := run()
	r.Observed[0].Identity.Type = 7
	if got := string(collection.Canonical(r)); !strings.Contains(got, `"identity":"realm-a/unrecognised(7)/alice"`) {
		t.Errorf("Canonical =\n%s", got)
	}
}

func TestStringsAreEscapedTheWayGoWritesThem(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain ascii", "keycloak", `"keycloak"`},
		{"angle brackets and ampersand", "a<b>&c", `"a~u003cb~u003e~u0026c"`},
		{"non-ASCII stays as it is", "\xc3\xa9quipe \xe6\x97\xa5\xe6\x9c\xac \xf0\x9f\x94\x91", "\"\xc3\xa9quipe \xe6\x97\xa5\xe6\x9c\xac \xf0\x9f\x94\x91\""},
		{"line separator", "a\xe2\x80\xa8b", `"a~u2028b"`},
		{"paragraph separator", "a\xe2\x80\xa9b", `"a~u2029b"`},
		{"quote, backslash and slash", `q"b\s/`, `"q\"b\\s/"`},
		{"short control escapes", "\b\f\n\r\t", `"\b\f\n\r\t"`},
		{"other control characters", "\x00\x01\x1f", `"~u0000~u0001~u001f"`},
		{"delete is not escaped", "\x7f", "\"\x7f\""},
		{"an invalid byte becomes an escaped U+FFFD", "a\xffb", `"a~ufffdb"`},
		{"each invalid byte becomes one", "\xc0\x80", `"~ufffd~ufffd"`},
		{"a surrogate is invalid UTF-8", "\xed\xa0\x80", `"~ufffd~ufffd~ufffd"`},
		{"a real U+FFFD is written as it is", "a\xef\xbf\xbdb", "\"a\xef\xbf\xbdb\""},
		{"an empty string", "", `""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := collection.Run{Source: tc.in}
			got := string(collection.Canonical(r))
			want := `{"source":` + esc(tc.want) + `,"started_at":`
			if !strings.HasPrefix(got, want) {
				t.Errorf("Canonical = %q\nwant it to start %q", got, want)
			}
		})
	}
}

// The rule holds for every string in the form, not only the source.
func TestEveryStringIsEscapedTheSame(t *testing.T) {
	r := collection.Run{
		Scopes:   []collection.Scope{{ID: "i<", Reason: "r&"}},
		Observed: []collection.Grant{{Identity: collection.Key{Scope: "s>", Type: 1, ID: "\xe2\x80\xa8"}}},
	}
	got := string(collection.Canonical(r))
	for _, want := range []string{`"id":"i~u003c"`, `"reason":"r~u0026"`, `"identity":"s~u003e/identity/~u2028"`} {
		if !strings.Contains(got, esc(want)) {
			t.Errorf("%s is missing from\n%s", esc(want), got)
		}
	}
}

func TestAnInstantIsWrittenInUTCWithTheFractionGoPrints(t *testing.T) {
	plus2 := time.FixedZone("", 2*60*60)
	cases := []struct {
		name string
		in   time.Time
		want string
	}{
		{"whole second", time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC), "2026-09-05T12:00:00Z"},
		{"half a second", time.Date(2026, 9, 5, 12, 0, 0, 500_000_000, time.UTC), "2026-09-05T12:00:00.5Z"},
		{"a millisecond, no trailing zeros", time.Date(2026, 9, 5, 12, 0, 0, 1_000_000, time.UTC), "2026-09-05T12:00:00.001Z"},
		{"a hundred milliseconds", time.Date(2026, 9, 5, 12, 0, 0, 100_000_000, time.UTC), "2026-09-05T12:00:00.1Z"},
		{"one nanosecond", time.Date(2026, 9, 5, 12, 0, 0, 1, time.UTC), "2026-09-05T12:00:00.000000001Z"},
		{"nine digits", time.Date(2026, 9, 5, 12, 0, 0, 123_456_789, time.UTC), "2026-09-05T12:00:00.123456789Z"},
		{"another zone is converted", time.Date(2026, 9, 5, 12, 0, 0, 0, plus2), "2026-09-05T10:00:00Z"},
		{"another zone across midnight", time.Date(2026, 1, 1, 1, 30, 0, 250_000_000, plus2), "2025-12-31T23:30:00.25Z"},
		{"the zero time", time.Time{}, "0001-01-01T00:00:00Z"},
		{"the last year", time.Date(9999, 12, 31, 23, 59, 59, 999_999_999, time.UTC), "9999-12-31T23:59:59.999999999Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(collection.Canonical(collection.Run{StartedAt: tc.in}))
			want := `"started_at":"` + tc.want + `","whole"`
			if !strings.Contains(got, want) {
				t.Errorf("Canonical = %s\nwant it to contain %s", got, want)
			}
		})
	}
}

func TestScopesAreOrderedByIDAsBytesAndKeepOnlyWhatTheyAre(t *testing.T) {
	r := collection.Run{Scopes: []collection.Scope{
		{ID: "b", Status: 1}, {ID: "a", Status: 2, ActivityAvailable: true}, {ID: "B", Status: 3},
		{ID: "\xc3\xa9", Status: 4}, {ID: "a0", Status: 5},
	}}
	got := string(collection.Canonical(r))
	want := `"scopes":[` +
		`{"id":"B","status":3,"reason":"","activity_available":false},` +
		`{"id":"a","status":2,"reason":"","activity_available":true},` +
		`{"id":"a0","status":5,"reason":"","activity_available":false},` +
		`{"id":"b","status":1,"reason":"","activity_available":false},` +
		"{\"id\":\"\xc3\xa9\",\"status\":4,\"reason\":\"\",\"activity_available\":false}],"
	if !strings.Contains(got, want) {
		t.Errorf("Canonical =\n%s\nwant it to contain\n%s", got, want)
	}
}

func TestActivityUndeterminedIsWrittenOnlyWhenTrue(t *testing.T) {
	r := collection.Run{Scopes: []collection.Scope{{ID: "s", ActivityUndetermined: true}}}
	if got := string(collection.Canonical(r)); !strings.Contains(got, `"activity_available":false,"activity_undetermined":true}`) {
		t.Errorf("flag missing or misplaced:\n%s", got)
	}
	r.Scopes[0].ActivityUndetermined = false
	if got := string(collection.Canonical(r)); strings.Contains(got, "activity_undetermined") {
		t.Errorf("a false flag was written:\n%s", got)
	}
}

func TestCountsAreInTheirFixedOrder(t *testing.T) {
	r := collection.Run{Counts: collection.Counts{Identities: 1, Groupings: 2, Entitlements: 3, Resources: 4, Grants: 5, Referenced: 6}}
	want := `"counts":{"identities":1,"groupings":2,"entitlements":3,"resources":4,"grants":5,"referenced":6}`
	if got := string(collection.Canonical(r)); !strings.Contains(got, want) {
		t.Errorf("Canonical =\n%s", got)
	}
}

// A grant is ordered by subject, then entitlement, then the route joined by
// ">", then fidelity, each part ended by a NUL so that one part cannot run into
// the next. "a" must sort before "a0" because NUL sorts before "0": with the
// parts simply joined it would be the other way about.
func TestGrantsAreOrderedBySubjectEntitlementRouteAndFidelity(t *testing.T) {
	g := func(id, ent string, fid int32, via ...string) collection.Grant {
		grant := collection.Grant{Identity: collection.Key{Scope: "s", Type: 1, ID: id},
			Entitlement: collection.Key{Scope: "s", Type: 3, ID: ent}, Fidelity: fid}
		for _, v := range via {
			grant.Via = append(grant.Via, collection.Key{Scope: "s", Type: 2, ID: v})
		}
		return grant
	}
	ordered := []collection.Grant{
		g("a", "x", 1),
		g("a", "x", 2),
		g("a", "x", 2, "g"),
		g("a", "x", 2, "g", "h"),
		g("a", "y", 1),
		g("a0", "x", 1),
		g("b", "x", 1),
	}
	const wantObserved = `"observed":[` +
		`{"identity":"s/identity/a","entitlement":"s/entitlement/x","fidelity":1,"via":null},` +
		`{"identity":"s/identity/a","entitlement":"s/entitlement/x","fidelity":2,"via":null},` +
		`{"identity":"s/identity/a","entitlement":"s/entitlement/x","fidelity":2,"via":["s/grouping/g"]},` +
		`{"identity":"s/identity/a","entitlement":"s/entitlement/x","fidelity":2,"via":["s/grouping/g","s/grouping/h"]},` +
		`{"identity":"s/identity/a","entitlement":"s/entitlement/y","fidelity":1,"via":null},` +
		`{"identity":"s/identity/a0","entitlement":"s/entitlement/x","fidelity":1,"via":null},` +
		`{"identity":"s/identity/b","entitlement":"s/entitlement/x","fidelity":1,"via":null}]}`

	rng := rand.New(rand.NewPCG(1, 2))
	for range 50 {
		shuffled := append([]collection.Grant(nil), ordered...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := string(collection.Canonical(collection.Run{Observed: shuffled})); !strings.HasSuffix(got, wantObserved) {
			t.Fatalf("the grants are not in the order written down:\n%s", got)
		}
	}
}

// The route is part of what a grant is, and its order is kept: two keys in a
// different order are a different route.
func TestARouteKeepsItsOrderAndIsNotSorted(t *testing.T) {
	r := run()
	r.Observed[0].Via = []collection.Key{key(2, "z"), key(2, "a")}
	got := string(collection.Canonical(r))
	if !strings.Contains(got, `"via":["realm-a/grouping/z","realm-a/grouping/a"]`) {
		t.Errorf("Canonical =\n%s", got)
	}
	r2 := run()
	r2.Observed[0].Via = []collection.Key{key(2, "a"), key(2, "z")}
	if collection.Digest(r) == collection.Digest(r2) {
		t.Error("two routes in a different order digested the same")
	}
}

func TestAnEmptyRouteIsNullWhetherEmptyOrAbsent(t *testing.T) {
	for _, via := range [][]collection.Key{nil, {}} {
		r := run()
		r.Observed[0].Via = via
		if got := string(collection.Canonical(r)); !strings.Contains(got, `"fidelity":2,"via":null}`) {
			t.Errorf("Canonical =\n%s", got)
		}
	}
}

// The second worked example of the specification: a name with every kind of
// character that needs care, a time given with an offset, and everything else
// empty. Its digest was computed outside Go, from the canonical text.
func TestTheSecondWorkedExampleOfTheSpecification(t *testing.T) {
	r := collection.Run{
		Source:    "a<b>&c\xe2\x80\xa8\xc3\xa9",
		StartedAt: time.Date(2026, 1, 2, 5, 4, 5, 250_000_000, time.FixedZone("", 2*60*60)),
	}
	want := esc(`{"source":"a~u003cb~u003e~u0026c~u2028`) + "\xc3\xa9" + `","started_at":"2026-01-02T03:04:05.25Z","whole":false,` +
		`"verdict":0,"cause":0,"scopes":null,` +
		`"counts":{"identities":0,"groupings":0,"entitlements":0,"resources":0,"grants":0,"referenced":0},"observed":null}`
	if got := string(collection.Canonical(r)); got != want {
		t.Errorf("Canonical =\n%s\nwant\n%s", got, want)
	}
	if got := collection.Digest(r); got != "495983f446860798f67b7af20866ea989b1cd8e9c4fa8bfcb00f98a91ee99ab8" {
		t.Errorf("Digest = %s", got)
	}
}

// Two grants can read alike to the ordering: a route through one key whose id
// holds ">" and a route through two keys give the same joined text. The order of
// such grants is then that of their renderings, so the digest is a function of
// the record and not of the order the grants arrived in. The digests below were
// computed by testdata/gen/fixture.py --vectors, outside Go.
const (
	tieGrantsDigest = "da7234b611b6b9b15ffe0e6e5fb298a7d926258b5f29cb11911b181bc0af7b73"
	tieScopesDigest = "615ac6461ef671e2f5f3da10420d6e7597190f9a3ae1aaf09a2526142e298aee"
)

func tied() (joined, separate collection.Grant) {
	id, ent := collection.Key{Scope: "s", Type: 1, ID: "a"}, collection.Key{Scope: "s", Type: 3, ID: "x"}
	joined = collection.Grant{Identity: id, Entitlement: ent, Fidelity: 1,
		Via: []collection.Key{{Scope: "s", Type: 2, ID: "g>s/grouping/h"}}}
	separate = collection.Grant{Identity: id, Entitlement: ent, Fidelity: 1,
		Via: []collection.Key{{Scope: "s", Type: 2, ID: "g"}, {Scope: "s", Type: 2, ID: "h"}}}
	return joined, separate
}

func TestGrantsThatReadAlikeAreOrderedByTheirRendering(t *testing.T) {
	joined, separate := tied()
	const wantObserved = `"observed":[` +
		`{"identity":"s/identity/a","entitlement":"s/entitlement/x","fidelity":1,"via":["s/grouping/g","s/grouping/h"]},` +
		`{"identity":"s/identity/a","entitlement":"s/entitlement/x","fidelity":1,"via":["s/grouping/g~u003es/grouping/h"]}]}`
	for name, order := range map[string][]collection.Grant{"joined first": {joined, separate}, "separate first": {separate, joined}} {
		r := collection.Run{Observed: order}
		if got := string(collection.Canonical(r)); !strings.HasSuffix(got, esc(wantObserved)) {
			t.Errorf("%s: Canonical =\n%s", name, got)
		}
		if got := collection.Digest(r); got != tieGrantsDigest {
			t.Errorf("%s: Digest = %s", name, got)
		}
	}
}

func TestScopesOfOneIDAreOrderedByTheirRendering(t *testing.T) {
	one := collection.Scope{ID: "s", Status: 1, ActivityAvailable: true}
	two := collection.Scope{ID: "s", Status: 2}
	const wantScopes = `"scopes":[{"id":"s","status":1,"reason":"","activity_available":true},` +
		`{"id":"s","status":2,"reason":"","activity_available":false}],`
	for name, order := range map[string][]collection.Scope{"one first": {one, two}, "two first": {two, one}} {
		r := collection.Run{Scopes: order}
		if got := string(collection.Canonical(r)); !strings.Contains(got, wantScopes) {
			t.Errorf("%s: Canonical =\n%s", name, got)
		}
		if got := collection.Digest(r); got != tieScopesDigest {
			t.Errorf("%s: Digest = %s", name, got)
		}
	}
}

// Past twelve elements Go's sort stops being an insertion sort and may reorder
// elements that compare equal. A total order does not care.
func TestAManyWayTieHasOneDigestWhateverTheArrivalOrder(t *testing.T) {
	joined, separate := tied()
	var grants []collection.Grant
	var scopes []collection.Scope
	for i := range 20 {
		g := joined
		if i%2 == 1 {
			g = separate
		}
		g.Fidelity = 1 + int32(i%3)
		grants = append(grants, g)
		scopes = append(scopes, collection.Scope{ID: "s" + strings.Repeat("x", i%2), Status: int32(i % 5), Reason: strings.Repeat("r", i%4)})
	}
	want := collection.Digest(collection.Run{Observed: grants, Scopes: scopes})
	rng := rand.New(rand.NewPCG(9, 9))
	for range 100 {
		g := append([]collection.Grant(nil), grants...)
		s := append([]collection.Scope(nil), scopes...)
		rng.Shuffle(len(g), func(i, j int) { g[i], g[j] = g[j], g[i] })
		rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
		if got := collection.Digest(collection.Run{Observed: g, Scopes: s}); got != want {
			t.Fatal("the arrival order of tied elements reached the digest")
		}
	}
}
