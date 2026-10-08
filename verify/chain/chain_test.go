package chain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"go.acciew.io/collector/verify/chain"
)

// The digests are sha256 of the literal strings "first run", "second run" and
// "third run", and every chain value below was computed with
// `printf '<preimage>' | shasum -a 256`, not with this package.
const (
	d1 = "7d48a58261da7384cdc61ebe4735a8664ac5cdc8abb9d0cdcfa3e77cff58e7de"
	d2 = "791d43e21f7b8031e0a268cf4fef3379cea793a242094611c76b486ad3dd3150"
	d3 = "7639e48f6cb67b4a04ab8eefc79674becf5c3f8d1614e70fb44ab436ff973681"

	c1 = "9d5b80b6185e3ac33be500a8d82ba82d7b5e95a6d2dd303cae45064cfd25c4dc"
	c2 = "21112c55263d3ac28a443bb29db6ff17b225eb560632f68d6eba573ab2528171"
	c3 = "bfffc5468dcd41f16a86e014e01d9a29b102be7d0f980ca1591990c25f988c5f"
)

func at(t testing.TB, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("test time %q: %v", s, err)
	}
	return v
}

func log(t testing.TB) []chain.Entry {
	t.Helper()
	return []chain.Entry{
		{Sequence: 1, RecordedAt: at(t, "2026-01-02T03:04:05Z"), Digest: d1, Previous: "", Chain: c1},
		{Sequence: 2, RecordedAt: at(t, "2026-01-02T03:04:06.5Z"), Digest: d2, Previous: c1, Chain: c2},
		{Sequence: 3, RecordedAt: at(t, "2026-01-02T03:04:07.123456789Z"), Digest: d3, Previous: c2, Chain: c3},
	}
}

func TestValueIsTheSHA256OfTheFourFieldsJoinedByNewlines(t *testing.T) {
	cases := []struct {
		name     string
		sequence uint64
		at       string
		digest   string
		previous string
		preimage string
		want     string
	}{
		{"first entry, nothing before it", 1, "2026-01-02T03:04:05Z", d1, "",
			"1\n2026-01-02T03:04:05Z\n" + d1 + "\n", c1},
		{"a fraction is printed without trailing zeros", 2, "2026-01-02T03:04:06.500Z", d2, c1,
			"2\n2026-01-02T03:04:06.5Z\n" + d2 + "\n" + c1, c2},
		{"nanoseconds are kept", 3, "2026-01-02T03:04:07.123456789Z", d3, c2,
			"3\n2026-01-02T03:04:07.123456789Z\n" + d3 + "\n" + c2, c3},
		{"another zone is written as the same instant in UTC", 1, "2026-01-02T05:04:05+02:00", d1, "",
			"1\n2026-01-02T03:04:05Z\n" + d1 + "\n", c1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The literal in this table is checked here with the standard
			// library alone, so a wrong expectation fails before the package does.
			sum := sha256.Sum256([]byte(tc.preimage))
			if got := hex.EncodeToString(sum[:]); got != tc.want {
				t.Fatalf("the table is wrong: sha256(%q) = %s, table says %s", tc.preimage, got, tc.want)
			}
			if got := chain.Value(tc.sequence, at(t, tc.at), tc.digest, tc.previous); got != tc.want {
				t.Errorf("Value = %s, want %s", got, tc.want)
			}
		})
	}
}

// Without the position, two identical runs recorded one after the other would
// chain the same way and the second would be invisible.
func TestEveryFieldReachesTheValue(t *testing.T) {
	base := chain.Value(2, at(t, "2026-01-02T03:04:06Z"), d2, c1)
	changed := map[string]string{
		"sequence": chain.Value(3, at(t, "2026-01-02T03:04:06Z"), d2, c1),
		"time":     chain.Value(2, at(t, "2026-01-02T03:04:07Z"), d2, c1),
		"digest":   chain.Value(2, at(t, "2026-01-02T03:04:06Z"), d3, c1),
		"previous": chain.Value(2, at(t, "2026-01-02T03:04:06Z"), d2, c2),
	}
	for field, got := range changed {
		if got == base {
			t.Errorf("changing the %s left the chain value as it was", field)
		}
	}
}

func TestAnUntouchedLogHolds(t *testing.T) {
	if err := chain.Check(log(t)); err != nil {
		t.Errorf("Check: %v", err)
	}
	if err := chain.Check(nil); err != nil {
		t.Errorf("an empty log has nothing to disagree with: %v", err)
	}
}

func TestCheckNamesWhatIsWrong(t *testing.T) {
	cases := []struct {
		name   string
		change func([]chain.Entry) []chain.Entry
		reason chain.Reason
		at     uint64
	}{
		{"an entry missing from the middle", func(e []chain.Entry) []chain.Entry {
			return []chain.Entry{e[0], e[2]}
		}, chain.ReasonSequence, 3},
		{"the first entry missing", func(e []chain.Entry) []chain.Entry {
			return e[1:]
		}, chain.ReasonSequence, 2},
		{"two entries swapped", func(e []chain.Entry) []chain.Entry {
			return []chain.Entry{e[0], e[2], e[1]}
		}, chain.ReasonSequence, 3},
		{"an entry repeated", func(e []chain.Entry) []chain.Entry {
			return []chain.Entry{e[0], e[1], e[1], e[2]}
		}, chain.ReasonSequence, 2},
		{"the first entry claims a predecessor", func(e []chain.Entry) []chain.Entry {
			e[0].Previous = c3
			return e
		}, chain.ReasonLink, 1},
		{"an entry linked to the wrong predecessor", func(e []chain.Entry) []chain.Entry {
			e[2].Previous = c1
			return e
		}, chain.ReasonLink, 3},
		{"a digest edited", func(e []chain.Entry) []chain.Entry {
			e[1].Digest = d3
			return e
		}, chain.ReasonValue, 2},
		{"a time edited", func(e []chain.Entry) []chain.Entry {
			e[1].RecordedAt = e[1].RecordedAt.Add(time.Second)
			return e
		}, chain.ReasonValue, 2},
		{"a chain value edited", func(e []chain.Entry) []chain.Entry {
			e[0].Chain = c2
			return e
		}, chain.ReasonValue, 1},
		{"a chain value emptied", func(e []chain.Entry) []chain.Entry {
			e[2].Chain = ""
			return e
		}, chain.ReasonValue, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := chain.Check(tc.change(log(t)))
			var fault *chain.Error
			if !errors.As(err, &fault) {
				t.Fatalf("Check = %v, want a *chain.Error", err)
			}
			if fault.Reason != tc.reason || fault.Sequence != tc.at {
				t.Errorf("fault = %s at entry %d, want %s at entry %d (%v)",
					fault.Reason, fault.Sequence, tc.reason, tc.at, err)
			}
		})
	}
}

// Cutting entries off the end leaves every remaining link intact: the chain
// cannot see it, which is what the anchor is for.
func TestTheChainAloneCannotSeeItsTailBeingCut(t *testing.T) {
	if err := chain.Check(log(t)[:2]); err != nil {
		t.Errorf("Check on a log cut at the tail: %v", err)
	}
}

// A failure says the file and its chain disagree. It must not say more than
// that: who changed what, and when, is not something a chain can show.
func TestAFaultDoesNotClaimToKnowWhoOrWhy(t *testing.T) {
	entries := log(t)
	entries[1].Digest = d3
	err := chain.Check(entries)
	if err == nil {
		t.Fatal("no fault")
	}
	for _, word := range []string{"tamper", "forged", "attack", "fraud"} {
		if strings.Contains(strings.ToLower(err.Error()), word) {
			t.Errorf("%q: the message says more than a chain can know", err)
		}
	}
	if !strings.Contains(err.Error(), "entry 2") {
		t.Errorf("%q does not say which entry", err)
	}
}

// A chain value comes from the file being checked. It is printed as a quoted,
// shortened token, never as raw text that could carry control characters.
func TestAFaultQuotesWhatItQuotesFromTheFile(t *testing.T) {
	entries := log(t)
	entries[2].Previous = "\x1b[31mred\u202e" + strings.Repeat("a", 100)
	err := chain.Check(entries)
	if err == nil {
		t.Fatal("no fault")
	}
	if strings.ContainsAny(err.Error(), "\x1b\u202e") {
		t.Errorf("%q carries a control or direction character from the file", err)
	}
	if len(err.Error()) > 300 {
		t.Errorf("a %d-byte message: a line of the file went into it whole", len(err.Error()))
	}
}

// A reader that streams a log checks one entry at a time and must reach the
// same verdict as Check on the whole.
func TestCheckEntryChecksOneEntryAgainstWhatCameBefore(t *testing.T) {
	entries := log(t)
	if err := chain.CheckEntry(2, c1, entries[1]); err != nil {
		t.Errorf("CheckEntry: %v", err)
	}
	for name, err := range map[string]error{
		"wrong position": chain.CheckEntry(3, c1, entries[1]),
		"wrong previous": chain.CheckEntry(2, c2, entries[1]),
	} {
		if err == nil {
			t.Errorf("%s: no fault", name)
		}
	}
}
