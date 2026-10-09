package jsonobj_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.acciew.io/collector/verify/internal/jsonobj"
)

func TestMembersReadsAnObjectByExactName(t *testing.T) {
	m, err := jsonobj.Members([]byte(` {"a":1,"B":[1,{"x":2}],"c":{"d":"e"},"n":null} `))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 4 || string(m["a"]) != "1" || string(m["B"]) != `[1,{"x":2}]` || string(m["c"]) != `{"d":"e"}` || string(m["n"]) != "null" {
		t.Errorf("members = %v", m)
	}
	if _, ok := m["b"]; ok {
		t.Error("a name was matched in another case")
	}
	if m, err := jsonobj.Members([]byte(`{}`)); err != nil || len(m) != 0 {
		t.Errorf("empty object: %v, %v", m, err)
	}
}

// What one reader takes one way another takes another.
func TestMembersRefusesWhatWouldBeReadTwoWays(t *testing.T) {
	cases := map[string]string{
		"a repeated member":          `{"a":1,"a":2}`,
		"a repeated member, quoted":  `{"a":1,"` + "\\" + `u0061":2}`,
		"not an object: array":       `[1]`,
		"not an object: string":      `"x"`,
		"not an object: null":        `null`,
		"not JSON":                   `{`,
		"nothing":                    ``,
		"data after the object":      `{"a":1} {"b":2}`,
		"garbage after the object":   `{"a":1} x`,
		"a member without a value":   `{"a"}`,
		"a trailing comma":           `{"a":1,}`,
		"a number for a name":        `{1:2}`,
		"an unterminated nested one": `{"a":{"b":1}`,
	}
	for name, in := range cases {
		if _, err := jsonobj.Members([]byte(in)); err == nil {
			t.Errorf("%s: read %q", name, in)
		}
	}
}

func TestARepeatedMemberIsNamed(t *testing.T) {
	_, err := jsonobj.Members([]byte(`{"type":"x","type":"y"}`))
	if err == nil || !strings.Contains(err.Error(), `repeats the member "type"`) {
		t.Errorf("error = %v", err)
	}
	// A name from outside is quoted when a terminal would obey it.
	_, err = jsonobj.Members([]byte(`{"a` + "\\" + `u001b[2J":1,"a` + "\\" + `u001b[2J":2}`))
	if err == nil || strings.Contains(err.Error(), "\x1b") {
		t.Errorf("error = %q", err)
	}
}

// The standard library stops at ten thousand levels, and so does this.
func TestMembersDoesNotFollowAnObjectIntoTheGround(t *testing.T) {
	deep := `{"a":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`
	if _, err := jsonobj.Members([]byte(deep)); err == nil {
		t.Error("an object 20000 levels deep was read")
	}
	ok := `{"a":` + strings.Repeat("[", 500) + strings.Repeat("]", 500) + `}`
	if _, err := jsonobj.Members([]byte(ok)); err != nil {
		t.Errorf("500 levels: %v", err)
	}
}

func TestString(t *testing.T) {
	for in, want := range map[string]string{`"x"`: "x", `""`: "", `"a<b"`: "a<b"} {
		got, err := jsonobj.String([]byte(in))
		if err != nil || got != want {
			t.Errorf("String(%s) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{`null`, `1`, `true`, `["x"]`, `{}`, ``, `"x`} {
		if _, err := jsonobj.String([]byte(in)); err == nil {
			t.Errorf("String(%s) was read", in)
		}
	}
}

func TestUint64(t *testing.T) {
	for in, want := range map[string]uint64{`0`: 0, `7`: 7, `18446744073709551615`: 1<<64 - 1} {
		got, err := jsonobj.Uint64([]byte(in))
		if err != nil || got != want {
			t.Errorf("Uint64(%s) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{`null`, `-1`, `1.0`, `1e2`, `"1"`, `18446744073709551616`, `01`, `+1`, ``, `true`} {
		if _, err := jsonobj.Uint64([]byte(in)); err == nil {
			t.Errorf("Uint64(%s) was read", in)
		}
	}
}

func TestArray(t *testing.T) {
	items, err := jsonobj.Array([]byte(`[1,"a",{"b":[2]},null]`))
	if err != nil || len(items) != 4 || string(items[2]) != `{"b":[2]}` || string(items[3]) != "null" {
		t.Errorf("Array = %q, %v", items, err)
	}
	if items, err := jsonobj.Array([]byte(`[]`)); err != nil || len(items) != 0 {
		t.Errorf("empty array = %q, %v", items, err)
	}
	for _, in := range []string{`null`, `{}`, `"x"`, `1`, `[1,]`, `[1] [2]`, `[`, ``} {
		if _, err := jsonobj.Array([]byte(in)); err == nil {
			t.Errorf("Array(%s) was read", in)
		}
	}
}

// The decoder says it in its own words; callers want the member.
func TestUnknownMemberIsTheMemberADecoderRefused(t *testing.T) {
	var v struct{ A int }
	dec := json.NewDecoder(strings.NewReader(`{"A":1,"extra":2}`))
	dec.DisallowUnknownFields()
	err := dec.Decode(&v)
	if name, ok := jsonobj.UnknownMember(err); !ok || name != "extra" {
		t.Errorf("UnknownMember(%v) = %q, %v", err, name, ok)
	}
	wrapped := fmt.Errorf("is not an entry: %w", err)
	if name, ok := jsonobj.UnknownMember(wrapped); !ok || name != "extra" {
		t.Errorf("wrapped: %q, %v", name, ok)
	}
	// A name with a quote and an escape in it is the name, not its spelling.
	dec = json.NewDecoder(strings.NewReader(`{"a\"bA":2}`))
	dec.DisallowUnknownFields()
	if name, ok := jsonobj.UnknownMember(dec.Decode(&v)); !ok || name != `a"bA` {
		t.Errorf("UnknownMember = %q, %v", name, ok)
	}
	for _, other := range []error{nil, errors.New("something else"), errors.New(`json: unknown field `), errors.New(`json: unknown field x`)} {
		if name, ok := jsonobj.UnknownMember(other); ok {
			t.Errorf("UnknownMember(%v) = %q", other, name)
		}
	}
}
