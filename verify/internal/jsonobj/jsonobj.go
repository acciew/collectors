// Package jsonobj reads JSON the way every reader reads it. Go's decoder takes
// the last of a repeated member and matches a member name in any case, and a
// null as an empty value; a program in another language does not, and a file
// that two readers read two ways is not one that has been checked. These
// functions refuse such input, and read names exactly.
package jsonobj

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.acciew.io/collector/verify/internal/text"
)

// Members reads a JSON object into its members by exact name, each value as the
// text it was written in. It refuses anything but a single object: a repeated
// member name (however the name is spelled), data after the object, or a value
// that is not an object. Nesting is limited by the standard library to ten
// thousand levels.
func Members(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("is not JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("is not an object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("is not JSON: %w", err)
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("is not an object")
		}
		if _, again := out[name]; again {
			return nil, fmt.Errorf("repeats the member %s", quote(name))
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("is not JSON: %w", err)
		}
		out[name] = value
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, fmt.Errorf("is not JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("has data after the object")
	}
	return out, nil
}

// quote renders a name from outside for a message, quoted.
func quote(name string) string {
	return `"` + text.Show(name) + `"`
}

// String reads a JSON string. A null, a number and everything else is refused.
func String(raw []byte) (string, error) {
	var s string
	if err := decode(raw, &s, '"'); err != nil {
		return "", errors.New("is not a string")
	}
	return s, nil
}

// Uint64 reads a JSON number that is a whole number in the range of an unsigned
// 64-bit integer, written without a sign, a fraction or an exponent.
func Uint64(raw []byte) (uint64, error) {
	var n uint64
	if err := decode(raw, &n, '0'); err != nil {
		return 0, errors.New("is not a whole number from 0 to 18446744073709551615")
	}
	return n, nil
}

// Array reads a JSON array into its items, each as the text it was written in.
func Array(raw []byte) ([]json.RawMessage, error) {
	var items []json.RawMessage
	if err := decode(raw, &items, '['); err != nil {
		return nil, errors.New("is not a list")
	}
	return items, nil
}

// decode reads one JSON value, of the kind that begins with first (a digit stands
// for a number), into v. null is not a value of any kind here.
func decode(raw []byte, v any, first byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return errors.New("nothing")
	}
	switch c := raw[0]; {
	case first == '0' && (c >= '0' && c <= '9'):
	case c == first:
	default:
		return errors.New("another kind")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the value")
	}
	return nil
}
