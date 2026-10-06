package collector

import (
	"bytes"
	"errors"
	"testing"
)

// A downloaded collector has to be able to say which one it is without a host
// to talk to, or the only way to learn a release's version is to trust the
// file name.
func TestAskedForItsVersionACollectorSaysWhichItIs(t *testing.T) {
	var out bytes.Buffer
	if err := printVersion(&out, &fake{}); err != nil {
		t.Fatalf("printVersion: %v", err)
	}
	if got, want := out.String(), "fake 0.0.1\n"; got != want {
		t.Errorf("printed %q, want %q", got, want)
	}
}

func TestAVersionIsNotMadeUpWhenTheCollectorCannotDescribeItself(t *testing.T) {
	var out bytes.Buffer
	c := &fake{describe: func() (*Description, error) { return nil, errors.New("no") }}
	if err := printVersion(&out, c); err == nil {
		t.Error("printVersion succeeded though Describe failed")
	}
	if out.Len() != 0 {
		t.Errorf("printed %q before failing", out.String())
	}
}
