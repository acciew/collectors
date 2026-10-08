// Package lifecycle is the two things an agent does to its own identity: enrol, and rotate its key.
package lifecycle

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
	"go.acciew.io/collector/cmd/acciew-agent/internal/session"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
)

// Protocol is the version of /agent/v1 this agent speaks, sent at enrolment.
const Protocol = "1"

// Enrollment is what the human gave the agent.
type Enrollment struct {
	URL, Token, Name, StateDir, Version string
	Out                                 io.Writer
}

// Enroll makes a key, registers its public half with the single-use token, and stores the
// key and where it was registered. It prints the fingerprint for an administrator to confirm.
func Enroll(ctx context.Context, e Enrollment) error {
	c, err := client.New(e.URL, e.Version)
	if err != nil {
		return err
	}
	// Before anything is spent: the token is good once, and a directory that would refuse the
	// key afterwards would waste it.
	if state.Exists(e.StateDir) {
		return fmt.Errorf("%w: %s (use another --state-dir, or remove it to enrol again)", state.ErrEnrolled, e.StateDir)
	}
	name := e.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	key, err := identity.GenerateKey()
	if err != nil {
		return err
	}
	pub := identity.PublicKey(key)
	got, err := c.Enroll(ctx, client.EnrollRequest{
		Token: e.Token, Name: name, PublicKey: base64.StdEncoding.EncodeToString(pub),
		Versions: map[string]string{"agent": e.Version, "protocol": Protocol},
	})
	if err != nil {
		var refused *client.APIError
		if errors.As(err, &refused) && refused.Status == http.StatusUnauthorized {
			return errors.New("the service did not accept the enrolment token: it is single-use and good for an hour, so ask an administrator for a new one")
		}
		return fmt.Errorf("enrolling: %w", err)
	}
	local := identity.Fingerprint(pub)
	if !strings.EqualFold(got.Fingerprint, local) {
		return fmt.Errorf("the service reported a different fingerprint (%s) from this agent's key (%s): "+
			"something between here and the service changed the key, or used the token first. Nothing was stored; "+
			"ask for a new token and enrol from a network you trust", got.Fingerprint, local)
	}
	if _, err := identity.NewSigner(got.AgentID, key); err != nil {
		return fmt.Errorf("the service gave an agent id this agent cannot use: %w", err)
	}
	cfg := state.Config{URL: c.Base, AgentID: got.AgentID, Name: name, Fingerprint: local}
	if err := state.Create(e.StateDir, cfg, key); err != nil {
		return fmt.Errorf("the service registered this agent as %s, but its key could not be stored: %w; delete the agent in the service and enrol again", got.AgentID, err)
	}
	_, _ = fmt.Fprintf(e.Out, `Enrolled as agent %s.

  Fingerprint: %s

Give this fingerprint to a tenant administrator, who confirms it in the service. Until
then this agent is offered no work. Compare it with what the service shows, character
for character: if they differ, do not confirm it.

Then start the agent:  acciew-agent run --state-dir %s
`, got.AgentID, local, e.StateDir)
	return nil
}

// RotationOf names the agent whose key is to change.
type RotationOf struct {
	StateDir, Version string
	Out               io.Writer
}

// Rotate registers a new key, signed for by the old one, and swaps it in only once the
// service has taken it.
func Rotate(ctx context.Context, r RotationOf) error {
	st, err := state.Load(r.StateDir)
	if err != nil {
		return err
	}
	// One rotation at a time, for the whole of it: two would overwrite each other's pending key.
	// A running agent is not in the way; it finds the new key on disk.
	unlock, err := state.LockRotation(r.StateDir)
	if err != nil {
		return err
	}
	defer unlock()
	// Read again under the lock: another rotation may have finished while this one waited.
	if _, err := st.Reload(); err != nil {
		return err
	}
	c, err := client.New(st.URL, r.Version)
	if err != nil {
		return err
	}
	sess, err := session.New(c, st)
	if err != nil {
		return err
	}
	// Proves the agent is known and confirmed, and settles any rotation left unfinished.
	if _, err := sess.Token(ctx); err != nil {
		return fmt.Errorf("the service does not accept this agent as it is, so its key cannot be changed: %w", err)
	}
	next, err := identity.GenerateKey()
	if err != nil {
		return err
	}
	nextPub := identity.PublicKey(next)
	signer, err := identity.NewSigner(st.AgentID, st.Key)
	if err != nil {
		return err
	}
	assertion, newSig, err := signer.RotationRequest(c.Base, next)
	if err != nil {
		return err
	}
	// Stored first: if the service takes the key and the answer is lost, the agent still
	// holds the key it now needs.
	if err := st.BeginRotation(next); err != nil {
		return err
	}
	got, err := c.Rotate(ctx, assertion, newSig)
	if err != nil {
		var refused *client.APIError
		if errors.As(err, &refused) && refused.Status < 500 {
			if aerr := st.AbandonRotation(); aerr != nil {
				return errors.Join(err, aerr)
			}
			return fmt.Errorf("the service refused the new key; the old one is kept: %w", err)
		}
		return fmt.Errorf("whether the service took the new key is not known (%w): both keys are kept, and `acciew-agent run` "+
			"or another `acciew-agent rotate` settles it", err)
	}
	local := identity.Fingerprint(nextPub)
	if !strings.EqualFold(got.Fingerprint, local) {
		return fmt.Errorf("the service reported a different fingerprint (%s) from the new key's (%s): both keys are kept until one of them is found to work", got.Fingerprint, local)
	}
	if err := st.CommitRotation(local); err != nil {
		return fmt.Errorf("the service took the new key but it could not be put in place: %w (it is in %s/agent.key.next)", err, st.Dir)
	}
	_, _ = fmt.Fprintf(r.Out, "The key is changed. The new fingerprint is %s.\nThe agent stays confirmed; the access tokens the old key got have stopped working, and the agent asks for new ones.\n", local)
	return nil
}
