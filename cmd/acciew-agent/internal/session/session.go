// Package session is the agent holding an access token: it signs an assertion when it has no
// good token, keeps the token until a minute before it ends, and asks again when the service
// says it is no longer good. Concurrent callers share one token.
package session

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
	"go.acciew.io/collector/cmd/acciew-agent/internal/state"
)

// Session is one agent's standing with the service.
type Session struct {
	Client *client.Client
	State  *state.State
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu        sync.Mutex
	signer    *identity.Signer
	tok       string
	refreshAt time.Time
}

// New checks that the stored id and key can sign.
func New(c *client.Client, st *state.State) (*Session, error) {
	signer, err := identity.NewSigner(st.AgentID, st.Key)
	if err != nil {
		return nil, err
	}
	return &Session{Client: c, State: st, signer: signer}, nil
}

// Fingerprint is the fingerprint of the key the agent is using, as an administrator confirms it.
func (s *Session) Fingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return identity.Fingerprint(identity.PublicKey(s.signer.Key))
}

func (s *Session) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// staleAfter is how long a pending key may wait before it is taken for the remains of a rotation
// that ended without it: a rotation in another process is over in seconds.
const staleAfter = 5 * time.Minute

func refused(err error) bool {
	var e *client.APIError
	return errors.As(err, &e) && e.Status == http.StatusUnauthorized
}

// Token returns an access token that is good for at least a minute more, asking for one if
// need be. A 403 from the service (pending, revoked) comes back as it came.
func (s *Session) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok != "" && s.now().Before(s.refreshAt) {
		return s.tok, nil
	}
	tok, err := s.ask(ctx, s.signer)
	if refused(err) {
		// The key may have been changed from another terminal: `acciew-agent rotate` while this runs.
		if changed, rerr := s.State.Reload(); rerr == nil && changed {
			next, nerr := identity.NewSigner(s.State.AgentID, s.State.Key)
			if nerr != nil {
				return "", nerr
			}
			s.signer = next
			tok, err = s.ask(ctx, s.signer)
		}
	}
	if refused(err) && s.State.Next != nil {
		// A rotation was begun and its end is not known. If the service took the new
		// key the old one no longer works, and the new one does.
		return s.tryNext(ctx, err)
	}
	if err == nil && s.State.Next != nil {
		// The key works. A pending one the service never took is dropped, once it is too old to be
		// a rotation still under way in another process.
		if age, ok := s.State.NextAge(); ok && age > staleAfter {
			if aerr := s.State.AbandonRotation(); aerr != nil {
				return "", aerr
			}
		}
	}
	return tok, err
}

func (s *Session) tryNext(ctx context.Context, refusal error) (string, error) {
	next, err := identity.NewSigner(s.State.AgentID, s.State.Next)
	if err != nil {
		return "", err
	}
	tok, err := s.ask(ctx, next)
	if err != nil {
		return "", refusal
	}
	if cerr := s.State.CommitRotation(identity.Fingerprint(identity.PublicKey(s.State.Next))); cerr != nil {
		return "", cerr
	}
	s.signer = next
	return tok, nil
}

// ask signs and trades, and keeps the token it gets.
func (s *Session) ask(ctx context.Context, signer *identity.Signer) (string, error) {
	assertion, err := signer.TokenAssertion(s.Client.Base)
	if err != nil {
		return "", err
	}
	got, err := s.Client.Token(ctx, assertion)
	if err != nil {
		return "", err
	}
	life := got.ExpiresIn
	if life <= 0 {
		life = max(0, got.ExpiresAt.Sub(s.now()))
	}
	s.tok, s.refreshAt = got.Token, s.now().Add(life-min(time.Minute, life/2))
	return got.Token, nil
}

// Do runs fn with a token. If the service answers 401 the token is dropped, a new one is
// asked for, and fn is tried once more.
func (s *Session) Do(ctx context.Context, fn func(token string) error) error {
	tok, err := s.Token(ctx)
	if err != nil {
		return err
	}
	err = fn(tok)
	var refused *client.APIError
	if !errors.As(err, &refused) || refused.Status != http.StatusUnauthorized {
		return err
	}
	s.Invalidate(tok)
	if tok, err = s.Token(ctx); err != nil {
		return err
	}
	return fn(tok)
}

// Invalidate drops a token the service refused, if it is still the one held.
func (s *Session) Invalidate(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok == tok {
		s.tok = ""
	}
}
