package fakeservice

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

// This file is the service's own rule for an assertion (internal/agentapi in the
// private repository), written out again so that the agent's signing is tested
// against the rule it will meet and not against itself. Where the service changes
// its rule, this changes with it.

const (
	maxAssertionLife = 2 * time.Minute
	clockSkew        = time.Minute
)

var errAssertion = errors.New("the assertion is not valid")

var kidShape = regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// Assertion is a JWT as the service reads it: the parts, not yet trusted.
type Assertion struct {
	Signed    string // header.payload, what was signed
	Signature []byte
	ID        string // the kid: tenant.agent
	Claims    struct {
		Iss    string `json:"iss"`
		Sub    string `json:"sub"`
		Aud    string `json:"aud"`
		Jti    string `json:"jti"`
		Iat    int64  `json:"iat"`
		Exp    int64  `json:"exp"`
		NewKey string `json:"new_key"`
	}
}

// ParseAssertion reads a compact JWT of the one shape an agent signs and checks what
// can be checked before the key is known: the algorithm, the id, the audience, the times.
func ParseAssertion(raw, audience string, now time.Time) (*Assertion, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errAssertion
	}
	b64 := base64.RawURLEncoding
	headJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, errAssertion
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errAssertion
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errAssertion
	}
	var head struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	a := &Assertion{Signed: parts[0] + "." + parts[1], Signature: sig}
	if json.Unmarshal(headJSON, &head) != nil || json.Unmarshal(body, &a.Claims) != nil {
		return nil, errAssertion
	}
	if head.Alg != "EdDSA" || kidShape.FindStringSubmatch(head.Kid) == nil {
		return nil, errAssertion
	}
	c := a.Claims
	switch {
	case c.Iss != head.Kid || c.Sub != head.Kid, c.Aud != audience:
		return nil, errAssertion
	case c.Jti == "" || len(c.Jti) > 128:
		return nil, errAssertion
	case c.Iat <= 0 || c.Exp <= c.Iat || c.Exp-c.Iat > int64(maxAssertionLife/time.Second):
		return nil, errAssertion
	case now.Before(time.Unix(c.Iat, 0).Add(-clockSkew)) || !now.Before(time.Unix(c.Exp, 0).Add(clockSkew)):
		return nil, errAssertion
	}
	a.ID = head.Kid
	return a, nil
}

// Verify says the key signed it.
func (a *Assertion) Verify(key []byte) bool {
	return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, []byte(a.Signed), a.Signature)
}

// Expires is when the service stops remembering the assertion's jti.
func (a *Assertion) Expires() time.Time { return time.Unix(a.Claims.Exp, 0).Add(clockSkew) }

// Fingerprint is what an agent prints and an administrator confirms: 128 bits of
// the SHA-256 of the public key, in eight groups of four hexadecimal digits.
func Fingerprint(pub []byte) string {
	return fingerprint(pub)
}
