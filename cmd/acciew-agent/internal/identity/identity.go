// Package identity is the agent's key and what it signs with it: the assertion that
// trades for an access token, and the request that changes the key. The private key
// never leaves the host; the service holds only the public half.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// AssertionLife is how long an assertion is good for. The service accepts up to two minutes.
const AssertionLife = 60 * time.Second

var idShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// PublicKey is the public half of a private key.
func PublicKey(key ed25519.PrivateKey) ed25519.PublicKey {
	pub, _ := key.Public().(ed25519.PublicKey)
	return pub
}

// GenerateKey makes a key pair.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

// Fingerprint is what the agent prints and an administrator confirms: the first 128 bits
// of the SHA-256 of the public key, in eight groups of four hexadecimal digits. The
// service computes it the same way, so a key swapped on the way shows a different one.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:16])
	groups := make([]string, 8)
	for i := range groups {
		groups[i] = h[i*4 : i*4+4]
	}
	return strings.Join(groups, "-")
}

// Signer signs for one agent.
type Signer struct {
	ID  string // tenant.agent
	Key ed25519.PrivateKey
	// Now and Rand are for tests; nil is the clock and the system's randomness.
	Now  func() time.Time
	Rand io.Reader
}

// NewSigner checks the id is the shape the service gives out, so a stored file that
// is not one is found here and not by a 401.
func NewSigner(id string, key ed25519.PrivateKey) (*Signer, error) {
	if !idShape.MatchString(id) {
		return nil, fmt.Errorf("%q is not an agent id (tenant.agent)", id)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("the key is not an Ed25519 private key")
	}
	return &Signer{ID: id, Key: key}, nil
}

func (s *Signer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type claims struct {
	Iss    string `json:"iss"`
	Sub    string `json:"sub"`
	Aud    string `json:"aud"`
	Jti    string `json:"jti"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
	NewKey string `json:"new_key,omitempty"`
}

// TokenAssertion is the assertion for POST /agent/v1/token.
func (s *Signer) TokenAssertion(base string) (string, error) {
	return s.assertion(audience(base, "/agent/v1/token"), "")
}

// RotationRequest is the assertion for POST /agent/v1/rotate, signed with this key and
// naming next, and next's signature over the same bytes.
func (s *Signer) RotationRequest(base string, next ed25519.PrivateKey) (assertion, newKeySignature string, err error) {
	if len(next) != ed25519.PrivateKeySize {
		return "", "", errors.New("the new key is not an Ed25519 private key")
	}
	pub := PublicKey(next)
	assertion, err = s.assertion(audience(base, "/agent/v1/rotate"), base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		return "", "", err
	}
	signed := assertion[:strings.LastIndexByte(assertion, '.')]
	return assertion, base64.RawURLEncoding.EncodeToString(ed25519.Sign(next, []byte(signed))), nil
}

// audience is the service's address and the path, exactly: the service compares them as strings.
func audience(base, path string) string { return strings.TrimRight(base, "/") + path }

func (s *Signer) assertion(aud, newKey string) (string, error) {
	jti := make([]byte, 18)
	r := s.Rand
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, jti); err != nil {
		return "", fmt.Errorf("making an assertion id: %w", err)
	}
	now := s.now()
	head, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": s.ID})
	body, err := json.Marshal(claims{
		Iss: s.ID, Sub: s.ID, Aud: aud, Jti: base64.RawURLEncoding.EncodeToString(jti),
		Iat: now.Unix(), Exp: now.Add(AssertionLife).Unix(), NewKey: newKey,
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signed := enc.EncodeToString(head) + "." + enc.EncodeToString(body)
	return signed + "." + enc.EncodeToString(ed25519.Sign(s.Key, []byte(signed))), nil
}
