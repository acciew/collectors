package identity_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/fakeservice"
	"go.acciew.io/collector/cmd/acciew-agent/internal/identity"
)

const (
	agentID = "0a1b2c3d-0000-4000-8000-000000000001.9f8e7d6c-0000-4000-8000-000000000002"
	base    = "https://acciew.example.test"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func signer(t *testing.T) (*identity.Signer, ed25519.PublicKey) {
	t.Helper()
	key, err := identity.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := identity.NewSigner(agentID, key)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return now }
	return s, identity.PublicKey(key)
}

// The fingerprint is what a human compares across two screens, so it is pinned to a
// worked example and not to a second copy of the code that makes it.
func TestTheFingerprintOfAKeyIsEightGroupsOfItsDigest(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	if got, want := identity.Fingerprint(pub), "630d-cd29-66c4-3366-9112-5448-bbb2-5b4f"; got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
}

func TestAnAssertionForTheTokenAddressIsOneTheServiceAccepts(t *testing.T) {
	s, pub := signer(t)
	raw, err := s.TokenAssertion(base)
	if err != nil {
		t.Fatal(err)
	}
	a, err := fakeservice.ParseAssertion(raw, base+"/agent/v1/token", now)
	if err != nil {
		t.Fatalf("the service's rule refuses it: %v", err)
	}
	if !a.Verify(pub) {
		t.Error("the signature is not the key's")
	}
	if a.ID != agentID || a.Claims.Iss != agentID || a.Claims.Sub != agentID {
		t.Errorf("kid, iss and sub should all be the agent id: %q %q %q", a.ID, a.Claims.Iss, a.Claims.Sub)
	}
	if life := a.Claims.Exp - a.Claims.Iat; life != 60 {
		t.Errorf("an assertion lasts %d seconds, want 60", life)
	}
	if a.Claims.NewKey != "" {
		t.Error("a token assertion names no new key")
	}
}

func TestTheHeaderNamesEdDSAAndJWTAndNothingElse(t *testing.T) {
	s, _ := signer(t)
	raw, _ := s.TokenAssertion(base)
	head, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(head, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": agentID}
	if len(got) != len(want) || got["alg"] != "EdDSA" || got["typ"] != "JWT" || got["kid"] != agentID {
		t.Errorf("header = %v, want %v", got, want)
	}
}

// The service refuses an assertion it has seen, so two must never be the same.
func TestEveryAssertionHasAFreshJti(t *testing.T) {
	s, _ := signer(t)
	seen := map[string]bool{}
	for range 50 {
		raw, _ := s.TokenAssertion(base)
		a, err := fakeservice.ParseAssertion(raw, base+"/agent/v1/token", now)
		if err != nil {
			t.Fatal(err)
		}
		if seen[a.Claims.Jti] {
			t.Fatalf("jti %q was used twice", a.Claims.Jti)
		}
		seen[a.Claims.Jti] = true
	}
}

// The audience is compared exactly, so an address typed with a trailing slash
// must not become part of it, and an assertion for one service is no use at another.
func TestTheAudienceIsTheAddressExactly(t *testing.T) {
	s, _ := signer(t)
	raw, _ := s.TokenAssertion(base + "/")
	if _, err := fakeservice.ParseAssertion(raw, base+"/agent/v1/token", now); err != nil {
		t.Errorf("a trailing slash in the address changed the audience: %v", err)
	}
	if _, err := fakeservice.ParseAssertion(raw, "https://other.example.test/agent/v1/token", now); err == nil {
		t.Error("an assertion for one service was accepted by another")
	}
	if _, err := fakeservice.ParseAssertion(raw, base+"/agent/v1/rotate", now); err == nil {
		t.Error("a token assertion was accepted as a rotation")
	}
}

func TestAnAgentIdThatIsNotTenantDotAgentIsRefusedBeforeAnythingIsSigned(t *testing.T) {
	key, _ := identity.GenerateKey()
	for _, id := range []string{"", "agent-1", agentID + "x", strings.ToUpper(agentID), strings.Replace(agentID, ".", "-", 1)} {
		if _, err := identity.NewSigner(id, key); err == nil {
			t.Errorf("NewSigner accepted %q", id)
		}
	}
}

func TestAnAssertionIsOnlyGoodForItsMinute(t *testing.T) {
	s, _ := signer(t)
	raw, _ := s.TokenAssertion(base)
	// The service allows a minute of difference between the clocks on either side.
	for _, c := range []struct {
		at time.Time
		ok bool
	}{
		{now.Add(-59 * time.Second), true},
		{now.Add(2*time.Minute - time.Second), true},
		{now.Add(2*time.Minute + time.Second), false},
		{now.Add(-61 * time.Second), false},
	} {
		_, err := fakeservice.ParseAssertion(raw, base+"/agent/v1/token", c.at)
		if (err == nil) != c.ok {
			t.Errorf("at %v: accepted = %v, want %v", c.at.Sub(now), err == nil, c.ok)
		}
	}
}

func TestARotationIsSignedByTheOldKeyAndTheNewKeySignsTheSameBytes(t *testing.T) {
	s, oldPub := signer(t)
	next, err := identity.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, newSig, err := s.RotationRequest(base, next)
	if err != nil {
		t.Fatal(err)
	}
	a, err := fakeservice.ParseAssertion(raw, base+"/agent/v1/rotate", now)
	if err != nil {
		t.Fatalf("the service's rule refuses it: %v", err)
	}
	if !a.Verify(oldPub) {
		t.Error("the old key did not sign the assertion")
	}
	gotNew, err := base64.StdEncoding.DecodeString(a.Claims.NewKey)
	if err != nil || !ed25519.PublicKey(gotNew).Equal(next.Public()) {
		t.Errorf("new_key = %q, want the standard base64 of the new public key (%v)", a.Claims.NewKey, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(newSig)
	if err != nil || !ed25519.Verify(identity.PublicKey(next), []byte(a.Signed), sig) {
		t.Errorf("the new key's signature is not over header.payload (%v)", err)
	}
	if _, err := fakeservice.ParseAssertion(raw, base+"/agent/v1/token", now); err == nil {
		t.Error("a rotation request was accepted as a token request")
	}
}

func TestARotationToSomethingThatIsNotAKeyIsRefused(t *testing.T) {
	s, _ := signer(t)
	if _, _, err := s.RotationRequest(base, ed25519.PrivateKey("short")); err == nil {
		t.Error("a rotation to a 5-byte key was signed")
	}
	if _, err := identity.NewSigner(agentID, ed25519.PrivateKey("short")); err == nil {
		t.Error("a signer was made from a 5-byte key")
	}
}
