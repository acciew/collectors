package graph

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Certificate is an RSA key and the certificate registered for it, used to
// sign the client assertion that stands in for a secret.
//
// The standard library is enough: an assertion is a JWT signed with PS256 and
// carrying the certificate's SHA-256 thumbprint, and pulling in an
// authentication library to build one would put its whole dependency tree in
// front of whoever audits this collector.
type Certificate struct {
	key        *rsa.PrivateKey
	thumbprint string
}

// ParseCertificate reads a PEM bundle holding one private key (PKCS#8 or
// PKCS#1) and the certificate registered for it.
//
// An encrypted key is refused: decrypting it needs a passphrase, which would
// be a second secret to configure, and nothing here would be able to ask for
// it.
func ParseCertificate(bundle []byte) (*Certificate, error) {
	var key *rsa.PrivateKey
	var cert *x509.Certificate
	sawKey := false
	for rest := bundle; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("the private key is encrypted; supply an unencrypted key, protected by the file's permissions")
		case "PRIVATE KEY":
			sawKey = true
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("reading the private key: %w", err)
			}
			rsaKey, ok := parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("the private key is not an RSA key; Entra signs assertions with PS256, which needs RSA")
			}
			key = rsaKey
		case "RSA PRIVATE KEY":
			sawKey = true
			parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("reading the private key: %w", err)
			}
			key = parsed
		case "CERTIFICATE":
			if cert != nil {
				continue // the first is the leaf; any others are its chain
			}
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("reading the certificate: %w", err)
			}
			cert = parsed
		}
	}
	switch {
	case !sawKey && cert == nil:
		return nil, errors.New("no PEM blocks found; expected a private key and its certificate")
	case !sawKey:
		return nil, errors.New("the bundle holds a certificate and no private key")
	case cert == nil:
		return nil, errors.New("the bundle holds a private key and no certificate; the certificate's thumbprint names the key to Entra")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("the private key does not belong to the certificate")
	}
	sum := sha256.Sum256(cert.Raw)
	return &Certificate{key: key, thumbprint: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// assertionLifetime is how long an assertion is valid. It is used once, at
// once, so it need only outlast clock skew.
const assertionLifetime = 10 * time.Minute

// assertion signs a client assertion for the token endpoint.
func (c *Certificate) assertion(clientID, audience string, now time.Time) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": c.thumbprint})
	claims, _ := json.Marshal(map[string]any{
		"aud": audience, "iss": clientID, "sub": clientID,
		"jti": fmt.Sprintf("%x", jti),
		"nbf": now.Unix(), "iat": now.Unix(), "exp": now.Add(assertionLifetime).Unix(),
	})
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPSS(rand.Reader, c.key, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
