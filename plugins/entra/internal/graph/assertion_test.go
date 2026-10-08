package graph_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/plugins/entra/internal/graph"
)

// selfSigned makes a throwaway key and certificate. The key is 2048 bits, the
// smallest Entra accepts, and exists only for the length of the test.
func selfSigned(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "acciew-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func bundle(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, pkcs8 bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		_ = pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	} else {
		_ = pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	}
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return buf.Bytes()
}

// The fake checks the assertion as the token service does: the signature by
// the registered certificate's key, the thumbprint, and the claims that bind
// it to this client and this endpoint. A signing bug fails here rather than
// as an unexplained AADSTS code from the operator's own tenant.
func TestACertificateSignsAnAssertionTheTokenServiceAccepts(t *testing.T) {
	for _, pkcs8 := range []bool{true, false} {
		key, cert := selfSigned(t)
		parsed, err := graph.ParseCertificate(bundle(t, key, cert, pkcs8))
		if err != nil {
			t.Fatalf("ParseCertificate(pkcs8=%v): %v", pkcs8, err)
		}
		srv := fakegraph.New(t, tenantWithUsers(1))
		srv.AcceptCertificate(testClient, cert)

		c, err := graph.Dial(context.Background(), graph.Config{
			TenantID: srv.Tenant.ID, ClientID: testClient, Certificate: parsed,
			Endpoints: graph.Endpoints{Login: srv.URL, Graph: srv.URL},
		})
		if err != nil {
			t.Fatalf("Dial with a certificate (pkcs8=%v): %v", pkcs8, err)
		}
		if _, err := graph.GetPage[graph.User](context.Background(), c, "/users"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnAssertionFromAnotherKeyIsRefused(t *testing.T) {
	registered, cert := selfSigned(t)
	_ = registered
	other, otherCert := selfSigned(t)
	parsed, err := graph.ParseCertificate(bundle(t, other, otherCert, true))
	if err != nil {
		t.Fatal(err)
	}
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.AcceptCertificate(testClient, cert)

	_, err = graph.Dial(context.Background(), graph.Config{
		TenantID: srv.Tenant.ID, ClientID: testClient, Certificate: parsed,
		Endpoints: graph.Endpoints{Login: srv.URL, Graph: srv.URL},
	})
	if err == nil || !strings.Contains(err.Error(), "AADSTS700027") {
		t.Fatalf("err = %v, want the token service's refusal", err)
	}
}

func TestACertificateBundleThatCannotSignIsExplained(t *testing.T) {
	key, cert := selfSigned(t)
	good := bundle(t, key, cert, true)
	otherKey, _ := selfSigned(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	var ec bytes.Buffer
	_ = pem.Encode(&ec, &pem.Block{Type: "PRIVATE KEY", Bytes: ecDER})
	_ = pem.Encode(&ec, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	for _, c := range []struct {
		name  string
		input []byte
		says  string
	}{
		{"nothing", nil, "PEM"},
		{"a certificate and no key", pemOnly(good, "CERTIFICATE"), "private key"},
		{"a key and no certificate", pemOnly(good, "PRIVATE KEY"), "certificate"},
		{"a key that is not the certificate's", bundle(t, otherKey, cert, true), "does not belong"},
		{"an elliptic-curve key", ec.Bytes(), "RSA"},
		{"an encrypted key", []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n" +
			string(pemOnly(good, "CERTIFICATE"))), "encrypted"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := graph.ParseCertificate(c.input)
			if err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("err = %v, want it to say %q", err, c.says)
			}
		})
	}
}

// pemOnly keeps the blocks of one type.
func pemOnly(in []byte, blockType string) []byte {
	var out bytes.Buffer
	for rest := in; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out.Bytes()
		}
		if b.Type == blockType {
			_ = pem.Encode(&out, b)
		}
	}
}
