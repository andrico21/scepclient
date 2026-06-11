package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

// ---------------------------------------------------------------------------
// Test PKI helpers — mint throwaway CA / RA / leaf certificates in-memory.
// ---------------------------------------------------------------------------

type testCert struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	der  []byte
}

func mustKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// makeCA mints a self-signed CA certificate with the given CommonName.
func makeCA(t *testing.T, cn string) testCert {
	t.Helper()
	key := mustKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return testCert{cert: cert, key: key, der: der}
}

// makeLeaf mints a certificate signed by issuer with explicit keyUsage and isCA.
func makeLeaf(t *testing.T, cn string, issuer testCert, keyUsage x509.KeyUsage, isCA bool, leafKey *rsa.PrivateKey) testCert {
	t.Helper()
	if leafKey == nil {
		leafKey = mustKey(t)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, &leafKey.PublicKey, issuer.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return testCert{cert: cert, key: leafKey, der: der}
}

// ---------------------------------------------------------------------------
// getCACaps parsing (driven through an httptest server)
// ---------------------------------------------------------------------------

func TestGetCACapsParsing(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status int
		want   caCaps
	}{
		{
			name: "full caps",
			body: "POSTPKIOperation\nAES\nSHA-256\nSHA-1\nDES3\nRenewal\n",
			want: caCaps{postSupported: true, aes: true, sha256: true, sha1: true, des3: true, renewal: true},
		},
		{
			name: "scepstandard implies aes+sha256+post",
			body: "SCEPStandard\n",
			want: caCaps{scepStandard: true, aes: true, sha256: true, postSupported: true},
		},
		{
			name: "case insensitive and whitespace",
			body: "  postpkioperation  \n\n  aes\n",
			want: caCaps{postSupported: true, aes: true},
		},
		{
			name: "des3 only",
			body: "DES3\n",
			want: caCaps{des3: true},
		},
		{
			name:   "non-200 yields empty caps",
			body:   "AES\n",
			status: http.StatusNotFound,
			want:   caCaps{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			httpClient = &http.Client{Timeout: 5 * time.Second}

			caps, err := getCACaps(srv.URL)
			if err != nil {
				t.Fatalf("getCACaps: %v", err)
			}
			if caps.postSupported != tc.want.postSupported ||
				caps.aes != tc.want.aes ||
				caps.sha256 != tc.want.sha256 ||
				caps.sha1 != tc.want.sha1 ||
				caps.des3 != tc.want.des3 ||
				caps.scepStandard != tc.want.scepStandard ||
				caps.renewal != tc.want.renewal {
				t.Errorf("caps mismatch\n got: %+v\nwant: %+v", *caps, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildCSRRaw — parse-back and signature verification
// ---------------------------------------------------------------------------

func TestBuildCSRRaw(t *testing.T) {
	key := mustKey(t)
	der, err := buildCSRRaw(key, "test-cn", "test-org", "US", "s3cr3t-challenge")
	if err != nil {
		t.Fatalf("buildCSRRaw: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "test-cn" {
		t.Errorf("CN = %q, want test-cn", csr.Subject.CommonName)
	}

	found := false
	for _, ext := range csr.Attributes { //nolint:staticcheck // deprecated but fine for test
		if ext.Type.Equal(oidChallengePassword) {
			found = true
		}
	}
	if !found {
		// Fall back to scanning the DER for the OID bytes, since Go's parser
		// does not always surface challengePassword via Attributes.
		oidDER, _ := asn1.Marshal(oidChallengePassword)
		if !containsBytes(der, oidDER) {
			t.Errorf("challengePassword OID not present in CSR")
		}
	}
}

func containsBytes(haystack, needle []byte) bool {
	return strings.Contains(string(haystack), string(needle))
}

// ---------------------------------------------------------------------------
// buildChallengePasswordAttr — DER structure
// ---------------------------------------------------------------------------

func TestBuildChallengePasswordAttr(t *testing.T) {
	der, err := buildChallengePasswordAttr("hunter2")
	if err != nil {
		t.Fatalf("buildChallengePasswordAttr: %v", err)
	}

	// Outer SEQUENCE { OID, SET { value } }
	var seq struct {
		OID   asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		t.Fatalf("unmarshal outer SEQUENCE: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("trailing bytes after SEQUENCE: %d", len(rest))
	}
	if !seq.OID.Equal(oidChallengePassword) {
		t.Errorf("OID = %v, want %v", seq.OID, oidChallengePassword)
	}
	if seq.Value.Class != asn1.ClassUniversal || seq.Value.Tag != asn1.TagSet {
		t.Errorf("value wrapper is not a universal SET (class=%d tag=%d)", seq.Value.Class, seq.Value.Tag)
	}

	// The SET contains the challenge string.
	var pw string
	if _, err := asn1.Unmarshal(seq.Value.Bytes, &pw); err != nil {
		t.Fatalf("unmarshal challenge value: %v", err)
	}
	if pw != "hunter2" {
		t.Errorf("challenge = %q, want hunter2", pw)
	}
}

// ---------------------------------------------------------------------------
// validateResponse — fatal paths return errors (no os.Exit)
// ---------------------------------------------------------------------------

func TestValidateResponse(t *testing.T) {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	txn := &scepTransaction{transactionID: "txn-abc", senderNonce: nonce}

	tests := []struct {
		name    string
		result  *certRepResult
		wantErr bool
	}{
		{
			name:    "all match",
			result:  &certRepResult{transactionID: "txn-abc", recipNonce: nonce},
			wantErr: false,
		},
		{
			name:    "transactionID mismatch",
			result:  &certRepResult{transactionID: "txn-WRONG", recipNonce: nonce},
			wantErr: true,
		},
		{
			name:    "missing recipientNonce",
			result:  &certRepResult{transactionID: "txn-abc", recipNonce: nil},
			wantErr: true,
		},
		{
			name:    "recipientNonce mismatch",
			result:  &certRepResult{transactionID: "txn-abc", recipNonce: []byte{9, 9, 9, 9}},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResponse(tc.result, txn)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// truncate — strconv.Quote sanitisation (terminal-escape injection guard)
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{name: "short string quoted", in: "ab", n: 5, want: `"ab"`},
		{name: "truncated with ellipsis", in: "abcdef", n: 3, want: `"abc..."`},
		{name: "escape byte neutralised", in: "\x1b[31mX", n: 100, want: `"\x1b[31mX"`},
		{name: "newline escaped", in: "a\nb", n: 100, want: `"a\nb"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.in, tc.n)
			if got != tc.want {
				t.Errorf("truncate(%q,%d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// selectCACerts — anchor vs encryption-recipient selection
// ---------------------------------------------------------------------------

func TestSelectCACerts(t *testing.T) {
	ca := makeCA(t, "Test CA")
	ra := makeLeaf(t, "Test RA", ca, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, false, nil)

	t.Run("prefers RA recipient with keyEncipherment", func(t *testing.T) {
		anchor, recipient, err := selectCACerts([]*x509.Certificate{ca.cert, ra.cert})
		if err != nil {
			t.Fatalf("selectCACerts: %v", err)
		}
		if !anchor.Equal(ca.cert) {
			t.Errorf("anchor = %q, want CA", anchor.Subject.CommonName)
		}
		if !recipient.Equal(ra.cert) {
			t.Errorf("recipient = %q, want RA", recipient.Subject.CommonName)
		}
	})

	t.Run("falls back to CA recipient when no RA", func(t *testing.T) {
		anchor, recipient, err := selectCACerts([]*x509.Certificate{ca.cert})
		if err != nil {
			t.Fatalf("selectCACerts: %v", err)
		}
		if !anchor.Equal(ca.cert) || !recipient.Equal(ca.cert) {
			t.Errorf("anchor/recipient should both be CA when no RA present")
		}
	})

	t.Run("error when no CA candidate", func(t *testing.T) {
		leaf := makeLeaf(t, "Just A Leaf", ca, x509.KeyUsageDigitalSignature, false, nil)
		_, _, err := selectCACerts([]*x509.Certificate{leaf.cert})
		if err == nil {
			t.Errorf("expected error when no CA candidate present")
		}
	})

	t.Run("error on empty", func(t *testing.T) {
		if _, _, err := selectCACerts(nil); err == nil {
			t.Errorf("expected error on empty cert list")
		}
	})
}

// ---------------------------------------------------------------------------
// normalizeCAFingerprint — accept/reject matrix
// ---------------------------------------------------------------------------

func TestNormalizeCAFingerprint(t *testing.T) {
	valid := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "bare 64 hex", in: valid, want: valid},
		{name: "uppercase normalised", in: strings.ToUpper(valid), want: valid},
		{name: "colon separated", in: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99", want: valid},
		{name: "surrounding whitespace", in: "  " + valid + "  ", want: valid},
		{name: "too short", in: "aabbcc", wantErr: true},
		{name: "not hex", in: strings.Repeat("zz", 32), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeCAFingerprint(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildCATrustPool — fingerprint matching and TOFU
// ---------------------------------------------------------------------------

func TestBuildCATrustPool(t *testing.T) {
	ca := makeCA(t, "Trust CA")
	ra := makeLeaf(t, "Trust RA", ca, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, false, nil)
	certs := []*x509.Certificate{ca.cert, ra.cert}

	t.Run("matching fingerprint authenticates anchor", func(t *testing.T) {
		_, anchor, err := buildCATrustPool(certs, fingerprint(ca.cert))
		if err != nil {
			t.Fatalf("buildCATrustPool: %v", err)
		}
		if !anchor.Equal(ca.cert) {
			t.Errorf("anchor = %q, want CA", anchor.Subject.CommonName)
		}
	})

	t.Run("colon-separated fingerprint also matches", func(t *testing.T) {
		fp := fingerprint(ca.cert)
		var withColons strings.Builder
		for i := 0; i < len(fp); i += 2 {
			if i > 0 {
				withColons.WriteByte(':')
			}
			withColons.WriteString(fp[i : i+2])
		}
		if _, _, err := buildCATrustPool(certs, withColons.String()); err != nil {
			t.Errorf("colon-separated fingerprint should match: %v", err)
		}
	})

	t.Run("non-matching fingerprint is fatal", func(t *testing.T) {
		other := "0000000000000000000000000000000000000000000000000000000000000000"
		if _, _, err := buildCATrustPool(certs, other); err == nil {
			t.Errorf("expected error for non-matching fingerprint")
		}
	})

	t.Run("fingerprint matching non-CA cert is rejected", func(t *testing.T) {
		_, _, err := buildCATrustPool(certs, fingerprint(ra.cert))
		if err == nil {
			t.Errorf("expected error: fingerprint matches RA (non-CA) cert")
		}
	})

	t.Run("malformed fingerprint is a localFlagError", func(t *testing.T) {
		_, _, err := buildCATrustPool(certs, "not-a-fingerprint")
		if err == nil {
			t.Fatalf("expected error for malformed fingerprint")
		}
		var lfe *localFlagError
		if !errors.As(err, &lfe) {
			t.Errorf("expected *localFlagError, got %T: %v", err, err)
		}
	})

	t.Run("absent fingerprint uses TOFU", func(t *testing.T) {
		_, anchor, err := buildCATrustPool(certs, "")
		if err != nil {
			t.Fatalf("TOFU should succeed: %v", err)
		}
		if !anchor.Equal(ca.cert) {
			t.Errorf("TOFU anchor = %q, want CA", anchor.Subject.CommonName)
		}
	})
}

// ---------------------------------------------------------------------------
// parseCertRep — CMS verification gate (forged response is rejected)
// ---------------------------------------------------------------------------

// buildCertRep constructs a SCEP CertRep: a signed message (signed by signer)
// whose authenticated attributes carry pkiStatus/messageType/transactionID/
// recipientNonce, and whose content is an EnvelopedData wrapping the issued
// certificate encrypted to recipientCert.
func buildCertRep(t *testing.T, signer testCert, pkiStatus, msgType, txnID string, recipNonce []byte, recipientCert *x509.Certificate, issuedDER []byte) []byte {
	t.Helper()

	// Inner: EnvelopedData over a degenerate SignedData carrying the issued cert.
	degenerate, err := pkcs7.DegenerateCertificate(issuedDER)
	if err != nil {
		t.Fatalf("degenerate cert: %v", err)
	}
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
	enveloped, err := pkcs7.Encrypt(degenerate, []*x509.Certificate{recipientCert})
	if err != nil {
		t.Fatalf("encrypt inner: %v", err)
	}

	// Outer: SignedData over the EnvelopedData with SCEP authenticated attrs.
	sd, err := pkcs7.NewSignedData(enveloped)
	if err != nil {
		t.Fatalf("new signed data: %v", err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	attrs := []pkcs7.Attribute{
		{Type: oidSCEPtransactionID, Value: txnID},
		{Type: oidSCEPmessageType, Value: msgType},
		{Type: oidSCEPpkiStatus, Value: pkiStatus},
	}
	if recipNonce != nil {
		attrs = append(attrs, pkcs7.Attribute{Type: oidSCEPrecipNonce, Value: recipNonce})
	}
	if err := sd.AddSigner(signer.cert, signer.key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}); err != nil {
		t.Fatalf("add signer: %v", err)
	}
	out, err := sd.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return out
}

func TestParseCertRepVerification(t *testing.T) {
	ca := makeCA(t, "Real CA")
	clientKey := mustKey(t)
	clientCert := makeLeaf(t, "client", ca, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, false, clientKey)
	issued := makeLeaf(t, "issued", ca, x509.KeyUsageDigitalSignature, false, clientKey)
	nonce := []byte{10, 20, 30, 40, 50, 60, 70, 80}
	txnID := "txn-verify"

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	t.Run("valid CertRep verifies and extracts attributes", func(t *testing.T) {
		msg := buildCertRep(t, ca, statusSUCCESS, msgTypeCertRep, txnID, nonce, clientCert.cert, issued.der)
		result, err := parseCertRep(msg, roots)
		if err != nil {
			t.Fatalf("parseCertRep: %v", err)
		}
		if result.pkiStatus != statusSUCCESS {
			t.Errorf("pkiStatus = %q, want %q", result.pkiStatus, statusSUCCESS)
		}
		if result.transactionID != txnID {
			t.Errorf("transactionID = %q, want %q", result.transactionID, txnID)
		}
	})

	t.Run("forged CertRep (different CA) fails verification", func(t *testing.T) {
		evilCA := makeCA(t, "Evil CA")
		msg := buildCertRep(t, evilCA, statusSUCCESS, msgTypeCertRep, txnID, nonce, clientCert.cert, issued.der)
		if _, err := parseCertRep(msg, roots); err == nil {
			t.Errorf("expected verification failure for forged CertRep")
		}
	})

	t.Run("wrong messageType is fatal", func(t *testing.T) {
		msg := buildCertRep(t, ca, statusSUCCESS, msgTypePKCSReq, txnID, nonce, clientCert.cert, issued.der)
		if _, err := parseCertRep(msg, roots); err == nil {
			t.Errorf("expected error for wrong messageType")
		}
	})
}

// ---------------------------------------------------------------------------
// End-to-end decrypt: parseCertRep -> decryptCertRep round-trip
// ---------------------------------------------------------------------------

func TestDecryptCertRepRoundTrip(t *testing.T) {
	ca := makeCA(t, "RT CA")
	clientKey := mustKey(t)
	clientCert := makeLeaf(t, "rt-client", ca, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, false, clientKey)
	issued := makeLeaf(t, "rt-issued", ca, x509.KeyUsageDigitalSignature, false, clientKey)

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	msg := buildCertRep(t, ca, statusSUCCESS, msgTypeCertRep, "rt-txn", []byte{1, 1, 1, 1}, clientCert.cert, issued.der)
	result, err := parseCertRep(msg, roots)
	if err != nil {
		t.Fatalf("parseCertRep: %v", err)
	}
	cert, err := decryptCertRep(result, clientCert.cert, clientKey)
	if err != nil {
		t.Fatalf("decryptCertRep: %v", err)
	}
	if pubKeyHash(cert.PublicKey) != pubKeyHash(&clientKey.PublicKey) {
		t.Errorf("decrypted issued cert pubkey does not match client key")
	}
}
