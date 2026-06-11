// scepclient — Minimal SCEP client implementing RFC 8894
// Uses only github.com/smallstep/pkcs7 + Go stdlib.
// Every CMS operation is performed explicitly with debug logging.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
)

// version is set at build time via: go build -ldflags "-X main.version=1.0"
var version = "dev"

// ---------------------------------------------------------------------------
// SCEP OIDs — RFC 8894 §3.2.1
// ---------------------------------------------------------------------------

var (
	// id-VeriSign OBJECT_IDENTIFIER ::= {2 16 US(840) 1 VeriSign(113733)}
	// id-pki      OBJECT_IDENTIFIER ::= {id-VeriSign pki(1)}
	// id-attributes OBJECT_IDENTIFIER ::= {id-pki attributes(9)}
	oidSCEPtransactionID = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	oidSCEPmessageType   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPpkiStatus     = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPfailInfo      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPsenderNonce   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPrecipNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}

	// PKCS#9 challengePassword
	oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
)

// SCEP messageType values (PrintableString)
const (
	msgTypeCertRep    = "3"
	msgTypeRenewalReq = "17"
	msgTypePKCSReq    = "19"
	msgTypeCertPoll   = "20"
	msgTypeGetCert    = "21"
	msgTypeGetCRL     = "22"
)

// SCEP pkiStatus values (PrintableString)
const (
	statusSUCCESS = "0"
	statusFAILURE = "2"
	statusPENDING = "3"
)

// failInfo human-readable names
var failInfoNames = map[string]string{
	"0": "badAlg — Unrecognised or unsupported algorithm",
	"1": "badMessageCheck — Integrity check (signature verification) failed",
	"2": "badRequest — Transaction not permitted or supported",
	"3": "badTime — signingTime not sufficiently close to system time",
	"4": "badCertId — No certificate matching provided criteria",
}

// CA capabilities discovered via GetCACaps.
type caCaps struct {
	postSupported bool
	aes           bool
	sha256        bool
	sha1          bool
	des3          bool
	scepStandard  bool
	renewal       bool
	raw           []string
}

// ---------------------------------------------------------------------------
// ANSI terminal colours
// ---------------------------------------------------------------------------

const (
	cReset  = "\033[0m"
	cRed    = "\033[1;31m"
	cGreen  = "\033[1;32m"
	cYellow = "\033[1;33m"
	cCyan   = "\033[1;36m"
)

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

const (
	exitSuccess     = 0 // Certificate issued successfully
	exitProtoFail   = 1 // Protocol failure (pkiStatus=FAILURE)
	exitPending     = 2 // PENDING status (with -no-poll)
	exitPollTimeout = 3 // Polling timeout exceeded
	exitNetwork     = 4 // Network or HTTP error
	exitClientError = 5 // Client-side error (args, file I/O, crypto)
)

// ---------------------------------------------------------------------------
// Debug logger
// ---------------------------------------------------------------------------

var (
	verbose      bool
	silent       bool
	httpClient   *http.Client // initialised in main()
	rfcWarnCount int          // total RFC 8894 discrepancies detected
)

func dbg(format string, a ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, cCyan+"[DEBUG]"+cReset+" "+format+"\n", a...)
	}
}

func info(format string, a ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, cCyan+"[INFO]"+cReset+"  "+format+"\n", a...)
	}
}

func ok(format string, a ...interface{}) {
	if !silent {
		fmt.Fprintf(os.Stderr, cGreen+"[OK]"+cReset+"     "+format+"\n", a...)
	}
}

func warn(format string, a ...interface{}) {
	if !silent {
		fmt.Fprintf(os.Stderr, cYellow+"[WARN]"+cReset+"  "+format+"\n", a...)
	}
}

func fatal(code int, format string, a ...interface{}) {
	if !silent {
		fmt.Fprintf(os.Stderr, cRed+"[FATAL]"+cReset+" "+format+"\n", a...)
	}
	os.Exit(code)
}

// rfcWarn logs an RFC 8894 compliance discrepancy in bold yellow with section reference.
func rfcWarn(section string, format string, a ...interface{}) {
	rfcWarnCount++
	if !silent {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintf(os.Stderr, cYellow+"[RFC-WARN S%s]"+cReset+" %s\n", section, msg)
	}
}

// rfcOK logs a passed RFC compliance check (only in debug mode).
func rfcOK(format string, a ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, cGreen+"[RFC-OK]"+cReset+"  "+format+"\n", a...)
	}
}

// printRFCSummary outputs a final coloured RFC compliance tally (only when warnings exist).
func printRFCSummary() {
	if !silent && rfcWarnCount > 0 {
		fmt.Fprintf(os.Stderr, "\n"+cYellow+">> RFC 8894 compliance: %d warning(s) detected"+cReset+"\n", rfcWarnCount)
	}
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

func fingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}

func pubKeyHash(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "<error>"
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func savePEM(path string, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func loadPEMKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	// Try PKCS#1 first, then PKCS#8
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return rsaKey, nil
}

// initHTTPClient creates an *http.Client with optional custom TLS roots.
func initHTTPClient(tlsRootsPath string) *http.Client {
	if tlsRootsPath == "" {
		return &http.Client{Timeout: 30 * time.Second}
	}
	data, err := os.ReadFile(tlsRootsPath)
	if err != nil {
		fatal(exitClientError, "Reading TLS roots file %s: %v", tlsRootsPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		fatal(exitClientError, "No PEM certificates found in %s", tlsRootsPath)
	}
	info("Loaded custom TLS roots from %s", tlsRootsPath)
	// Clone the default transport so proxy, dialer, and timeout settings from
	// the environment are preserved; only the TLS root set is overridden.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

func httpGet(rawURL string) ([]byte, http.Header, int, error) {
	dbg("HTTP GET %s", rawURL)
	resp, err := httpClient.Get(rawURL)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("reading response body: %w", err)
	}
	dbg("HTTP GET response: status=%d, content-type=%s, body-len=%d",
		resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
	return body, resp.Header, resp.StatusCode, nil
}

func httpPost(rawURL string, contentType string, body []byte) ([]byte, http.Header, int, error) {
	dbg("HTTP POST %s (content-type=%s, body-len=%d)", rawURL, contentType, len(body))
	resp, err := httpClient.Post(rawURL, contentType, bytes.NewReader(body))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("reading response body: %w", err)
	}
	dbg("HTTP POST response: status=%d, content-type=%s, body-len=%d",
		resp.StatusCode, resp.Header.Get("Content-Type"), len(respBody))
	return respBody, resp.Header, resp.StatusCode, nil
}

// ---------------------------------------------------------------------------
// Step 1: GetCACaps — RFC 8894 §3.5
// ---------------------------------------------------------------------------

func getCACaps(baseURL string) (*caCaps, error) {
	info("=== Step 1: GetCACaps ===")
	u := baseURL + "?operation=GetCACaps"
	body, _, status, err := httpGet(u)
	if err != nil {
		return nil, fmt.Errorf("GetCACaps: %w", err)
	}
	caps := &caCaps{}
	if status != 200 {
		warn("GetCACaps returned HTTP %d; proceeding with no advertised capabilities", status)
		return caps, nil
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		caps.raw = append(caps.raw, line)
		switch strings.ToLower(line) {
		case "postpkioperation":
			caps.postSupported = true
		case "aes":
			caps.aes = true
		case "sha-256":
			caps.sha256 = true
		case "sha-1":
			caps.sha1 = true
		case "des3":
			caps.des3 = true
		case "scepstandard":
			caps.scepStandard = true
			caps.aes = true
			caps.sha256 = true
			caps.postSupported = true
		case "renewal":
			caps.renewal = true
		}
	}

	info("Server capabilities: %s", strings.Join(caps.raw, ", "))

	// RFC 8894 S3.5.2 compliance checks
	if caps.postSupported {
		rfcOK("POSTPKIOperation supported (S3.5.2)")
	} else {
		rfcWarn("3.5.2", "POSTPKIOperation not advertised - server SHOULD support HTTP POST")
	}
	if caps.aes {
		rfcOK("AES encryption supported (S3.5.2)")
	} else {
		rfcWarn("3.5.2", "AES not advertised - AES SHOULD be preferred over DES3 for content encryption")
	}
	if caps.sha256 {
		rfcOK("SHA-256 hashing supported (S3.5.2)")
	} else {
		rfcWarn("3.5.2", "SHA-256 not advertised - SHA-1 is deprecated, SHA-256 SHOULD be used")
	}
	if caps.scepStandard {
		rfcOK("SCEPStandard advertised (S3.5.2)")
	} else {
		rfcWarn("3.5.2", "SCEPStandard not advertised - server may not fully comply with RFC 8894")
	}
	if !caps.aes && caps.des3 {
		rfcWarn("3.5.2", "Server only supports DES3 - this is a weak encryption algorithm")
	}
	return caps, nil
}

// ---------------------------------------------------------------------------
// Step 2: GetCACert — RFC 8894 §4.2
// ---------------------------------------------------------------------------

func getCACert(baseURL string) ([]*x509.Certificate, error) {
	info("=== Step 2: GetCACert ===")
	u := baseURL + "?operation=GetCACert"
	body, headers, status, err := httpGet(u)
	if err != nil {
		return nil, fmt.Errorf("GetCACert: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("GetCACert: HTTP %d", status)
	}

	ct := headers.Get("Content-Type")
	dbg("Content-Type: %s", ct)

	var certs []*x509.Certificate

	switch {
	case strings.Contains(strings.ToLower(ct), "x-x509-ca-cert"):
		// Single DER-encoded certificate
		cert, err := x509.ParseCertificate(body)
		if err != nil {
			return nil, fmt.Errorf("parsing single CA cert: %w", err)
		}
		certs = []*x509.Certificate{cert}
		info("Single CA certificate received")

	case strings.Contains(strings.ToLower(ct), "x-x509-ca-ra-cert"):
		// Degenerate PKCS#7 SignedData with certificate chain
		p7, err := pkcs7.Parse(body)
		if err != nil {
			return nil, fmt.Errorf("parsing CA cert chain (PKCS#7): %w", err)
		}
		certs = p7.Certificates
		info("CA certificate chain received (%d certs)", len(certs))

	default:
		// Fallback: try DER first, then PKCS#7
		rfcWarn("4.2", "Unexpected Content-Type %q - RFC 8894 S4.2 expects application/x-x509-ca-cert or application/x-x509-ca-ra-cert", ct)
		if cert, err := x509.ParseCertificate(body); err == nil {
			certs = []*x509.Certificate{cert}
		} else if p7, err := pkcs7.Parse(body); err == nil {
			certs = p7.Certificates
		} else {
			return nil, fmt.Errorf("GetCACert: unable to parse response (ct=%s)", ct)
		}
	}

	for i, cert := range certs {
		info("  CA cert[%d]: subject=%q issuer=%q serial=%s",
			i, cert.Subject.CommonName, cert.Issuer.CommonName, cert.SerialNumber.String())
		dbg("  CA cert[%d]: keyType=%T notBefore=%s notAfter=%s",
			i, cert.PublicKey, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
		dbg("  CA cert[%d]: SHA-256 fingerprint=%s", i, fingerprint(cert))
		dbg("  CA cert[%d]: keyUsage=%d isCA=%v", i, cert.KeyUsage, cert.IsCA)

		// RFC 8894 S4.2 compliance checks on CA certificate
		if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			rfcWarn("4.2", "CA cert[%d]: uses non-RSA key type %T - SCEP requires RSA for key transport", i, cert.PublicKey)
		} else {
			rsaPub := cert.PublicKey.(*rsa.PublicKey)
			bits := rsaPub.N.BitLen()
			if bits < 2048 {
				rfcWarn("4.2", "CA cert[%d]: RSA key is %d bits - minimum 2048 recommended", i, bits)
			} else {
				rfcOK("CA cert[%d]: RSA key size %d bits", i, bits)
			}
		}
		if !cert.IsCA {
			rfcWarn("4.2", "CA cert[%d]: BasicConstraints isCA=false - certificate is not a CA", i)
		}
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			rfcWarn("4.2", "CA cert[%d]: keyEncipherment not set in KeyUsage - SCEP clients encrypt to this cert", i)
		}
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			rfcWarn("4.2", "CA cert[%d]: digitalSignature not set in KeyUsage - needed by CA to sign CertRep", i)
		}
		now := time.Now()
		if now.After(cert.NotAfter) {
			rfcWarn("4.2", "CA cert[%d]: certificate EXPIRED (notAfter=%s)", i, cert.NotAfter.Format(time.RFC3339))
		} else if now.Before(cert.NotBefore) {
			rfcWarn("4.2", "CA cert[%d]: certificate NOT YET VALID (notBefore=%s)", i, cert.NotBefore.Format(time.RFC3339))
		} else {
			rfcOK("CA cert[%d]: within validity period", i)
		}
	}

	return certs, nil
}

// localFlagError marks a failure caused by a malformed local flag value rather
// than by untrusted protocol data, so callers can map it to the client-error
// exit code instead of the protocol-failure code.
type localFlagError struct{ err error }

func (e *localFlagError) Error() string { return e.err.Error() }
func (e *localFlagError) Unwrap() error { return e.err }

// isCACandidate reports whether a certificate is usable as a SCEP trust anchor:
// it must assert the CA basic constraint per RFC 8894 §2.1.2.
func isCACandidate(cert *x509.Certificate) bool {
	return cert.BasicConstraintsValid && cert.IsCA
}

// selectCACerts picks the trust anchor and the encryption recipient from the
// certificates returned by GetCACert. The anchor is the CA certificate (RFC
// 8894 §2.1.2); the recipient is the certificate the client encrypts the CSR
// to, which RFC 8894 §2.1.2 requires to assert keyEncipherment. When an RA
// (non-CA) certificate with keyEncipherment is present it is preferred as the
// recipient; otherwise the CA certificate is used.
func selectCACerts(certs []*x509.Certificate) (anchor *x509.Certificate, recipient *x509.Certificate, err error) {
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates in GetCACert response")
	}

	for _, c := range certs {
		if isCACandidate(c) && c.KeyUsage&x509.KeyUsageCertSign != 0 {
			anchor = c
			break
		}
	}
	if anchor == nil {
		for _, c := range certs {
			if isCACandidate(c) {
				anchor = c
				break
			}
		}
	}
	if anchor == nil {
		return nil, nil, fmt.Errorf("GetCACert response contains no CA certificate (BasicConstraints isCA=true)")
	}

	for _, c := range certs {
		if !isCACandidate(c) && c.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			recipient = c
			break
		}
	}
	if recipient == nil {
		if anchor.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			rfcWarn("2.1.2", "no certificate advertises keyEncipherment; encrypting CSR to CA certificate %q anyway", anchor.Subject.CommonName)
		}
		recipient = anchor
	}
	return anchor, recipient, nil
}

// normalizeCAFingerprint validates and canonicalizes a user-supplied
// -ca-fingerprint value. RFC 8894 §2.2 fingerprints are a hash over the whole
// DER certificate; this client requires SHA-256, accepting 64 hexadecimal
// characters either bare or colon-separated, case-insensitively. The return
// value is lowercase hex with separators removed.
func normalizeCAFingerprint(raw string) (string, error) {
	cleaned := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), ":", ""))
	if len(cleaned) != 64 {
		return "", fmt.Errorf("-ca-fingerprint must be a SHA-256 hash (64 hex chars, optionally colon-separated); got %d hex chars", len(cleaned))
	}
	if _, err := hex.DecodeString(cleaned); err != nil {
		return "", fmt.Errorf("-ca-fingerprint is not valid hexadecimal: %w", err)
	}
	return cleaned, nil
}

// buildCATrustPool establishes the SCEP message trust anchor from the GetCACert
// certificates. When caFingerprint is set it must match exactly one CA
// candidate's SHA-256 whole-certificate fingerprint (RFC 8894 §2.2/§4.2.1);
// zero or multiple matches are fatal. When it is empty the best CA candidate is
// trusted for this run only (trust on first use) with a loud warning. The
// returned pool contains only the selected anchor as a root; every other CA
// certificate is then verified to chain to that anchor (RFC 8894 §2.1.2).
func buildCATrustPool(certs []*x509.Certificate, caFingerprint string) (*x509.CertPool, *x509.Certificate, error) {
	anchor, _, err := selectCACerts(certs)
	if err != nil {
		return nil, nil, err
	}

	if caFingerprint != "" {
		want, ferr := normalizeCAFingerprint(caFingerprint)
		if ferr != nil {
			return nil, nil, &localFlagError{ferr}
		}
		var matched []*x509.Certificate
		for _, c := range certs {
			if fingerprint(c) == want {
				matched = append(matched, c)
			}
		}
		switch {
		case len(matched) == 0:
			return nil, nil, fmt.Errorf("-ca-fingerprint %s does not match any certificate returned by GetCACert; CA is not authenticated (RFC 8894 §2.2)", want)
		case len(matched) > 1:
			return nil, nil, fmt.Errorf("-ca-fingerprint %s matches %d certificates; ambiguous trust anchor", want, len(matched))
		}
		if !isCACandidate(matched[0]) {
			return nil, nil, fmt.Errorf("-ca-fingerprint %s matches a non-CA certificate (subject %q); the fingerprint must authenticate the CA, not an RA/end-entity cert (RFC 8894 §2.2)", want, matched[0].Subject.CommonName)
		}
		anchor = matched[0]
		rfcOK("CA certificate authenticated by -ca-fingerprint (RFC 8894 §2.2)")
	} else {
		warn("CA certificate is NOT authenticated: no -ca-fingerprint supplied.")
		warn("Trusting CA %q for this run only (trust on first use).", anchor.Subject.CommonName)
		warn("RFC 8894 §2.2 expects out-of-band CA authentication. Verify this fingerprint:")
		warn("  SHA-256: %s", fingerprint(anchor))
	}

	roots := x509.NewCertPool()
	roots.AddCert(anchor)

	intermediates := x509.NewCertPool()
	for _, c := range certs {
		if c.Equal(anchor) {
			continue
		}
		intermediates.AddCert(c)
	}
	for _, c := range certs {
		if c.Equal(anchor) || !isCACandidate(c) {
			continue
		}
		if _, verr := c.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); verr != nil {
			return nil, nil, fmt.Errorf("CA certificate %q does not chain to the trust anchor: %w", c.Subject.CommonName, verr)
		}
	}

	return roots, anchor, nil
}

// ---------------------------------------------------------------------------
// Step 3: Generate or load RSA private key
// ---------------------------------------------------------------------------

func getOrCreateKey(keyPath string, keySize int) (*rsa.PrivateKey, error) {
	info("=== Step 3: Private Key ===")

	if keyPath != "" {
		_, statErr := os.Stat(keyPath)
		switch {
		case statErr == nil:
			key, err := loadPEMKey(keyPath)
			if err != nil {
				return nil, fmt.Errorf("loading key from %s: %w", keyPath, err)
			}
			info("Loaded existing key from %s (%d-bit)", keyPath, key.N.BitLen())
			dbg("  Public key hash: %s", pubKeyHash(&key.PublicKey))
			if key.N.BitLen() < 2048 {
				rfcWarn("2.3", "RSA key is %d bits - RFC 8894 recommends >= 2048 bits", key.N.BitLen())
			} else {
				rfcOK("RSA key size: %d bits", key.N.BitLen())
			}
			return key, nil
		case !errors.Is(statErr, fs.ErrNotExist):
			// Security (F8): a non-ENOENT stat error (e.g. EACCES) must fail loudly,
			// never fall through to generation that would overwrite an unreadable key.
			return nil, fmt.Errorf("stat key path %s: %w", keyPath, statErr)
		}
	}

	if keySize < 2048 {
		rfcWarn("2.3", "Generating %d-bit RSA key - RFC 8894 recommends >= 2048 bits", keySize)
	}
	info("Generating new %d-bit RSA key", keySize)
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	dbg("  Public key hash: %s", pubKeyHash(&key.PublicKey))

	if keyPath != "" {
		der := x509.MarshalPKCS1PrivateKey(key)
		if err := savePEM(keyPath, "RSA PRIVATE KEY", der, 0o600); err != nil {
			return nil, fmt.Errorf("saving key to %s: %w", keyPath, err)
		}
		info("Saved key to %s (mode 0600)", keyPath)
	}

	return key, nil
}

// ---------------------------------------------------------------------------
// Step 4: Create PKCS#10 CSR with optional challengePassword
// ---------------------------------------------------------------------------

// buildChallengePasswordAttr constructs the ASN.1 for:
//
//	Attribute ::= SEQUENCE {
//	    type   OBJECT IDENTIFIER (1.2.840.113549.1.9.7),
//	    values SET { challenge }
//	}
//
// The challenge string value is encoded by encoding/asn1, which emits a
// PrintableString when every byte is printable ASCII and a UTF8String
// otherwise.
func buildChallengePasswordAttr(challenge string) ([]byte, error) {
	oidDER, err := asn1.Marshal(oidChallengePassword)
	if err != nil {
		return nil, err
	}

	pwDER, err := asn1.Marshal(challenge)
	if err != nil {
		return nil, err
	}

	// Wrap in SET
	setDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		Bytes: pwDER,
	})
	if err != nil {
		return nil, err
	}

	// Wrap in SEQUENCE { OID, SET }
	seqDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(oidDER, setDER...),
	})
	if err != nil {
		return nil, err
	}
	return seqDER, nil
}

// buildCSRRaw constructs a PKCS#10 CertificationRequest from raw ASN.1.
// This is necessary because Go's x509.CertificateRequest.Attributes field
// cannot correctly encode a challengePassword (its struct nests differently).
//
//	CertificationRequest ::= SEQUENCE {
//	    certificationRequestInfo CertificationRequestInfo,
//	    signatureAlgorithm       AlgorithmIdentifier,
//	    signature                BIT STRING
//	}
//	CertificationRequestInfo ::= SEQUENCE {
//	    version       INTEGER { v1(0) },
//	    subject       Name,
//	    subjectPKInfo SubjectPublicKeyInfo,
//	    attributes    [0] IMPLICIT SET OF Attribute
//	}
func buildCSRRaw(key *rsa.PrivateKey, cn, org, country, challenge string) ([]byte, error) {
	// --- version INTEGER 0 ---
	versionDER, err := asn1.Marshal(0)
	if err != nil {
		return nil, fmt.Errorf("marshal version: %w", err)
	}

	// --- subject Name (RDNSequence) ---
	subject := pkix.Name{CommonName: cn}
	if org != "" {
		subject.Organization = []string{org}
	}
	if country != "" {
		subject.Country = []string{country}
	}
	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal subject: %w", err)
	}

	// --- SubjectPublicKeyInfo ---
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	// --- attributes [0] IMPLICIT SET OF Attribute ---
	var attrsContent []byte
	if challenge != "" {
		attr, err := buildChallengePasswordAttr(challenge)
		if err != nil {
			return nil, fmt.Errorf("build challengePassword: %w", err)
		}
		attrsContent = attr
	}
	attrsDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: attrsContent,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal attributes: %w", err)
	}

	// --- CertificationRequestInfo SEQUENCE ---
	tbsContent := concat(versionDER, subjectDER, pubDER, attrsDER)
	tbsDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: tbsContent,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal tbsCSR: %w", err)
	}

	// --- Sign tbsDER with SHA256WithRSA ---
	h := sha256.Sum256(tbsDER)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return nil, fmt.Errorf("signing CSR: %w", err)
	}

	// --- SignatureAlgorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11) ---
	sigAlgOID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11})
	sigAlgNull, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal})
	sigAlgDER, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(sigAlgOID, sigAlgNull...),
	})

	// --- Signature BIT STRING ---
	sigBitsDER, _ := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})

	// --- CertificationRequest outer SEQUENCE ---
	csrContent := concat(tbsDER, sigAlgDER, sigBitsDER)
	csrDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: csrContent,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal CSR: %w", err)
	}
	return csrDER, nil
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func createCSR(key *rsa.PrivateKey, cn, org, country, challenge string) ([]byte, *x509.CertificateRequest, error) {
	info("=== Step 4: Create CSR (PKCS#10) ===")

	var csrDER []byte
	var err error

	if challenge != "" {
		// Use raw ASN.1 builder to include challengePassword properly
		dbg("  Building CSR with challengePassword via raw ASN.1 (length=%d)", len(challenge))
		csrDER, err = buildCSRRaw(key, cn, org, country, challenge)
		if err != nil {
			return nil, nil, fmt.Errorf("building CSR (raw): %w", err)
		}
	} else {
		// No challenge — use stdlib
		dbg("  Building CSR via x509.CreateCertificateRequest (no challenge)")
		subject := pkix.Name{CommonName: cn}
		if org != "" {
			subject.Organization = []string{org}
		}
		if country != "" {
			subject.Country = []string{country}
		}
		tmpl := &x509.CertificateRequest{
			Subject:            subject,
			SignatureAlgorithm: x509.SHA256WithRSA,
		}
		csrDER, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
		if err != nil {
			return nil, nil, fmt.Errorf("creating CSR: %w", err)
		}
	}

	// Parse it back to verify. A CSR we cannot parse is fatal: callers
	// dereference csr.Subject and csr.PublicKey, so returning a nil CSR with a
	// nil error would crash later instead of failing cleanly here.
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing generated CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR self-signature verification FAILED: %w", err)
	}

	info("CSR created: subject=%q, sigAlg=%s", csr.Subject, csr.SignatureAlgorithm)
	dbg("  CSR DER size: %d bytes", len(csrDER))
	dbg("  CSR public key hash: %s", pubKeyHash(csr.PublicKey))
	dbg("  CSR signature self-check: OK")
	if challenge != "" {
		dbg("  challengePassword: present (not logged for security)")
	}

	// Debug: save CSR PEM for offline inspection
	if verbose {
		_ = savePEM("debug-csr.pem", "CERTIFICATE REQUEST", csrDER, 0o644)
		dbg("  CSR saved to debug-csr.pem (inspect with: openssl req -text -noout -in debug-csr.pem)")
	}

	// Debug: try to extract challengePassword from parsed CSR attributes
	if verbose && challenge != "" {
		found := false
		for _, attr := range csr.Attributes {
			if attr.Type.Equal(oidChallengePassword) {
				found = true
				dbg("  Verified challengePassword attribute found via Go parser (Attributes field)")
				break
			}
		}
		if !found {
			dbg("  [WARN] challengePassword NOT found in csr.Attributes (Go parser may not extract it)")
			dbg("  This is expected — Go's pkix.AttributeTypeAndValueSET cannot decode DirectoryString")
		}
	}

	return csrDER, csr, nil
}

// ---------------------------------------------------------------------------
// Step 5: Create self-signed signer certificate
// ---------------------------------------------------------------------------

func createSelfSignedCert(key *rsa.PrivateKey, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	info("=== Step 5: Self-Signed Signer Certificate ===")

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    now.Add(-10 * time.Minute), // slight backdate for clock skew
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating self-signed cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing self-signed cert: %w", err)
	}

	info("Self-signed cert: subject=%q serial=%s", cert.Subject.CommonName, cert.SerialNumber)
	dbg("  Validity: %s to %s", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	dbg("  SHA-256 fingerprint: %s", fingerprint(cert))
	dbg("  KeyUsage: digitalSignature + keyEncipherment")

	return cert, nil
}

// ---------------------------------------------------------------------------
// Step 6: Generate SCEP transaction metadata
// ---------------------------------------------------------------------------

type scepTransaction struct {
	transactionID string
	senderNonce   []byte
}

func newTransaction(csr *x509.CertificateRequest) (*scepTransaction, error) {
	info("=== Step 6: Transaction Metadata ===")

	// transactionID = SHA-256 of CSR public key DER → hex string
	pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshalling public key: %w", err)
	}
	h := sha256.Sum256(pubDER)
	txnID := hex.EncodeToString(h[:])

	// senderNonce = 16 random bytes
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating senderNonce: %w", err)
	}

	info("transactionID: %s", txnID)
	dbg("  senderNonce: %s", hex.EncodeToString(nonce))

	return &scepTransaction{
		transactionID: txnID,
		senderNonce:   nonce,
	}, nil
}

// ---------------------------------------------------------------------------
// IssuerAndSubject — RFC 8894 §3.3.3 (CertPoll content)
// ---------------------------------------------------------------------------

// buildIssuerAndSubject constructs the ASN.1 encoding for CertPoll:
//
//	IssuerAndSubject ::= SEQUENCE {
//	    issuer  Name,  -- CA's subject (the expected issuer of the requested cert)
//	    subject Name   -- client's subject from the CSR
//	}
func buildIssuerAndSubject(caCert *x509.Certificate, csr *x509.CertificateRequest) ([]byte, error) {
	dbg("  Building IssuerAndSubject for CertPoll")
	dbg("    issuer:  %s", caCert.Subject)
	dbg("    subject: %s", csr.Subject)

	issuerDER, err := asn1.Marshal(caCert.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal issuer: %w", err)
	}
	subjectDER, err := asn1.Marshal(csr.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal subject: %w", err)
	}

	seqDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(issuerDER, subjectDER...),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal IssuerAndSubject: %w", err)
	}
	dbg("  IssuerAndSubject DER size: %d bytes", len(seqDER))
	return seqDER, nil
}

// ---------------------------------------------------------------------------
// Step 7: Encrypt CSR → CMS EnvelopedData (pkcsPKIEnvelope)
// ---------------------------------------------------------------------------

func encryptCSR(csrDER []byte, caCert *x509.Certificate) ([]byte, error) {
	info("=== Step 7: Encrypt CSR → CMS EnvelopedData ===")

	recipients := []*x509.Certificate{caCert}
	dbg("  Encrypting %d bytes of CSR to %d recipient(s)", len(csrDER), len(recipients))
	dbg("  Recipient: %q (fingerprint=%s)", caCert.Subject.CommonName, fingerprint(caCert))

	envelope, err := pkcs7.Encrypt(csrDER, recipients)
	if err != nil {
		return nil, fmt.Errorf("CMS Encrypt: %w", err)
	}

	dbg("  EnvelopedData size: %d bytes", len(envelope))
	return envelope, nil
}

// ---------------------------------------------------------------------------
// Step 8: Sign envelope → CMS SignedData with SCEP attributes
// ---------------------------------------------------------------------------

// marshalPrintableString creates ASN.1 PrintableString bytes for a SCEP attribute value.
func marshalPrintableString(s string) ([]byte, error) {
	raw := asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagPrintableString,
		Bytes: []byte(s),
	}
	return asn1.Marshal(raw)
}

func signEnvelope(envelope []byte, signerCert *x509.Certificate, key *rsa.PrivateKey, txn *scepTransaction, messageType string, caps *caCaps) ([]byte, error) {
	info("=== Step 8: Sign Envelope → CMS SignedData ===")

	sd, err := pkcs7.NewSignedData(envelope)
	if err != nil {
		return nil, fmt.Errorf("creating SignedData: %w", err)
	}

	// SCEP signers default to SHA-1 in this library; upgrade the message digest
	// to SHA-256 whenever the CA advertises it (RFC 8894 §3.2 / GetCACaps SHA-256).
	if caps.sha256 {
		sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
		info("Signature digest: SHA-256")
	} else {
		info("Signature digest: SHA-1 (CA did not advertise SHA-256)")
	}

	// Build SCEP authenticated attributes
	transactionIDBytes, err := marshalPrintableString(txn.transactionID)
	if err != nil {
		return nil, fmt.Errorf("marshalling transactionID: %w", err)
	}

	messageTypeBytes, err := marshalPrintableString(messageType)
	if err != nil {
		return nil, fmt.Errorf("marshalling messageType: %w", err)
	}

	senderNonceBytes, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagOctetString,
		Bytes: txn.senderNonce,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling senderNonce: %w", err)
	}

	attrs := []pkcs7.Attribute{
		{Type: oidSCEPtransactionID, Value: asn1.RawValue{FullBytes: transactionIDBytes}},
		{Type: oidSCEPmessageType, Value: asn1.RawValue{FullBytes: messageTypeBytes}},
		{Type: oidSCEPsenderNonce, Value: asn1.RawValue{FullBytes: senderNonceBytes}},
	}

	dbg("  Authenticated attributes:")
	dbg("    transactionID = %s", txn.transactionID)
	dbg("    messageType   = %s", messageType)
	dbg("    senderNonce   = %s", hex.EncodeToString(txn.senderNonce))
	dbg("  Signer cert: %q (fingerprint=%s)", signerCert.Subject.CommonName, fingerprint(signerCert))

	signerConfig := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: attrs,
	}

	if err := sd.AddSigner(signerCert, key, signerConfig); err != nil {
		return nil, fmt.Errorf("adding signer: %w", err)
	}

	// Detach content = false (content is included)
	msgBytes, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("finishing SignedData: %w", err)
	}

	info("SCEP message (type=%s) built: %d bytes", messageType, len(msgBytes))
	dbg("  SignedData DER size: %d bytes", len(msgBytes))

	return msgBytes, nil
}

// ---------------------------------------------------------------------------
// Step 9: HTTP POST PKIOperation
// ---------------------------------------------------------------------------

func sendPKIOperation(baseURL string, msg []byte, caps *caCaps) ([]byte, error) {
	info("=== Step 9: PKIOperation ===")

	if caps.postSupported {
		info("Sending PKIOperation via HTTP POST")
		u := baseURL + "?operation=PKIOperation"
		body, hdrs, status, err := httpPost(u, "application/x-pki-message", msg)
		if err != nil {
			return nil, fmt.Errorf("PKIOperation POST: %w", err)
		}
		if status != 200 {
			dbg("  Response body (first 200 bytes): %s", truncate(string(body), 200))
			return nil, fmt.Errorf("PKIOperation POST: HTTP %d", status)
		}
		checkPKIOperationContentType(hdrs)
		return body, nil
	}

	// Fallback: HTTP GET with base64+URL-encoded message
	info("Sending PKIOperation via HTTP GET (server does not support POST)")
	encoded := url.QueryEscape(base64.StdEncoding.EncodeToString(msg))
	u := baseURL + "?operation=PKIOperation&message=" + encoded
	body, hdrs, status, err := httpGet(u)
	if err != nil {
		return nil, fmt.Errorf("PKIOperation GET: %w", err)
	}
	if status != 200 {
		dbg("  Response body (first 200 bytes): %s", truncate(string(body), 200))
		return nil, fmt.Errorf("PKIOperation GET: HTTP %d", status)
	}
	checkPKIOperationContentType(hdrs)
	return body, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		s = s[:n] + "..."
	}
	// Quote the server-controlled bytes so control characters and ANSI escape
	// sequences cannot be injected into the terminal when logging responses.
	return strconv.Quote(s)
}

// checkPKIOperationContentType validates the Content-Type of a PKIOperation response.
// RFC 8894 S4.3 requires application/x-pki-message for CertRep.
func checkPKIOperationContentType(hdrs http.Header) {
	ct := hdrs.Get("Content-Type")
	if ct == "" {
		rfcWarn("4.3", "PKIOperation response has no Content-Type header")
	} else if !strings.Contains(strings.ToLower(ct), "application/x-pki-message") {
		rfcWarn("4.3", "PKIOperation response Content-Type=%q - expected application/x-pki-message", ct)
	} else {
		rfcOK("PKIOperation response Content-Type: %s", ct)
	}
}

// ---------------------------------------------------------------------------
// Step 10: Parse CertRep response
// ---------------------------------------------------------------------------

type certRepResult struct {
	pkiStatus     string
	failInfo      string
	messageType   string
	transactionID string
	recipNonce    []byte
	senderNonce   []byte // CA's own senderNonce
	raw           *pkcs7.PKCS7
}

func parseCertRep(data []byte, roots *x509.CertPool) (*certRepResult, error) {
	info("=== Step 10: Parse CertRep ===")
	dbg("  Response size: %d bytes", len(data))

	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing CertRep outer SignedData: %w", err)
	}

	dbg("  Outer SignedData parsed OK")
	dbg("  Certificates in SignedData: %d", len(p7.Certificates))
	for i, c := range p7.Certificates {
		dbg("    cert[%d]: subject=%q issuer=%q", i, c.Subject.CommonName, c.Issuer.CommonName)
	}

	// The CertRep signature MUST verify and chain to the authenticated CA
	// anchor (RFC 8894 SS2.1.2, SS2.2); an unverifiable response is fatal so a
	// forged or tampered CertRep can never reach decryption or disk.
	if err := p7.VerifyWithChain(roots); err != nil {
		return nil, fmt.Errorf("CertRep signature/chain verification failed: %w", err)
	}
	dbg("  Signature verification: OK (chained to CA trust anchor)")
	rfcOK("CertRep signature verified against CA trust anchor")

	result := &certRepResult{raw: p7}

	// Extract SCEP attributes
	// pkiStatus (REQUIRED - RFC 8894 S3.2.1.3)
	var statusRaw string
	if err := p7.UnmarshalSignedAttribute(oidSCEPpkiStatus, &statusRaw); err != nil {
		return nil, fmt.Errorf("extracting pkiStatus: %w", err)
	}
	result.pkiStatus = statusRaw
	dbg("  pkiStatus = %s", statusRaw)

	// messageType (REQUIRED - RFC 8894 S3.2.1.2)
	var msgType string
	if err := p7.UnmarshalSignedAttribute(oidSCEPmessageType, &msgType); err != nil {
		return nil, fmt.Errorf("CertRep missing required messageType attribute (RFC 8894 S3.2.1.2): %w", err)
	}
	result.messageType = msgType
	dbg("  messageType = %s", msgType)
	if msgType != msgTypeCertRep {
		return nil, fmt.Errorf("CertRep has wrong messageType %q, expected 3 (CertRep) (RFC 8894 S3.2.1.2)", msgType)
	}
	rfcOK("messageType = 3 (CertRep)")

	// transactionID (REQUIRED - RFC 8894 S3.2.1.1)
	var txnID string
	if err := p7.UnmarshalSignedAttribute(oidSCEPtransactionID, &txnID); err != nil {
		return nil, fmt.Errorf("CertRep missing required transactionID attribute (RFC 8894 S3.2.1.1): %w", err)
	}
	result.transactionID = txnID
	dbg("  transactionID = %s", txnID)

	// recipientNonce (REQUIRED - RFC 8894 S3.2.1.5)
	var recipNonce []byte
	if err := p7.UnmarshalSignedAttribute(oidSCEPrecipNonce, &recipNonce); err != nil {
		rfcWarn("3.2.1.5", "CertRep missing recipientNonce attribute: %v", err)
	} else {
		result.recipNonce = recipNonce
		dbg("  recipientNonce = %s", hex.EncodeToString(recipNonce))
	}

	// senderNonce — CA's own nonce (RFC 8894 S3.2.1.5)
	var caSenderNonce []byte
	if err := p7.UnmarshalSignedAttribute(oidSCEPsenderNonce, &caSenderNonce); err != nil {
		dbg("  CertRep does not include senderNonce (optional for CA)")
	} else {
		result.senderNonce = caSenderNonce
		dbg("  CA senderNonce = %s", hex.EncodeToString(caSenderNonce))
	}

	// failInfo (REQUIRED on FAILURE - RFC 8894 S3.2.1.4)
	if result.pkiStatus == statusFAILURE {
		var fInfo string
		if err := p7.UnmarshalSignedAttribute(oidSCEPfailInfo, &fInfo); err != nil {
			rfcWarn("3.2.1.4", "FAILURE response missing failInfo attribute: %v", err)
		} else {
			result.failInfo = fInfo
			dbg("  failInfo = %s", fInfo)
		}
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Step 11: Validate response nonces and transaction ID
// ---------------------------------------------------------------------------

func validateResponse(result *certRepResult, txn *scepTransaction) error {
	info("=== Step 11: Validate Response ===")

	// transactionID MUST match the request (RFC 8894 S3.2.1.1).
	if result.transactionID != txn.transactionID {
		return fmt.Errorf("transactionID mismatch: sent=%s received=%s (RFC 8894 S3.2.1.1)", txn.transactionID, result.transactionID)
	}
	rfcOK("transactionID: MATCH")

	// recipientNonce MUST be present and MUST echo our senderNonce
	// (RFC 8894 S3.2.1.5); a missing or mismatched nonce permits replay and
	// is fatal with no override.
	if len(result.recipNonce) == 0 {
		return fmt.Errorf("CertRep does not contain recipientNonce (RFC 8894 S3.2.1.5)")
	}
	if subtle.ConstantTimeCompare(result.recipNonce, txn.senderNonce) != 1 {
		return fmt.Errorf("recipientNonce does not match senderNonce: sent=%s received=%s (RFC 8894 S3.2.1.5)",
			hex.EncodeToString(txn.senderNonce), hex.EncodeToString(result.recipNonce))
	}
	rfcOK("recipientNonce matches senderNonce")

	if len(result.senderNonce) > 0 {
		dbg("  CA senderNonce: %s", hex.EncodeToString(result.senderNonce))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Step 12: Decrypt CertRep envelope → extract issued certificate
// ---------------------------------------------------------------------------

func decryptCertRep(result *certRepResult, signerCert *x509.Certificate, key *rsa.PrivateKey) (*x509.Certificate, error) {
	info("=== Step 12: Decrypt CertRep Envelope ===")

	content := result.raw.Content
	if len(content) == 0 {
		return nil, fmt.Errorf("CertRep has no content (empty pkcsPKIEnvelope)")
	}
	dbg("  Inner content size: %d bytes", len(content))

	innerP7, err := pkcs7.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("parsing inner EnvelopedData: %w", err)
	}
	dbg("  Inner PKCS#7 parsed OK")

	decrypted, err := innerP7.Decrypt(signerCert, key)
	if err != nil {
		return nil, fmt.Errorf("decrypting CertRep envelope: %w", err)
	}
	dbg("  Decrypted payload: %d bytes", len(decrypted))

	// The decrypted content is a degenerate PKCS#7 SignedData containing the issued cert
	certP7, err := pkcs7.Parse(decrypted)
	if err != nil {
		// Maybe it's a raw certificate?
		dbg("  Could not parse as PKCS#7, trying raw DER certificate...")
		cert, err2 := x509.ParseCertificate(decrypted)
		if err2 != nil {
			return nil, fmt.Errorf("could not parse decrypted content as PKCS#7 (%v) or DER cert (%v)", err, err2)
		}
		return cert, nil
	}

	if len(certP7.Certificates) == 0 {
		return nil, fmt.Errorf("degenerate SignedData contains no certificates")
	}

	// The issued certificate should be the leaf (first) certificate
	cert := certP7.Certificates[0]
	info("Issued certificate extracted!")
	info("  Subject: %s", cert.Subject)
	info("  Issuer:  %s", cert.Issuer)
	info("  Serial:  %s", cert.SerialNumber)
	info("  Valid:   %s to %s", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	dbg("  SHA-256 fingerprint: %s", fingerprint(cert))
	if len(cert.DNSNames) > 0 {
		dbg("  DNS SANs: %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) > 0 {
		dbg("  IP SANs: %v", cert.IPAddresses)
	}

	return cert, nil
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	var (
		flagURL           = flag.String("url", "", "SCEP server URL (required)")
		flagChallenge     = flag.String("challenge", "", "Challenge password for enrollment")
		flagChallengeFile = flag.String("challenge-file", "", "File containing challenge password (avoids shell quoting issues)")
		flagCN            = flag.String("cn", "scepclient", "Common Name for the certificate")
		flagOrg           = flag.String("org", "SCEP Test", "Organization")
		flagCountry       = flag.String("country", "US", "Country code")
		flagKey           = flag.String("key", "client.key", "Path to RSA private key (created if absent)")
		flagKeySize       = flag.Int("keysize", 2048, "RSA key size (if generating)")
		flagOut           = flag.String("out", "cert.pem", "Output certificate path")
		flagCACertOut     = flag.String("cacert", "ca.pem", "Output CA certificate path")
		flagCAFingerprint = flag.String("ca-fingerprint", "", "Expected SHA-256 fingerprint of the CA certificate (64 hex chars, optionally colon-separated) for out-of-band CA authentication (RFC 8894 §2.2)")
		flagAllowWeak     = flag.Bool("allow-weak-crypto", false, "Permit single-DES content encryption when the CA does not advertise AES (INSECURE, violates RFC 8894 §2.9)")
		flagVerbose       = flag.Bool("verbose", false, "Enable verbose logging")
		flagTLSRoots      = flag.String("tls-roots", "", "PEM file with custom TLS root CA(s) for HTTPS")
		flagRenew         = flag.Bool("renew", false, "Renew existing certificate (uses RenewalReq messageType 17)")
		flagRenewCert     = flag.String("renew-cert", "", "Path to existing certificate to renew (required with -renew)")
		flagNoPoll        = flag.Bool("no-poll", false, "Disable automatic polling on PENDING status")
		flagPollInterval  = flag.Duration("poll-interval", 30*time.Second, "Interval between CertPoll requests")
		flagPollTimeout   = flag.Duration("poll-timeout", 10*time.Minute, "Maximum time to wait for PENDING to resolve")
		flagSilent        = flag.Bool("silent", false, "Suppress all output, communicate only via exit codes")
		flagVersion       = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *flagVersion {
		fmt.Fprintf(os.Stdout, "scepclient v%s\n", version)
		os.Exit(0)
	}

	verbose = *flagVerbose
	silent = *flagSilent
	if silent {
		verbose = false
	}
	httpClient = initHTTPClient(*flagTLSRoots)

	// Resolve challenge password
	challenge := *flagChallenge
	if *flagChallengeFile != "" {
		data, err := os.ReadFile(*flagChallengeFile)
		if err != nil {
			fatal(exitClientError, "Reading challenge file %s: %v", *flagChallengeFile, err)
		}
		challenge = strings.TrimRight(string(data), "\r\n")
		dbg("Challenge loaded from file %s (length=%d)", *flagChallengeFile, len(challenge))
	}
	// Auto-strip surrounding single or double quotes (common shell quoting accident)
	if len(challenge) >= 2 {
		if (challenge[0] == '\'' && challenge[len(challenge)-1] == '\'') ||
			(challenge[0] == '"' && challenge[len(challenge)-1] == '"') {
			origLen := len(challenge)
			challenge = challenge[1 : len(challenge)-1]
			warn("Challenge had surrounding quotes (length %d->%d) - stripped automatically", origLen, len(challenge))
		}
	}
	if challenge != "" {
		dbg("Challenge password length: %d", len(challenge))
	}

	if *flagURL == "" {
		fmt.Fprintln(os.Stderr, "Usage: scepclient -url <SCEP_URL> [options]")
		flag.PrintDefaults()
		os.Exit(exitClientError)
	}

	baseURL := strings.TrimRight(*flagURL, "/")
	info("SCEP Client starting")
	info("Server URL: %s", baseURL)

	// Transport security (informational - not an RFC requirement)
	if strings.HasPrefix(baseURL, "https://") {
		rfcOK("Using HTTPS transport")
	} else {
		info("Using plain HTTP transport")
	}

	// Step 1: GetCACaps
	caps, err := getCACaps(baseURL)
	if err != nil {
		fatal(exitNetwork, "GetCACaps failed: %v", err)
	}

	// Select the CMS content-encryption algorithm once, before any envelope is
	// built. AES is mandatory unless the operator explicitly opts into the
	// 56-bit single-DES fallback, which is cryptographically broken and
	// violates RFC 8894 §2.9.
	if caps.aes {
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
		info("Content encryption: AES-128-CBC")
	} else if *flagAllowWeak {
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmDESCBC
		rfcWarn("2.9", "CA does not advertise AES; using DES-CBC (56-bit, INSECURE) because -allow-weak-crypto was set")
	} else {
		fatal(exitProtoFail, "CA does not advertise AES content encryption; refusing to fall back to 56-bit DES (RFC 8894 §2.9). Re-run with -allow-weak-crypto to override.")
	}

	// Step 2: GetCACert
	caCerts, err := getCACert(baseURL)
	if err != nil {
		fatal(exitNetwork, "GetCACert failed: %v", err)
	}
	if len(caCerts) == 0 {
		fatal(exitProtoFail, "No CA certificates received")
	}

	// Authenticate the CA and build the trust anchor used to verify every
	// signed response. A malformed -ca-fingerprint is a local usage error
	// (exit 5); any other failure means the CA data is untrustworthy (exit 1).
	roots, anchor, err := buildCATrustPool(caCerts, *flagCAFingerprint)
	if err != nil {
		var lfe *localFlagError
		if errors.As(err, &lfe) {
			fatal(exitClientError, "%v", err)
		}
		fatal(exitProtoFail, "CA trust establishment failed: %v", err)
	}

	// Save the authenticated CA certificate (the trust anchor, not an RA cert).
	if err := savePEM(*flagCACertOut, "CERTIFICATE", anchor.Raw, 0o644); err != nil {
		fatal(exitClientError, "Saving CA cert: %v", err)
	}
	info("CA certificate saved to %s", *flagCACertOut)

	// Select the encryption recipient (RA cert with keyEncipherment when the
	// CA delegates to one, otherwise the CA itself).
	_, caCert, err := selectCACerts(caCerts)
	if err != nil {
		fatal(exitProtoFail, "Selecting encryption recipient: %v", err)
	}

	// Step 3: Get or create RSA key
	key, err := getOrCreateKey(*flagKey, *flagKeySize)
	if err != nil {
		fatal(exitClientError, "Key setup failed: %v", err)
	}

	// Determine message type and load renewal cert early (need subject for CSR)
	msgType := msgTypePKCSReq
	var signerCert *x509.Certificate
	csrCN, csrOrg, csrCountry := *flagCN, *flagOrg, *flagCountry

	if *flagRenew {
		msgType = msgTypeRenewalReq
		ok("Mode: RENEWAL (messageType=%s)", msgType)
		if *flagRenewCert == "" {
			fatal(exitClientError, "-renew requires -renew-cert <path> to existing certificate")
		}
		if !caps.renewal {
			warn("-renew requested but the CA did not advertise the Renewal capability (RFC 8894 S3.1) - the request may be rejected")
		}
		if challenge != "" {
			warn("Challenge password provided for renewal - RFC 8894 S2.4: clients SHOULD omit challengePassword but MAY include it")
		}

		// Load existing certificate — used as CMS signer AND as subject source for CSR
		info("=== Loading Existing Certificate (for Renewal) ===")
		certData, err := os.ReadFile(*flagRenewCert)
		if err != nil {
			fatal(exitClientError, "Reading renewal cert %s: %v", *flagRenewCert, err)
		}
		block, _ := pem.Decode(certData)
		if block == nil {
			fatal(exitClientError, "No PEM block found in %s", *flagRenewCert)
		}
		signerCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			fatal(exitClientError, "Parsing renewal cert: %v", err)
		}
		// The renewal cert must correspond to the loaded private key; otherwise
		// the CMS signature would be made with a key the cert does not certify,
		// which the CA will reject (and which usually means the wrong -key or
		// -renew-cert was supplied).
		if pubKeyHash(signerCert.PublicKey) != pubKeyHash(&key.PublicKey) {
			fatal(exitClientError, "Renewal certificate public key does not match the private key in %s (wrong -renew-cert or -key?)", *flagKey)
		}
		info("Using existing cert as signer: subject=%q serial=%s", signerCert.Subject.CommonName, signerCert.SerialNumber)
		if time.Now().After(signerCert.NotAfter) {
			warn("Existing certificate is EXPIRED (notAfter=%s) - renewal may be rejected", signerCert.NotAfter.Format(time.RFC3339))
		}

		// Extract subject from existing cert for the renewal CSR
		csrCN = signerCert.Subject.CommonName
		if len(signerCert.Subject.Organization) > 0 {
			csrOrg = signerCert.Subject.Organization[0]
		}
		if len(signerCert.Subject.Country) > 0 {
			csrCountry = signerCert.Subject.Country[0]
		}
		info("Renewal CSR will use subject from existing cert: CN=%q O=%q C=%q", csrCN, csrOrg, csrCountry)
	} else {
		ok("Mode: INITIAL ENROLLMENT (messageType=%s)", msgType)
	}

	// Step 4: Create CSR
	csrDER, csr, err := createCSR(key, csrCN, csrOrg, csrCountry, challenge)
	if err != nil {
		fatal(exitClientError, "CSR creation failed: %v", err)
	}

	// Step 5: Signer certificate (for initial enrollment, create self-signed)
	if !*flagRenew {
		signerCert, err = createSelfSignedCert(key, csr)
		if err != nil {
			fatal(exitClientError, "Self-signed cert creation failed: %v", err)
		}
	}

	// Step 6: Transaction metadata
	txn, err := newTransaction(csr)
	if err != nil {
		fatal(exitClientError, "Transaction setup failed: %v", err)
	}

	// Step 7: Encrypt CSR
	envelope, err := encryptCSR(csrDER, caCert)
	if err != nil {
		fatal(exitClientError, "CSR encryption failed: %v", err)
	}

	// Step 8: Sign envelope
	msg, err := signEnvelope(envelope, signerCert, key, txn, msgType, caps)
	if err != nil {
		fatal(exitClientError, "Envelope signing failed: %v", err)
	}

	// Step 9: Send PKIOperation
	respBytes, err := sendPKIOperation(baseURL, msg, caps)
	if err != nil {
		fatal(exitNetwork, "PKIOperation failed: %v", err)
	}

	// Step 10: Parse CertRep
	result, err := parseCertRep(respBytes, roots)
	if err != nil {
		fatal(exitProtoFail, "CertRep parsing failed: %v", err)
	}

	// Step 11: Validate response
	if err := validateResponse(result, txn); err != nil {
		fatal(exitProtoFail, "Response validation failed: %v", err)
	}

	// Handle status
	switch result.pkiStatus {
	case statusSUCCESS:
		if !silent {
			fmt.Fprintf(os.Stderr, cGreen+"[OK]"+cReset+"     pkiStatus = "+cGreen+"SUCCESS"+cReset+" - certificate issued!\n")
		}
	case statusFAILURE:
		name := failInfoNames[result.failInfo]
		if name == "" {
			name = "unknown (" + result.failInfo + ")"
		}
		if !silent {
			fmt.Fprintf(os.Stderr, cRed+"[FAIL]"+cReset+"  pkiStatus = "+cRed+"FAILURE"+cReset+" - failInfo: %s\n", name)
			if result.failInfo == "2" {
				fmt.Fprintf(os.Stderr, cYellow+"[HINT]"+cReset+"  Wrong/missing challenge password or name constraints? Check CA logs for the exact reason.\n")
			}
		}
		printRFCSummary()
		os.Exit(exitProtoFail)
	case statusPENDING:
		if !silent {
			fmt.Fprintf(os.Stderr, cCyan+"[INFO]"+cReset+"  pkiStatus = "+cCyan+"PENDING"+cReset+" — manual approval required\n")
		}
		if *flagNoPoll {
			warn("Polling disabled (--no-poll). Approve the request on the CA, then re-run.")
			printRFCSummary()
			os.Exit(exitPending)
		}

		// Auto-poll: build CertPoll messages until SUCCESS, FAILURE, or timeout
		info("Starting automatic polling (interval=%s, timeout=%s)", *flagPollInterval, *flagPollTimeout)
		pollStart := time.Now()
		pollDeadline := pollStart.Add(*flagPollTimeout)
		pollCount := 0
		for {
			if time.Now().After(pollDeadline) {
				fatal(exitPollTimeout, "Polling timeout (%s) exceeded after %d attempt(s)", *flagPollTimeout, pollCount)
			}
			time.Sleep(*flagPollInterval)
			pollCount++

			// Each CertPoll carries a fresh senderNonce. Per RFC 8894 §3.3.2 and
			// Appendix A the CertPoll itself omits recipientNonce; the CA echoes
			// this senderNonce back as the recipientNonce we validate.
			pollTxn := &scepTransaction{
				transactionID: txn.transactionID,
				senderNonce:   make([]byte, 16),
			}
			if _, err := rand.Read(pollTxn.senderNonce); err != nil {
				fatal(exitClientError, "Generating poll senderNonce: %v", err)
			}

			info("CertPoll attempt %d (deadline in %s)", pollCount, time.Until(pollDeadline).Round(time.Second))

			// Build IssuerAndSubject as poll content
			pollContent, err := buildIssuerAndSubject(caCert, csr)
			if err != nil {
				fatal(exitClientError, "Building IssuerAndSubject: %v", err)
			}

			// Encrypt IssuerAndSubject to CA
			pollEnvelope, err := encryptCSR(pollContent, caCert)
			if err != nil {
				fatal(exitClientError, "Encrypting poll content: %v", err)
			}

			// Sign with messageType=20 (GetCertInitial)
			pollMsg, err := signEnvelope(pollEnvelope, signerCert, key, pollTxn, msgTypeCertPoll, caps)
			if err != nil {
				fatal(exitClientError, "Signing poll message: %v", err)
			}

			// Send
			pollResp, err := sendPKIOperation(baseURL, pollMsg, caps)
			if err != nil {
				warn("CertPoll attempt %d failed: %v (will retry)", pollCount, err)
				continue
			}

			// Parse response
			pollResult, err := parseCertRep(pollResp, roots)
			if err != nil {
				fatal(exitProtoFail, "CertPoll response verification failed: %v", err)
			}
			if err := validateResponse(pollResult, pollTxn); err != nil {
				fatal(exitProtoFail, "CertPoll response validation failed: %v", err)
			}

			switch pollResult.pkiStatus {
			case statusSUCCESS:
				if !silent {
					fmt.Fprintf(os.Stderr, cGreen+"[OK]"+cReset+"     pkiStatus = "+cGreen+"SUCCESS"+cReset+" — certificate issued (after %d poll(s))!\n", pollCount)
				}
				result = pollResult
				goto extractCert
			case statusFAILURE:
				name := failInfoNames[pollResult.failInfo]
				if name == "" {
					name = "unknown (" + pollResult.failInfo + ")"
				}
				if !silent {
					fmt.Fprintf(os.Stderr, cRed+"[FAIL]"+cReset+"  pkiStatus = "+cRed+"FAILURE"+cReset+" — failInfo: %s (during poll %d)\n", name, pollCount)
				}
				printRFCSummary()
				os.Exit(exitProtoFail)
			case statusPENDING:
				info("Still PENDING (attempt %d/%s elapsed)", pollCount, time.Since(pollStart).Round(time.Second))
			}
		}
	default:
		printRFCSummary()
		fatal(exitProtoFail, "Unknown pkiStatus: %s", result.pkiStatus)
	}

extractCert:
	// Step 12: Decrypt and extract issued cert
	issuedCert, err := decryptCertRep(result, signerCert, key)
	if err != nil {
		fatal(exitClientError, "Certificate extraction failed: %v", err)
	}

	// The issued certificate MUST certify our own public key (RFC 8894 S3.3.2).
	// A mismatch means the CA bound the certificate to a different key, so it is
	// useless to us and a sign of a misissue or a swapped response; fail without
	// writing it to disk.
	issuedPubHash := pubKeyHash(issuedCert.PublicKey)
	clientPubHash := pubKeyHash(&key.PublicKey)
	if issuedPubHash != clientPubHash {
		dbg("  Issued cert pubkey: %s", issuedPubHash)
		dbg("  Client key pubkey:  %s", clientPubHash)
		fatal(exitProtoFail, "Issued certificate public key does not match the client private key (RFC 8894 S3.3.2); not saving certificate")
	}
	rfcOK("Issued certificate public key matches client key")

	// Step 13: Save issued certificate atomically (temp + rename) so a failed
	// write never leaves a corrupt or partial cert in place, for both initial
	// enrollment and renewal.
	tmpPath := *flagOut + ".tmp"
	if err := savePEM(tmpPath, "CERTIFICATE", issuedCert.Raw, 0o644); err != nil {
		fatal(exitClientError, "Saving issued cert to temp file: %v", err)
	}
	if err := os.Rename(tmpPath, *flagOut); err != nil {
		_ = os.Remove(tmpPath)
		fatal(exitClientError, "Renaming temp cert %s -> %s: %v", tmpPath, *flagOut, err)
	}
	dbg("Atomic write: %s -> %s", tmpPath, *flagOut)
	ok("Issued certificate saved to %s", *flagOut)
	ok("Private key: %s", *flagKey)
	ok("CA certificate: %s", *flagCACertOut)
	printRFCSummary()
}
