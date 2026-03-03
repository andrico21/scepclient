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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
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
		fmt.Fprintf(os.Stderr, cCyan+"[INFO]"+cReset+"  "+format+"\n", a...)
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

func savePEM(path string, typ string, der []byte) error {
	f, err := os.Create(path)
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
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
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
	if status != 200 {
		return nil, fmt.Errorf("GetCACaps: HTTP %d", status)
	}

	caps := &caCaps{}
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

// ---------------------------------------------------------------------------
// Step 3: Generate or load RSA private key
// ---------------------------------------------------------------------------

func getOrCreateKey(keyPath string, keySize int) (*rsa.PrivateKey, error) {
	info("=== Step 3: Private Key ===")

	if keyPath != "" {
		if _, err := os.Stat(keyPath); err == nil {
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
		if err := savePEM(keyPath, "RSA PRIVATE KEY", der); err != nil {
			return nil, fmt.Errorf("saving key to %s: %w", keyPath, err)
		}
		info("Saved key to %s", keyPath)
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
//	    values SET { UTF8String challenge }
//	}
func buildChallengePasswordAttr(challenge string) ([]byte, error) {
	oidDER, err := asn1.Marshal(oidChallengePassword)
	if err != nil {
		return nil, err
	}

	// Encode the password as UTF8String (PrintableString won't work for special chars)
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

	// Parse it back to verify
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		// Go's parser may fail on non-standard attributes; dump DER for debugging
		dbg("  [WARN] Go x509.ParseCertificateRequest failed: %v", err)
		dbg("  CSR DER (base64): %s", base64.StdEncoding.EncodeToString(csrDER))
		// Try to continue — the DER may still be valid per RFC even if Go can't parse it
		info("CSR created (raw ASN.1): subject CN=%q, sigAlg=SHA256WithRSA", cn)
		dbg("  CSR DER size: %d bytes", len(csrDER))
		if challenge != "" {
			dbg("  challengePassword: present (not logged for security)")
		}
		return csrDER, nil, nil
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
		_ = savePEM("debug-csr.pem", "CERTIFICATE REQUEST", csrDER)
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
			dbg("  The attribute IS present in the raw DER; dumping challengePassword attr hex:")
			attrHex, _ := buildChallengePasswordAttr(challenge)
			dbg("  challengePassword Attribute DER: %s", hex.EncodeToString(attrHex))
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

func encryptCSR(csrDER []byte, caCert *x509.Certificate, caps *caCaps) ([]byte, error) {
	info("=== Step 7: Encrypt CSR → CMS EnvelopedData ===")

	recipients := []*x509.Certificate{caCert}
	dbg("  Encrypting %d bytes of CSR to %d recipient(s)", len(csrDER), len(recipients))
	dbg("  Recipient: %q (fingerprint=%s)", caCert.Subject.CommonName, fingerprint(caCert))

	// Choose encryption algorithm based on capabilities
	var algName string
	if caps.aes {
		algName = "AES-128-CBC"
		dbg("  Using AES-128-CBC encryption (server supports AES)")
	} else if caps.des3 {
		algName = "DES3-CBC"
		dbg("  Using 3DES-CBC encryption (AES not available)")
	} else {
		algName = "DES3-CBC (fallback)"
		rfcWarn("3.5.2", "No encryption capability advertised - falling back to 3DES-CBC (weak)")
	}

	// Set content encryption algorithm to match server capabilities
	if caps.aes {
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
	} else {
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmDESCBC
	}
	envelope, err := pkcs7.Encrypt(csrDER, recipients)
	if err != nil {
		return nil, fmt.Errorf("CMS Encrypt (algo=%s): %w", algName, err)
	}

	dbg("  EnvelopedData size: %d bytes", len(envelope))

	// Verify we can parse the envelope back
	p7, err := pkcs7.Parse(envelope)
	if err != nil {
		dbg("  [WARN] Could not re-parse envelope for verification: %v", err)
	} else {
		dbg("  EnvelopedData re-parse: OK (content-type verified)")
		_ = p7
	}

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

func signEnvelope(envelope []byte, signerCert *x509.Certificate, key *rsa.PrivateKey, txn *scepTransaction, messageType string) ([]byte, error) {
	info("=== Step 8: Sign Envelope → CMS SignedData ===")

	sd, err := pkcs7.NewSignedData(envelope)
	if err != nil {
		return nil, fmt.Errorf("creating SignedData: %w", err)
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
		body, hdrs, status, err := httpPost(u, "application/octet-stream", msg)
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
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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

func parseCertRep(data []byte, caCerts []*x509.Certificate) (*certRepResult, error) {
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

	// Verify signature. Add CA certs so verification chain can be built.
	// Note: The response is signed by the CA, so we need to trust it.
	if err := p7.Verify(); err != nil {
		dbg("  Signature verification failed: %v", err)
		dbg("  Attempting verification with CA certs injected...")

		// Try with CA certs added
		for _, caCert := range caCerts {
			p7.Certificates = append(p7.Certificates, caCert)
		}
		if err2 := p7.Verify(); err2 != nil {
			rfcWarn("4.3", "CertRep signature verification failed: %v (continuing anyway)", err2)
		} else {
			dbg("  Signature verification: OK (with CA certs)")
		}
	} else {
		dbg("  Signature verification: OK")
	}

	result := &certRepResult{raw: p7}

	// Extract SCEP attributes
	// pkiStatus (REQUIRED - RFC 8894 S3.2.1.3)
	var statusRaw string
	if err := p7.UnmarshalSignedAttribute(oidSCEPpkiStatus, &statusRaw); err != nil {
		return nil, fmt.Errorf("extracting pkiStatus: %w", err)
	}
	result.pkiStatus = statusRaw
	dbg("  pkiStatus = %s", statusRaw)

	// messageType (REQUIRED - RFC 8894 S3.2.1.1)
	var msgType string
	if err := p7.UnmarshalSignedAttribute(oidSCEPmessageType, &msgType); err != nil {
		rfcWarn("3.2.1.1", "CertRep missing messageType attribute: %v", err)
	} else {
		result.messageType = msgType
		dbg("  messageType = %s", msgType)
		if msgType != msgTypeCertRep {
			rfcWarn("3.2.1.1", "Expected messageType=3 (CertRep), got %q", msgType)
		} else {
			rfcOK("messageType = 3 (CertRep)")
		}
	}

	// transactionID (REQUIRED - RFC 8894 S3.2.1.2)
	var txnID string
	if err := p7.UnmarshalSignedAttribute(oidSCEPtransactionID, &txnID); err != nil {
		rfcWarn("3.2.1.2", "CertRep missing transactionID attribute: %v", err)
	} else {
		result.transactionID = txnID
		dbg("  transactionID = %s", txnID)
	}

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

func validateResponse(result *certRepResult, txn *scepTransaction) {
	info("=== Step 11: Validate Response ===")

	// Check transactionID matches (REQUIRED - RFC 8894 S3.2.1.2)
	if result.transactionID != "" && result.transactionID != txn.transactionID {
		rfcWarn("3.2.1.2", "transactionID mismatch: sent=%s received=%s", txn.transactionID, result.transactionID)
	} else if result.transactionID != "" {
		rfcOK("transactionID: MATCH")
	}

	// Check recipientNonce matches our senderNonce (RFC 8894 S3.2.1.5)
	if len(result.recipNonce) > 0 {
		if hex.EncodeToString(result.recipNonce) != hex.EncodeToString(txn.senderNonce) {
			rfcWarn("3.2.1.5", "recipientNonce does not match senderNonce!")
			dbg("  senderNonce:    %s", hex.EncodeToString(txn.senderNonce))
			dbg("  recipientNonce: %s", hex.EncodeToString(result.recipNonce))
		} else {
			rfcOK("recipientNonce matches senderNonce")
		}
	} else {
		rfcWarn("3.2.1.5", "CertRep does not contain recipientNonce - required by RFC 8894")
	}

	// Log CA's own senderNonce (informational — used for future polling)
	if len(result.senderNonce) > 0 {
		dbg("  CA senderNonce: %s (would be used as recipientNonce in polling)", hex.EncodeToString(result.senderNonce))
	}
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
		dbg("Challenge password length: %d, first byte: 0x%02x, last byte: 0x%02x",
			len(challenge), challenge[0], challenge[len(challenge)-1])
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

	// Step 2: GetCACert
	caCerts, err := getCACert(baseURL)
	if err != nil {
		fatal(exitNetwork, "GetCACert failed: %v", err)
	}
	if len(caCerts) == 0 {
		fatal(exitNetwork, "No CA certificates received")
	}

	// Save CA cert
	if err := savePEM(*flagCACertOut, "CERTIFICATE", caCerts[0].Raw); err != nil {
		fatal(exitClientError, "Saving CA cert: %v", err)
	}
	info("CA certificate saved to %s", *flagCACertOut)

	// Use the first cert as the encryption recipient
	caCert := caCerts[0]

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
	envelope, err := encryptCSR(csrDER, caCert, caps)
	if err != nil {
		fatal(exitClientError, "CSR encryption failed: %v", err)
	}

	// Step 8: Sign envelope
	msg, err := signEnvelope(envelope, signerCert, key, txn, msgType)
	if err != nil {
		fatal(exitClientError, "Envelope signing failed: %v", err)
	}

	// Step 9: Send PKIOperation
	respBytes, err := sendPKIOperation(baseURL, msg, caps)
	if err != nil {
		fatal(exitNetwork, "PKIOperation failed: %v", err)
	}

	// Step 10: Parse CertRep
	result, err := parseCertRep(respBytes, caCerts)
	if err != nil {
		fatal(exitClientError, "CertRep parsing failed: %v", err)
	}

	// Step 11: Validate response
	validateResponse(result, txn)

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
		pollDeadline := time.Now().Add(*flagPollTimeout)
		pollCount := 0
		for {
			if time.Now().After(pollDeadline) {
				fatal(exitPollTimeout, "Polling timeout (%s) exceeded after %d attempt(s)", *flagPollTimeout, pollCount)
			}
			time.Sleep(*flagPollInterval)
			pollCount++

			// Update nonce: use CA's senderNonce as our new recipientNonce
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
			pollEnvelope, err := encryptCSR(pollContent, caCert, caps)
			if err != nil {
				fatal(exitClientError, "Encrypting poll content: %v", err)
			}

			// Sign with messageType=20 (GetCertInitial)
			pollMsg, err := signEnvelope(pollEnvelope, signerCert, key, pollTxn, msgTypeCertPoll)
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
			pollResult, err := parseCertRep(pollResp, caCerts)
			if err != nil {
				warn("CertPoll attempt %d: parse error: %v (will retry)", pollCount, err)
				continue
			}
			validateResponse(pollResult, pollTxn)

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
				info("Still PENDING (attempt %d/%s elapsed)", pollCount, time.Since(pollDeadline.Add(-*flagPollTimeout)).Round(time.Second))
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

	// Validate issued certificate public key matches our private key
	issuedPubHash := pubKeyHash(issuedCert.PublicKey)
	clientPubHash := pubKeyHash(&key.PublicKey)
	if issuedPubHash != clientPubHash {
		rfcWarn("4.3", "Issued certificate public key does NOT match client key!")
		dbg("  Issued cert pubkey: %s", issuedPubHash)
		dbg("  Client key pubkey:  %s", clientPubHash)
	} else {
		rfcOK("Issued certificate public key matches client key")
	}

	// Step 13: Save issued certificate
	// For renewal: use atomic write (temp + rename) to avoid corrupting the
	// existing certificate if something goes wrong during the write.
	if *flagRenew {
		tmpPath := *flagOut + ".tmp"
		if err := savePEM(tmpPath, "CERTIFICATE", issuedCert.Raw); err != nil {
			fatal(exitClientError, "Saving issued cert to temp file: %v", err)
		}
		if err := os.Rename(tmpPath, *flagOut); err != nil {
			fatal(exitClientError, "Renaming temp cert %s -> %s: %v", tmpPath, *flagOut, err)
		}
		dbg("Atomic write: %s -> %s", tmpPath, *flagOut)
	} else {
		if err := savePEM(*flagOut, "CERTIFICATE", issuedCert.Raw); err != nil {
			fatal(exitClientError, "Saving issued cert: %v", err)
		}
	}
	ok("Issued certificate saved to %s", *flagOut)
	ok("Private key: %s", *flagKey)
	ok("CA certificate: %s", *flagCACertOut)
	printRFCSummary()
}
