# scepclient

A minimal, single-binary SCEP client written in Go, strictly following [RFC 8894](https://www.rfc-editor.org/rfc/rfc8894) (Simple Certificate Enrolment Protocol).

AI-assisted development, built from scratch using only the Go standard library and [smallstep/pkcs7](https://github.com/smallstep/pkcs7) for CMS operations. Every protocol step is performed explicitly with detailed logging and RFC compliance checks.

## Features

- **Initial enrollment** (PKCSReq, messageType 19)
- **Certificate renewal** (RenewalReq, messageType 17) using existing certificate as CMS signer
- **Automatic polling** on PENDING status with configurable interval and timeout
- **Authenticated CA trust** — every signed response is verified and chained to the CA, which is pinned out-of-band via `-ca-fingerprint` (or trusted on first use with a loud warning)
- **Fatal-by-default verification** — forged/unverifiable responses, nonce/transactionID/messageType mismatches, and key mismatches abort with no certificate written
- **RFC 8894 compliance checking** — colored warnings for protocol deviations
- **Structured exit codes** (0–5) for scripting and automation
- **Silent mode** — no output, communicate only via exit codes
- **Verbose mode** — full CMS operation trace for debugging (never logs challenge material beyond its length)
- **Atomic certificate write** for both initial enrollment and renewal to prevent corruption
- **Strong crypto by default** — refuses 56-bit single-DES unless `-allow-weak-crypto` is set
- **Challenge password** — supports file-based input to avoid shell quoting issues
- **Custom TLS roots** — for HTTPS servers with private CA chains (transport trust only; does not affect SCEP message verification)
- **Build-time version injection** via `-ldflags`
- **Self-contained** — single `main.go`, no framework dependencies

## Build

```bash
# Development build
go build -o scepclient .

# Production build (stripped, PIE, with version)
go build -buildmode=pie -trimpath -ldflags="-s -w -X main.version=1.1" -o scepclient .
```

### Cross-compilation

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -buildmode=pie -trimpath -ldflags="-s -w -X main.version=1.1" -o scepclient-linux-amd64 .

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -buildmode=pie -trimpath -ldflags="-s -w -X main.version=1.1" -o scepclient-darwin-arm64 .
```

## Usage

### Initial Enrollment

```bash
# Basic enrollment with challenge password from file
echo 'my-challenge-password' > pw.txt
./scepclient -url https://scep.example.com/scep/provisioner -challenge-file pw.txt

# With custom TLS roots and verbose output
./scepclient -url https://scep.example.com/scep/provisioner -challenge-file pw.txt -tls-roots /path/to/ca-bundle.pem -cn myhost.example.com -org "My Org" -country US -verbose
```

### Certificate Renewal

```bash
# Renew using existing certificate and key

./scepclient -url http://scep.example.com/scep/provisioner -renew -renew-cert cert.pem -key client.key
# or
./scepclient -url https://scep.example.com/scep/provisioner -renew -renew-cert cert.pem -key client.key [-tls-roots /path/to/ca-bundle.pem]
```

The renewal CSR automatically uses the subject (CN, O, C) from the existing certificate.

### All Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-url` | *(required)* | SCEP server URL |
| `-challenge` | | Challenge password (inline) |
| `-challenge-file` | | File containing challenge password |
| `-cn` | `scepclient` | Common Name for the certificate |
| `-org` | `SCEP Test` | Organization |
| `-country` | `US` | Country code |
| `-key` | `client.key` | Path to RSA private key (created if absent) |
| `-keysize` | `2048` | RSA key size when generating a new key |
| `-out` | `cert.pem` | Output certificate path |
| `-cacert` | `ca.pem` | Output CA certificate path (the authenticated CA, not an RA cert) |
| `-ca-fingerprint` | | Expected SHA-256 fingerprint of the CA certificate (64 hex chars, optionally colon-separated) for out-of-band CA authentication (RFC 8894 §2.2). When omitted, the CA is trusted on first use for this run only and its fingerprint is printed as a loud warning. |
| `-allow-weak-crypto` | `false` | Permit 56-bit single-DES content encryption when the CA does not advertise AES. **INSECURE**, violates RFC 8894 §2.9. Without it, a CA lacking AES support is rejected. |
| `-tls-roots` | | PEM file with custom TLS root CA(s) for HTTPS (transport trust only) |
| `-renew` | `false` | Renew existing certificate (messageType 17) |
| `-renew-cert` | | Path to existing certificate to renew |
| `-no-poll` | `false` | Disable automatic polling on PENDING status |
| `-poll-interval` | `30s` | Interval between CertPoll requests |
| `-poll-timeout` | `10m` | Maximum time to wait for PENDING to resolve |
| `-verbose` | `false` | Enable verbose logging |
| `-silent` | `false` | Suppress all output, communicate only via exit codes |
| `-version` | | Print version and exit |

## Output Levels

The client uses a structured output hierarchy:

| Prefix | Visibility | Meaning |
|--------|-----------|---------|
| `[OK]` | Always | Successful operation |
| `[WARN]` | Always | Non-RFC warning |
| `[RFC-WARN Sn.n]` | Always | RFC 8894 compliance deviation with section reference |
| `[HINT]` | Always | Actionable troubleshooting suggestion |
| `[FAIL]` | Always | Fatal protocol error (e.g. pkiStatus=FAILURE) |
| `[FATAL]` | Always | Unrecoverable error |
| `[INFO]` | `-verbose` | Detailed protocol trace |
| `[RFC-OK]` | `-verbose` | Passed RFC compliance check |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — certificate issued |
| `1` | Protocol/verification failure — `pkiStatus=FAILURE`, unverifiable CertRep signature/chain, transactionID/messageType/recipientNonce mismatch, CA fingerprint mismatch, or issued-cert public-key mismatch (no certificate written) |
| `2` | Pending — manual approval required (with `-no-poll`) |
| `3` | Polling timeout — PENDING not resolved within `-poll-timeout` |
| `4` | Network/HTTP error — server unreachable or transport failure |
| `5` | Client-side error — bad arguments, malformed `-ca-fingerprint`, file I/O, key generation, renewal key/cert mismatch, CMS error |

## Protocol Flow

The client implements the complete SCEP enrollment flow:

1. **GetCACaps** — discover server capabilities (POST support, AES, SHA-256)
2. **GetCACert** — retrieve and authenticate the CA (pin via `-ca-fingerprint`, or trust-on-first-use), then build the trust anchor
3. **Generate RSA key** — or load existing key from file
4. **Create CSR** — PKCS#10 with optional challengePassword (raw ASN.1)
5. **Self-signed cert** — temporary signer for CMS (or existing cert for renewal)
6. **Transaction metadata** — transactionID (SHA-256 of public key), senderNonce
7. **Encrypt CSR** — CMS EnvelopedData to the CA/RA recipient (AES-128-CBC; single-DES only with `-allow-weak-crypto`)
8. **Sign envelope** — CMS SignedData with SCEP authenticated attributes (SHA-256 digest when advertised)
9. **PKIOperation** — HTTP POST (`application/x-pki-message`) or GET fallback
10. **Parse CertRep** — verify signature/chain against the CA anchor, then validate pkiStatus, nonces, and transactionID (all mismatches fatal)
11. **CertPoll** *(if PENDING)* — automatic polling with IssuerAndSubject (messageType 20)
12. **Decrypt** — extract issued certificate and verify it certifies the client key
13. **Save** — atomically write certificate, key (mode 0600), and CA cert to disk

## RFC 8894 Compliance Checks

The client validates server behavior against RFC 8894. Trust and response-binding checks are **fatal** (the client aborts); advisory checks are reported as warnings:

- **§2.2 / §4.2.1** — CA authentication via SHA-256 whole-certificate fingerprint (`-ca-fingerprint`); mismatch, ambiguous match, or a fingerprint matching a non-CA certificate is **fatal**
- **§2.1.2 / §3.2** — CMS SignedData signature verified and chained to the authenticated CA anchor; failure is **fatal**
- **§3.2.1.1** — transactionID match; mismatch is **fatal**
- **§3.2.1.2** — CertRep messageType present and correct; missing or wrong is **fatal**
- **§3.2.1.3** — pkiStatus presence
- **§3.2.1.4** — failInfo presence on FAILURE
- **§3.2.1.5** — recipientNonce present and matching senderNonce (constant-time); missing or mismatched is **fatal**
- **§3.3.2** — issued certificate must certify the client's public key; mismatch is **fatal** (no certificate written)
- **§2.9** — content encryption must use AES; falling back to 56-bit single-DES requires `-allow-weak-crypto`
- **§3.5.2 / §4.2** — capability advertisement and CA certificate properties (advisory)
- **§2.3** — client RSA key size (advisory)
- **§2.4** — challengePassword in renewal requests (advisory)

There is intentionally **no `-lenient` flag**: once the CA is established (pinned or trust-on-first-use), response verification cannot be disabled. `-ca-fingerprint` is the only trust escape hatch and it authenticates rather than bypasses.

## Dependencies

- [github.com/smallstep/pkcs7](https://github.com/smallstep/pkcs7) v0.2.1 — CMS/PKCS#7 operations
- Go standard library — crypto, ASN.1, HTTP, x509

## Limitations

- **RSA only** — SCEP (RFC 8894) defines RSA key transport; EC keys on the CA cert are not supported
- **No GetCRL** — CRL retrieval is not implemented

## License

MIT
