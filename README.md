# scepclient

A minimal, single-binary SCEP client written in Go, strictly following [RFC 8894](https://www.rfc-editor.org/rfc/rfc8894) (Simple Certificate Enrolment Protocol).

AI-assisted development, built from scratch using only the Go standard library and [smallstep/pkcs7](https://github.com/smallstep/pkcs7) for CMS operations. Every protocol step is performed explicitly with detailed logging and RFC compliance checks.

## Features

- **Initial enrollment** (PKCSReq, messageType 19)
- **Certificate renewal** (RenewalReq, messageType 17) using existing certificate as CMS signer
- **Automatic polling** on PENDING status with configurable interval and timeout
- **RFC 8894 compliance checking** — colored warnings for protocol deviations
- **Structured exit codes** (0–5) for scripting and automation
- **Silent mode** — no output, communicate only via exit codes
- **Verbose mode** — full CMS operation trace for debugging
- **Atomic certificate write** on renewal to prevent corruption of existing cert
- **Challenge password** — supports file-based input to avoid shell quoting issues
- **Custom TLS roots** — for HTTPS servers with private CA chains
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
| `-cacert` | `ca.pem` | Output CA certificate path |
| `-tls-roots` | | PEM file with custom TLS root CA(s) for HTTPS |
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
| `1` | Protocol failure — pkiStatus=FAILURE |
| `2` | Pending — manual approval required (with `-no-poll`) |
| `3` | Polling timeout — PENDING not resolved within `-poll-timeout` |
| `4` | Network/HTTP error — server unreachable or returned error |
| `5` | Client-side error — bad arguments, file I/O, key generation, CMS error |

## Protocol Flow

The client implements the complete SCEP enrollment flow:

1. **GetCACaps** — discover server capabilities (POST support, AES, SHA-256)
2. **GetCACert** — retrieve CA certificate chain
3. **Generate RSA key** — or load existing key from file
4. **Create CSR** — PKCS#10 with optional challengePassword (raw ASN.1)
5. **Self-signed cert** — temporary signer for CMS (or existing cert for renewal)
6. **Transaction metadata** — transactionID (SHA-256 of public key), senderNonce
7. **Encrypt CSR** — CMS EnvelopedData to CA certificate (AES-128 or 3DES)
8. **Sign envelope** — CMS SignedData with SCEP authenticated attributes
9. **PKIOperation** — HTTP POST (or GET fallback)
10. **Parse CertRep** — extract pkiStatus, validate nonces and transactionID
11. **CertPoll** *(if PENDING)* — automatic polling with IssuerAndSubject (messageType 20)
12. **Decrypt** — extract issued certificate from CMS envelope
13. **Save** — write certificate, key, and CA cert to disk

## RFC 8894 Compliance Checks

The client validates server behavior against RFC 8894 and reports deviations:

- **S3.5.2** — Capability advertisement (POSTPKIOperation, AES, SHA-256, SCEPStandard)
- **S4.2** — CA certificate properties (RSA key type, key size, KeyUsage, validity)
- **S4.3** — PKIOperation response Content-Type
- **S3.2.1.1** — CertRep messageType
- **S3.2.1.2** — transactionID match
- **S3.2.1.4** — failInfo presence on FAILURE
- **S3.2.1.5** — recipientNonce/senderNonce validation
- **S2.3** — Client RSA key size
- **S2.4** — challengePassword in renewal requests

## Dependencies

- [github.com/smallstep/pkcs7](https://github.com/smallstep/pkcs7) v0.2.1 — CMS/PKCS#7 operations
- Go standard library — crypto, ASN.1, HTTP, x509

## Limitations

- **RSA only** — SCEP (RFC 8894) defines RSA key transport; EC keys on the CA cert are not supported
- **No GetCRL** — CRL retrieval is not implemented

## License

MIT
