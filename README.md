# mdoc - Go Library for ISO 18013-5 Mobile Documents

A Go implementation of ISO 18013-5/7 compliant mobile Driver License (mDL) issuance and verification.

> **Disclaimer:** This is a fun experiment; use at your peril. It is not intended for production use.

## Features

- **Document Issuance**: Create and sign mDL documents with COSE Sign1
- **Selective Disclosure**: Generate device responses with only requested attributes
- **Verification**: Verify issuer signatures, device authentication, and data integrity
- **OID4VP Support**: Session transcript handling for OpenID for Verifiable Presentations
- **Multiple Auth Methods**: Support for both MAC and signature-based device authentication
- **CBOR Encoding**: Full CBOR support with custom tags (DateOnly, DataItem)

## Installation

```bash
go get github.com/georgepadayatti/mdoc
```

## Quick Start

### Issuing a Document

```go
package main

import (
    "crypto/x509"
    "encoding/pem"
    "log"
    "time"

    "github.com/georgepadayatti/mdoc/mdoc"
)

func main() {
    // Parse issuer credentials
    block, _ := pem.Decode([]byte(issuerPrivateKeyPEM))
    privateKey, _ := x509.ParsePKCS8PrivateKey(block.Bytes)

    // Create and sign document
    doc, err := mdoc.NewDocument(mdoc.DocTypeMDL).
        AddIssuerNameSpace(mdoc.NamespaceMDL, map[string]any{
            "family_name":     "Jones",
            "given_name":      "Ava",
            "birth_date":      "2007-03-25",
            "issue_date":      "2023-09-01",
            "expiry_date":     "2028-09-30",
            "issuing_country": "US",
            "document_number": "DL-123456",
        }).
        AddDeviceKeyInfo(devicePublicKey).
        AddValidityInfo(mdoc.ValidityInfo{
            Signed:     time.Now(),
            ValidFrom:  time.Now(),
            ValidUntil: time.Now().AddDate(5, 0, 0),
        }).
        Sign(mdoc.SignParams{
            IssuerPrivateKey:  privateKey,
            IssuerCertificate: []byte(issuerCertPEM),
            Algorithm:         mdoc.AlgorithmES256,
        })

    if err != nil {
        log.Fatal(err)
    }

    // Encode for storage/transmission
    encoded, _ := mdoc.NewMDoc(doc).Encode()
}
```

### Verifying a Document

```go
package main

import (
    "log"

    "github.com/georgepadayatti/mdoc/mdoc"
)

func main() {
    // Create verifier with trusted certificates
    verifier, err := mdoc.NewVerifier([][]byte{
        []byte(trustedIssuerCertPEM),
    })
    if err != nil {
        log.Fatal(err)
    }

    // Create session transcript for OID4VP
    transcript, _ := mdoc.CreateSessionTranscriptOID4VP(
        mdocNonce, clientID, responseURI, verifierNonce,
    )

    // Verify the device response
    result, err := verifier.Verify(encodedResponse, mdoc.VerifyOptions{
        EncodedSessionTranscript: transcript,
        EphemeralReaderKey:       readerPrivateKey, // For MAC verification
    })

    if err != nil {
        log.Fatal("Verification failed:", err)
    }

    // Access verified attributes
    for _, doc := range result.Documents {
        attrs := doc.GetIssuerNameSpace(mdoc.NamespaceMDL)
        log.Printf("Family Name: %s", attrs["family_name"])
    }
}
```

### Creating a Device Response (Selective Disclosure)

```go
package main

import (
    "log"

    "github.com/georgepadayatti/mdoc/mdoc"
)

func main() {
    // Parse the stored mDL
    storedMDoc, _ := mdoc.Parse(storedMDocBytes)

    // Build presentation definition (what verifier requests)
    pd := mdoc.BuildMDLPresentationDefinition("request-id",
        "family_name", "given_name", "birth_date",
    )

    // Create device response with selective disclosure
    response, err := mdoc.DeviceResponseFrom(storedMDoc).
        UsingPresentationDefinition(pd).
        UsingSessionTranscriptForOID4VP(
            mdocNonce, clientID, responseURI, verifierNonce,
        ).
        AuthenticateWithSignature(devicePrivateKey, mdoc.AlgorithmES256).
        Sign()

    if err != nil {
        log.Fatal(err)
    }

    // Encode for transmission
    encoded, _ := response.Encode()
}
```

## Package Structure

```
mdoc/
├── mdoc/           # Main library package
│   ├── document.go         # Document builder for issuance
│   ├── device_response.go  # Device response builder
│   ├── verifier.go         # Verification logic
│   ├── parser.go           # CBOR parsing
│   ├── types.go            # Type definitions
│   └── ...
├── cbor/           # CBOR utilities
│   ├── cbor.go             # Encode/decode wrappers
│   ├── dateonly.go         # DateOnly type (tag 1004)
│   └── dataitem.go         # DataItem (tag 24)
├── cose/           # COSE utilities
│   └── cosekey.go          # COSE key conversion
└── examples/       # Example applications
    ├── issuance/           # Document issuance
    ├── verification/       # Document verification
    └── device_response/    # Selective disclosure
```

## API Reference

### Document Builder

The `Document` type provides a fluent API for creating mDL documents:

| Method | Description |
|--------|-------------|
| `NewDocument(docType)` | Create a new document builder |
| `AddIssuerNameSpace(ns, values)` | Add attributes to a namespace |
| `AddDeviceKeyInfo(publicKey)` | Set the device's public key |
| `AddValidityInfo(info)` | Set validity period |
| `UseDigestAlgorithm(alg)` | Set digest algorithm (default: SHA-256) |
| `Sign(params)` | Sign and return IssuerSignedDocument |

### Device Response Builder

The `DeviceResponse` type creates selective disclosure responses:

| Method | Description |
|--------|-------------|
| `DeviceResponseFrom(mdoc)` | Create builder from stored mDL |
| `UsingPresentationDefinition(pd)` | Set requested attributes |
| `UsingSessionTranscriptForOID4VP(...)` | Set OID4VP session transcript |
| `AuthenticateWithSignature(key, alg)` | Use signature authentication |
| `AuthenticateWithMAC(key, pubKey, alg)` | Use MAC authentication |
| `Sign()` | Build and sign the response |

### Verifier

The `Verifier` type validates device responses:

| Method | Description |
|--------|-------------|
| `NewVerifier(trustedCerts)` | Create verifier with trusted roots |
| `Verify(data, options)` | Verify and return parsed mDL |

### Verification Options

```go
type VerifyOptions struct {
    EphemeralReaderKey       []byte // For MAC verification
    EncodedSessionTranscript []byte // Session transcript
    OnCheck                  func(VerificationAssessment) error // Callback
    DisableCertificateChainValidation bool
}
```

## Supported Algorithms

### Signature Algorithms
- `AlgorithmES256` - ECDSA with P-256 and SHA-256
- `AlgorithmES384` - ECDSA with P-384 and SHA-384
- `AlgorithmES512` - ECDSA with P-521 and SHA-512
- `AlgorithmEdDSA` - EdDSA with Ed25519

### Digest Algorithms
- `DigestAlgorithmSHA256`
- `DigestAlgorithmSHA384`
- `DigestAlgorithmSHA512`

### MAC Algorithms
- `MacAlgorithmHS256` - HMAC with SHA-256

## Examples

See the [examples](./examples) directory for complete working examples:

- **[Issuance](./examples/issuance)** - Create and sign mDL documents
- **[Verification](./examples/verification)** - Verify device responses
- **[Device Response](./examples/device_response)** - Selective disclosure

## Standards Compliance

This library implements:
- **ISO/IEC 18013-5:2021** - Personal identification - ISO-compliant driving licence - Part 5: Mobile driving licence (mDL) application
- **ISO/IEC 18013-7** - Mobile driving licence (mDL) add-on functions
- **OpenID for Verifiable Presentations (OID4VP)** - Session transcript format

## Dependencies

- [github.com/fxamacker/cbor/v2](https://github.com/fxamacker/cbor) - CBOR encoding/decoding
- [github.com/veraison/go-cose](https://github.com/veraison/go-cose) - COSE signing
- [golang.org/x/crypto](https://golang.org/x/crypto) - HKDF key derivation

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

