package mdoc

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	fxcbor "github.com/fxamacker/cbor/v2"
	"github.com/georgepadayatti/mdoc/cbor"
	mcose "github.com/georgepadayatti/mdoc/cose"
	"github.com/veraison/go-cose"
)

// COSE Header Parameters
const (
	HeaderAlgorithm   = 1
	HeaderKeyID       = 4
	HeaderX5Chain     = 33 // x5chain - X.509 certificate chain
)

// IssuerAuth wraps a COSE_Sign1 message containing the Mobile Security Object (MSO).
type IssuerAuth struct {
	sign1       *cose.Sign1Message
	mso         *MSO
	certificate *x509.Certificate
	rawBytes    []byte
}

// NewIssuerAuth creates a new IssuerAuth from a COSE Sign1 message.
func NewIssuerAuth(sign1 *cose.Sign1Message) *IssuerAuth {
	return &IssuerAuth{sign1: sign1}
}

// Sign creates a new IssuerAuth by signing the MSO.
func (ia *IssuerAuth) Sign(params SignParams) error {
	// This would be called after setting up the MSO
	return fmt.Errorf("not implemented - use SignMSO instead")
}

// SignMSO creates and signs an MSO to produce an IssuerAuth.
func SignMSO(mso *MSO, params SignParams) (*IssuerAuth, error) {
	// Encode MSO as DataItem (tag 24)
	msoBytes, err := cbor.Encode(cbor.NewDataItem(mso))
	if err != nil {
		return nil, fmt.Errorf("failed to encode MSO: %w", err)
	}

	// Parse issuer certificate(s)
	certs, err := mcose.ParsePEMCertificates(params.IssuerCertificate)
	if err != nil {
		if cert, err := x509.ParseCertificate(params.IssuerCertificate); err == nil {
			certs = []*x509.Certificate{cert}
		} else {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
	}

	// Get private key
	privateKey, err := ParsePrivateKey(params.IssuerPrivateKey)
	if err != nil {
		return nil, err
	}

	// Find the end-entity (document signer) certificate.
	// Only the end-entity cert goes into x5chain, matching pymdoccbor behaviour
	// and what holder wallets expect. The IACA/CA cert is NOT included.
	var endEntityCert *x509.Certificate
	for _, cert := range certs {
		if !cert.IsCA {
			endEntityCert = cert
			break
		}
	}
	if endEntityCert == nil {
		// Fallback: use the first certificate
		endEntityCert = certs[0]
	}

	// Create COSE Sign1 message
	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.Algorithm(params.Algorithm))

	// Set x5chain in unprotected headers — single bstr per RFC 9360
	msg.Headers.Unprotected[HeaderX5Chain] = endEntityCert.Raw

	// Set key ID if provided
	if len(params.KeyID) > 0 {
		msg.Headers.Protected[HeaderKeyID] = params.KeyID
	}

	msg.Payload = msoBytes

	// Create signer
	signerKey, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("issuer private key is not a signer")
	}
	signer, err := cose.NewSigner(cose.Algorithm(params.Algorithm), signerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// Sign
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("failed to sign MSO: %w", err)
	}

	return &IssuerAuth{
		sign1:       msg,
		mso:         mso,
		certificate: certs[0],
	}, nil
}

// Sign1 returns the underlying COSE Sign1 message.
func (ia *IssuerAuth) Sign1() *cose.Sign1Message {
	return ia.sign1
}

// MSO returns the decoded Mobile Security Object.
func (ia *IssuerAuth) MSO() *MSO {
	if ia.mso != nil {
		return ia.mso
	}

	if ia.sign1 == nil || ia.sign1.Payload == nil {
		return nil
	}

	var mso MSO
	var di cbor.DataItem
	if err := cbor.Decode(ia.sign1.Payload, &di); err == nil {
		if inner, err := di.Bytes(); err == nil && inner != nil {
			if err := cbor.Decode(inner, &mso); err == nil {
				ia.mso = &mso
				return ia.mso
			}
		}
	}
	if err := cbor.Decode(ia.sign1.Payload, &mso); err != nil {
		return nil
	}
	ia.mso = &mso
	return ia.mso
}

// Certificate returns the X.509 certificate from x5chain.
func (ia *IssuerAuth) Certificate() *x509.Certificate {
	if ia.certificate != nil {
		return ia.certificate
	}

	if ia.sign1 == nil {
		return nil
	}

	// Get x5chain from unprotected headers
	x5chain := ia.sign1.Headers.Unprotected[HeaderX5Chain]
	if x5chain == nil {
		if v, ok := ia.sign1.Headers.Unprotected[int64(HeaderX5Chain)]; ok {
			x5chain = v
		}
	}
	if x5chain == nil {
		if v, ok := ia.sign1.Headers.Unprotected[uint64(HeaderX5Chain)]; ok {
			x5chain = v
		}
	}
	if x5chain == nil {
		return nil
	}

	var certBytes []byte
	switch v := x5chain.(type) {
	case []byte:
		certBytes = v
	case [][]byte:
		if len(v) > 0 {
			certBytes = v[0]
		}
	case []any:
		if len(v) > 0 {
			if b, ok := v[0].([]byte); ok {
				certBytes = b
			}
		}
	}

	if certBytes == nil {
		return nil
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil
	}

	ia.certificate = cert
	return cert
}

// CountryName returns the country name (C) from the certificate issuer.
func (ia *IssuerAuth) CountryName() string {
	cert := ia.Certificate()
	if cert == nil {
		return ""
	}
	if len(cert.Issuer.Country) > 0 {
		return cert.Issuer.Country[0]
	}
	return ""
}

// StateOrProvince returns the state/province (ST) from the certificate issuer.
func (ia *IssuerAuth) StateOrProvince() string {
	cert := ia.Certificate()
	if cert == nil {
		return ""
	}
	if len(cert.Issuer.Province) > 0 {
		return cert.Issuer.Province[0]
	}
	return ""
}

// Encode returns the CBOR-encoded representation.
func (ia *IssuerAuth) Encode() ([]byte, error) {
	if ia.rawBytes != nil {
		return ia.rawBytes, nil
	}
	if ia.sign1 == nil {
		return nil, fmt.Errorf("Sign1 message not set")
	}
	encoded, err := ia.sign1.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to encode IssuerAuth: %w", err)
	}
	ia.rawBytes = encoded
	return encoded, nil
}

// Algorithm returns the signature algorithm.
func (ia *IssuerAuth) Algorithm() cose.Algorithm {
	if ia.sign1 == nil {
		return cose.AlgorithmES256
	}
	alg, _ := ia.sign1.Headers.Protected.Algorithm()
	return alg
}

// Verify verifies the signature against the certificate's public key.
func (ia *IssuerAuth) Verify() error {
	cert := ia.Certificate()
	if cert == nil {
		return ErrInvalidCertificate
	}

	verifier, err := cose.NewVerifier(ia.Algorithm(), cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	if err := ia.sign1.Verify(nil, verifier); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	return nil
}

// VerifyWithCertPool verifies the signature and validates the certificate chain.
func (ia *IssuerAuth) VerifyWithCertPool(roots *x509.CertPool) error {
	cert := ia.Certificate()
	if cert == nil {
		return ErrInvalidCertificate
	}

	// Verify certificate
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	// Verify signature
	return ia.Verify()
}

// ParseIssuerAuth parses an IssuerAuth from CBOR bytes.
func ParseIssuerAuth(data []byte) (*IssuerAuth, error) {
	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(data); err != nil {
		if len(data) > 0 && data[0] == 0x84 {
			tagged := append([]byte{0xd2}, data...)
			if msg.UnmarshalCBOR(tagged) == nil {
				return &IssuerAuth{sign1: msg, rawBytes: data}, nil
			}
		}
		var tag fxcbor.Tag
		if decErr := fxcbor.Unmarshal(data, &tag); decErr == nil && tag.Number == 18 {
			switch content := tag.Content.(type) {
			case []any:
				encoded, encErr := cbor.Encode(content)
				if encErr == nil && msg.UnmarshalCBOR(encoded) == nil {
					return &IssuerAuth{sign1: msg, rawBytes: data}, nil
				}
			case []byte:
				if msg.UnmarshalCBOR(content) == nil {
					return &IssuerAuth{sign1: msg, rawBytes: data}, nil
				}
			}
		}
		return nil, WrapParseError("failed to parse IssuerAuth", err)
	}

	return &IssuerAuth{
		sign1:    msg,
		rawBytes: data,
	}, nil
}

// parseValidityInfo parses ValidityInfo from a raw map.
// EncodeCertificateToPEM encodes a certificate to PEM format.
func EncodeCertificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
