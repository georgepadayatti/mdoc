package mdoc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	mcose "github.com/georgepadayatti/mdoc/cose"
	"github.com/georgepadayatti/mdoc/mdoc/testdata"
)

func TestDeviceResponseMACVerification(t *testing.T) {
	issuerPriv, err := parseIssuerPrivateKey([]byte(testdata.IssuerPrivateKeyPEM))
	if err != nil {
		t.Fatalf("failed to parse issuer private key: %v", err)
	}

	deviceJWK, err := ParseJWK(testdata.DeviceKeyJWK)
	if err != nil {
		t.Fatalf("failed to parse device JWK: %v", err)
	}
	devicePriv, err := deviceJWK.ToECDSAPrivateKey()
	if err != nil {
		t.Fatalf("failed to convert device JWK: %v", err)
	}

	signed := time.Date(2023, 10, 24, 14, 55, 18, 0, time.UTC)
	validUntil := signed.AddDate(30, 0, 0)

	doc, err := NewDocument(DocTypeMDL).
		AddIssuerNameSpace(NamespaceMDL, testdata.TestMDLData).
		UseDigestAlgorithm(DigestAlgorithmSHA256).
		AddValidityInfo(ValidityInfo{
			Signed:     signed,
			ValidFrom:  signed,
			ValidUntil: validUntil,
		}).
		AddDeviceKeyInfo(&devicePriv.PublicKey).
		Sign(SignParams{
			IssuerPrivateKey:  issuerPriv,
			IssuerCertificate: []byte(testdata.IssuerCertificatePEM),
			Algorithm:         AlgorithmES256,
		})
	if err != nil {
		t.Fatalf("failed to sign document: %v", err)
	}

	mdoc := NewMDoc(doc)

	pd := BuildMDLPresentationDefinition("mdl-test", "family_name", "given_name", "birth_date")

	readerPriv, err := GenerateECDSAKeyPair(AlgorithmES256)
	if err != nil {
		t.Fatalf("failed to generate reader key: %v", err)
	}

	mdocNonce := "123456"
	clientID := "client"
	responseURI := "https://example.test/callback"
	verifierNonce := "nonce"

	deviceResponse, err := DeviceResponseFrom(mdoc).
		UsingPresentationDefinition(pd).
		UsingSessionTranscriptForOID4VP(mdocNonce, clientID, responseURI, verifierNonce).
		AuthenticateWithMAC(devicePriv, &readerPriv.PublicKey, MacAlgorithmHS256).
		Sign()
	if err != nil {
		t.Fatalf("failed to sign device response: %v", err)
	}

	encoded, err := deviceResponse.Encode()
	if err != nil {
		t.Fatalf("failed to encode device response: %v", err)
	}

	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatalf("failed to parse device response: %v", err)
	}
	if len(parsed.Documents) > 0 {
		if dsd, ok := parsed.Documents[0].(*DeviceSignedDocument); ok && dsd.DeviceSigned != nil && dsd.DeviceSigned.DeviceAuth != nil {
			if dsd.DeviceSigned.DeviceAuth.DeviceMAC != nil {
				if alg, algErr := dsd.DeviceSigned.DeviceAuth.DeviceMAC.Algorithm(); algErr != nil {
					t.Fatalf("device MAC algorithm parse error: %v", algErr)
				} else if alg != AlgHMAC256 {
					t.Fatalf("unexpected device MAC algorithm: %d", alg)
				}
			}
		}
	}

	verifier, err := NewVerifier([][]byte{[]byte(testdata.IssuerCertificatePEM)})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	sessionTranscript, err := CreateSessionTranscriptOID4VP(mdocNonce, clientID, responseURI, verifierNonce)
	if err != nil {
		t.Fatalf("failed to create session transcript: %v", err)
	}
	readerKeyCOSE, err := encodeCOSEPrivateKey(readerPriv)
	if err != nil {
		t.Fatalf("failed to encode reader private key: %v", err)
	}

	if _, err := verifier.Verify(encoded, VerifyOptions{
		EphemeralReaderKey:       readerKeyCOSE,
		EncodedSessionTranscript: sessionTranscript,
	}); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// Mismatch transcript should fail MAC validation
	badTranscript, _ := CreateSessionTranscriptOID4VP(mdocNonce, "wrong", responseURI, verifierNonce)
	if _, err := verifier.Verify(encoded, VerifyOptions{
		EphemeralReaderKey:       readerKeyCOSE,
		EncodedSessionTranscript: badTranscript,
	}); err == nil {
		t.Fatalf("expected verification error with mismatched transcript")
	}
}

func TestDeviceResponseSignatureVerification(t *testing.T) {
	issuerPriv, err := parseIssuerPrivateKey([]byte(testdata.IssuerPrivateKeyPEM))
	if err != nil {
		t.Fatalf("failed to parse issuer private key: %v", err)
	}

	deviceJWK, err := ParseJWK(testdata.DeviceKeyJWK)
	if err != nil {
		t.Fatalf("failed to parse device JWK: %v", err)
	}
	devicePriv, err := deviceJWK.ToECDSAPrivateKey()
	if err != nil {
		t.Fatalf("failed to convert device JWK: %v", err)
	}

	doc, err := NewDocument(DocTypeMDL).
		AddIssuerNameSpace(NamespaceMDL, map[string]any{
			"family_name": "Jones",
			"given_name":  "Ava",
		}).
		AddDeviceKeyInfo(&devicePriv.PublicKey).
		Sign(SignParams{
			IssuerPrivateKey:  issuerPriv,
			IssuerCertificate: []byte(testdata.IssuerCertificatePEM),
			Algorithm:         AlgorithmES256,
		})
	if err != nil {
		t.Fatalf("failed to sign document: %v", err)
	}

	mdoc := NewMDoc(doc)
	pd := BuildMDLPresentationDefinition("mdl-test", "family_name", "given_name")

	mdocNonce := "123456"
	clientID := "client"
	responseURI := "https://example.test/callback"
	verifierNonce := "nonce"

	deviceResponse, err := DeviceResponseFrom(mdoc).
		UsingPresentationDefinition(pd).
		UsingSessionTranscriptForOID4VP(mdocNonce, clientID, responseURI, verifierNonce).
		AuthenticateWithSignature(devicePriv, AlgorithmES256).
		Sign()
	if err != nil {
		t.Fatalf("failed to sign device response: %v", err)
	}

	encoded, err := deviceResponse.Encode()
	if err != nil {
		t.Fatalf("failed to encode device response: %v", err)
	}

	verifier, err := NewVerifier([][]byte{[]byte(testdata.IssuerCertificatePEM)})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	sessionTranscript, err := CreateSessionTranscriptOID4VP(mdocNonce, clientID, responseURI, verifierNonce)
	if err != nil {
		t.Fatalf("failed to create session transcript: %v", err)
	}

	if _, err := verifier.Verify(encoded, VerifyOptions{
		EncodedSessionTranscript: sessionTranscript,
	}); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func parseIssuerPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA private key")
	}
	return ecKey, nil
}

func encodeCOSEPrivateKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	coseKey, err := mcose.FromECDSAPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return coseKey.Encode()
}
