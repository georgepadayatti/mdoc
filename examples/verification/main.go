// Package main demonstrates how to verify an mDL device response.
//
// This example shows:
// - Setting up a verifier with trusted certificates
// - Creating session transcripts for OID4VP
// - Verifying issuer signatures and device authentication
// - Accessing verified attributes
// - Handling verification callbacks for detailed results
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	mcose "github.com/georgepadayatti/mdoc/cose"
	"github.com/georgepadayatti/mdoc/mdoc"
)

// Test issuer certificate (same as used for issuance)
const issuerCertificatePEM = `-----BEGIN CERTIFICATE-----
MIICKjCCAdCgAwIBAgIUV8bM0wi95D7KN0TyqHE42ru4hOgwCgYIKoZIzj0EAwIw
UzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMQ8wDQYDVQQHDAZBbGJh
bnkxDzANBgNVBAoMBk5ZIERNVjEPMA0GA1UECwwGTlkgRE1WMB4XDTIzMDkxNDE0
NTUxOFoXDTMzMDkxMTE0NTUxOFowUzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5l
dyBZb3JrMQ8wDQYDVQQHDAZBbGJhbnkxDzANBgNVBAoMBk5ZIERNVjEPMA0GA1UE
CwwGTlkgRE1WMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiTwtg0eQbcbNabf2
Nq9L/VM/lhhPCq2s0Qgw2kRx29tgrBcNHPxTT64tnc1Ij3dH/fl42SXqMenpCDw4
K6ntU6OBgTB/MB0GA1UdDgQWBBSrbS4DuR1JIkAzj7zK3v2TM+r2xzAfBgNVHSME
GDAWgBSrbS4DuR1JIkAzj7zK3v2TM+r2xzAPBgNVHRMBAf8EBTADAQH/MCwGCWCG
SAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAKBggqhkjO
PQQDAgNIADBFAiAJ/Qyrl7A+ePZOdNfc7ohmjEdqCvxaos6//gfTvncuqQIhANo4
q8mKCA9J8k/+zh//yKbN1bLAtdqPx7dnrDqV3Lg+
-----END CERTIFICATE-----`

const issuerPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCjo+vMGbV0J9LCokdb
oNWqYk4JBIgCiysI99sUkMw2ng==
-----END PRIVATE KEY-----`

func main() {
	fmt.Println("=== mDL Verification Example ===")
	fmt.Println()

	// First, create a sample device response to verify
	// (In practice, this would come from the holder's device)
	deviceResponse, readerPrivateKey, transcript := createSampleDeviceResponse()

	fmt.Println("=== Starting Verification ===")
	fmt.Println()

	// Step 1: Create verifier with trusted certificates
	verifier, err := mdoc.NewVerifier([][]byte{
		[]byte(issuerCertificatePEM),
	})
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}
	fmt.Println("1. Created verifier with trusted certificates")

	// Step 2: Encode the reader's private key for MAC verification
	readerKeyCOSE, err := encodeReaderPrivateKey(readerPrivateKey)
	if err != nil {
		log.Fatalf("Failed to encode reader key: %v", err)
	}
	fmt.Println("2. Encoded reader private key for MAC verification")

	// Step 3: Set up verification options with callback
	verificationResults := make([]mdoc.VerificationAssessment, 0)
	options := mdoc.VerifyOptions{
		EncodedSessionTranscript: transcript,
		EphemeralReaderKey:       readerKeyCOSE,
		OnCheck: func(assessment mdoc.VerificationAssessment) error {
			verificationResults = append(verificationResults, assessment)
			// Log each check as it happens
			status := "PASS"
			if assessment.Status == mdoc.StatusFailed {
				status = "FAIL"
			} else if assessment.Status == mdoc.StatusWarning {
				status = "WARN"
			}
			fmt.Printf("   [%s] %s: %s\n", status, assessment.Check, assessment.Category)
			return nil
		},
	}

	// Step 4: Perform verification
	fmt.Println("\n3. Running verification checks:")
	result, err := verifier.Verify(deviceResponse, options)
	if err != nil {
		log.Fatalf("\nVerification failed: %v", err)
	}

	// Step 5: Display verification summary
	fmt.Println("\n=== Verification Summary ===")
	passed := 0
	failed := 0
	warnings := 0
	for _, r := range verificationResults {
		switch r.Status {
		case mdoc.StatusPassed:
			passed++
		case mdoc.StatusFailed:
			failed++
		case mdoc.StatusWarning:
			warnings++
		}
	}
	fmt.Printf("Total checks: %d (Passed: %d, Failed: %d, Warnings: %d)\n",
		len(verificationResults), passed, failed, warnings)

	// Step 6: Access verified data
	fmt.Println("\n=== Verified Document Data ===")
	fmt.Printf("Version: %s\n", result.Version)
	fmt.Printf("Status: %d\n", result.Status)
	fmt.Printf("Documents: %d\n", len(result.Documents))

	for i, doc := range result.Documents {
		fmt.Printf("\nDocument %d:\n", i+1)

		switch d := doc.(type) {
		case *mdoc.DeviceSignedDocument:
			fmt.Printf("  Type: %s\n", d.DocType)

			// Get issuer-signed attributes
			ns := d.GetIssuerNameSpace(mdoc.NamespaceMDL)
			if ns != nil {
				fmt.Println("  Verified Attributes:")
				for key, value := range ns {
					fmt.Printf("    - %s: %v\n", key, value)
				}
			}

			// Check device authentication method
			if d.HasDeviceMAC() {
				fmt.Println("  Device Auth: MAC-based")
			} else if d.HasDeviceSignature() {
				fmt.Println("  Device Auth: Signature-based")
			}

		case *mdoc.IssuerSignedDocument:
			fmt.Printf("  Type: %s\n", d.DocType)
			ns := d.GetIssuerNameSpace(mdoc.NamespaceMDL)
			if ns != nil {
				fmt.Println("  Attributes:")
				for key, value := range ns {
					fmt.Printf("    - %s: %v\n", key, value)
				}
			}
		}
	}

	fmt.Println("\n=== Verification Complete ===")
}

// createSampleDeviceResponse creates a sample device response for demonstration
func createSampleDeviceResponse() ([]byte, *ecdsa.PrivateKey, []byte) {
	fmt.Println("--- Creating Sample Device Response ---")

	// Parse issuer key
	issuerPriv, err := parsePrivateKey(issuerPrivateKeyPEM)
	if err != nil {
		log.Fatalf("Failed to parse issuer key: %v", err)
	}

	// Generate device key
	devicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate device key: %v", err)
	}

	// Generate reader ephemeral key (verifier's key for MAC)
	readerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate reader key: %v", err)
	}

	// Create issued document
	now := time.Now().UTC()
	doc, err := mdoc.NewDocument(mdoc.DocTypeMDL).
		AddIssuerNameSpace(mdoc.NamespaceMDL, map[string]any{
			"family_name":     "Smith",
			"given_name":      "John",
			"birth_date":      "1990-05-15",
			"issuing_country": "US",
			"document_number": "DL-123456",
		}).
		AddDeviceKeyInfo(&devicePriv.PublicKey).
		AddValidityInfo(mdoc.ValidityInfo{
			Signed:     now,
			ValidFrom:  now,
			ValidUntil: now.AddDate(5, 0, 0),
		}).
		Sign(mdoc.SignParams{
			IssuerPrivateKey:  issuerPriv,
			IssuerCertificate: []byte(issuerCertificatePEM),
			Algorithm:         mdoc.AlgorithmES256,
		})
	if err != nil {
		log.Fatalf("Failed to sign document: %v", err)
	}
	fmt.Println("  - Created and signed mDL document")

	// Create MDoc container
	storedMDoc := mdoc.NewMDoc(doc)

	// Create presentation definition (verifier's request)
	pd := mdoc.BuildMDLPresentationDefinition("verification-request",
		"family_name", "given_name", "birth_date",
	)
	fmt.Println("  - Created presentation definition")

	// OID4VP session parameters
	mdocNonce := "abc123"
	clientID := "https://verifier.example.com"
	responseURI := "https://verifier.example.com/callback"
	verifierNonce := "xyz789"

	// Create session transcript
	transcript, err := mdoc.CreateSessionTranscriptOID4VP(
		mdocNonce, clientID, responseURI, verifierNonce,
	)
	if err != nil {
		log.Fatalf("Failed to create session transcript: %v", err)
	}
	fmt.Println("  - Created session transcript")

	// Create device response with MAC authentication
	response, err := mdoc.DeviceResponseFrom(storedMDoc).
		UsingPresentationDefinition(pd).
		UsingSessionTranscriptForOID4VP(mdocNonce, clientID, responseURI, verifierNonce).
		AuthenticateWithMAC(devicePriv, &readerPriv.PublicKey, mdoc.MacAlgorithmHS256).
		Sign()
	if err != nil {
		log.Fatalf("Failed to create device response: %v", err)
	}
	fmt.Println("  - Created device response with MAC authentication")

	// Encode response
	encoded, err := response.Encode()
	if err != nil {
		log.Fatalf("Failed to encode response: %v", err)
	}
	fmt.Printf("  - Encoded device response (%d bytes)\n\n", len(encoded))

	return encoded, readerPriv, transcript
}

// parsePrivateKey parses a PEM-encoded private key
func parsePrivateKey(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA private key")
	}

	return ecKey, nil
}

// encodeReaderPrivateKey encodes an ECDSA private key to COSE format
func encodeReaderPrivateKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	coseKey, err := mcose.FromECDSAPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return coseKey.Encode()
}
