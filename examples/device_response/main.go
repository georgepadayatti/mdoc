// Package main demonstrates selective disclosure with device responses.
//
// This example shows:
// - Creating presentation definitions (verifier requests)
// - Generating device responses with selective disclosure
// - Both MAC and signature-based device authentication
// - age_over_NN special handling
// - Session transcript creation for OID4VP
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

	"github.com/georgepadayatti/mdoc/mdoc"
)

// Test credentials (for demonstration only)
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
	fmt.Println("=== Selective Disclosure & Device Response Example ===")
	fmt.Println()

	// Create a stored mDL (simulating what's on the holder's device)
	storedMDoc, devicePrivateKey := createStoredMDoc()

	fmt.Println("=== Example 1: Basic Selective Disclosure ===")
	fmt.Println()
	demonstrateBasicSelectiveDisclosure(storedMDoc, devicePrivateKey)

	fmt.Println()
	fmt.Println("=== Example 2: Age Verification Only ===")
	fmt.Println()
	demonstrateAgeVerification(storedMDoc, devicePrivateKey)

	fmt.Println()
	fmt.Println("=== Example 3: Signature vs MAC Authentication ===")
	fmt.Println()
	demonstrateAuthenticationMethods(storedMDoc, devicePrivateKey)

	fmt.Println()
	fmt.Println("=== Examples Complete ===")
}

// createStoredMDoc creates a sample stored mDL document
func createStoredMDoc() (*mdoc.MDoc, *ecdsa.PrivateKey) {
	fmt.Println("--- Creating Stored mDL ---")

	issuerPriv, _ := parsePrivateKey(issuerPrivateKeyPEM)
	devicePriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	now := time.Now().UTC()

	// Create document with all attributes
	doc, err := mdoc.NewDocument(mdoc.DocTypeMDL).
		AddIssuerNameSpace(mdoc.NamespaceMDL, map[string]any{
			// Personal info
			"family_name":     "Johnson",
			"given_name":      "Emily",
			"birth_date":      "1995-08-20",
			"portrait":        []byte("portrait-data"),
			"sex":             2,

			// Address
			"resident_address":     "456 Oak Avenue",
			"resident_city":        "Brooklyn",
			"resident_state":       "NY",
			"resident_postal_code": "11201",
			"resident_country":     "US",

			// Document info
			"issue_date":           "2023-01-15",
			"expiry_date":          "2028-01-15",
			"issuing_country":      "US",
			"issuing_authority":    "NY DMV",
			"issuing_jurisdiction": "US-NY",
			"document_number":      "DL-2023-789012",

			// Age attestations
			"age_over_18": true,
			"age_over_21": true,
			"age_over_25": true,
			"age_over_65": false,

			// Driving privileges
			"driving_privileges": []map[string]any{
				{
					"vehicle_category_code": "B",
					"issue_date":            "2013-08-20",
					"expiry_date":           "2028-01-15",
				},
			},
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
		log.Fatalf("Failed to create document: %v", err)
	}

	storedMDoc := mdoc.NewMDoc(doc)
	fmt.Printf("Created mDL with %d attributes in namespace\n\n", len(doc.GetIssuerNameSpace(mdoc.NamespaceMDL)))

	return storedMDoc, devicePriv
}

// demonstrateBasicSelectiveDisclosure shows basic attribute selection
func demonstrateBasicSelectiveDisclosure(storedMDoc *mdoc.MDoc, devicePriv *ecdsa.PrivateKey) {
	fmt.Println("Scenario: Verifier requests name and birth date only")
	fmt.Println("(All other attributes remain hidden)")

	// Create presentation definition - verifier only wants these fields
	pd := mdoc.BuildMDLPresentationDefinition("basic-verification",
		"family_name",
		"given_name",
		"birth_date",
	)

	// OID4VP session parameters
	mdocNonce := "nonce123"
	clientID := "https://verifier.example.com"
	responseURI := "https://verifier.example.com/response"
	verifierNonce := "verifier-nonce-456"

	// Create device response
	response, err := mdoc.DeviceResponseFrom(storedMDoc).
		UsingPresentationDefinition(pd).
		UsingSessionTranscriptForOID4VP(mdocNonce, clientID, responseURI, verifierNonce).
		AuthenticateWithSignature(devicePriv, mdoc.AlgorithmES256).
		Sign()

	if err != nil {
		log.Fatalf("Failed to create device response: %v", err)
	}

	// Show what's disclosed
	fmt.Println("\nDisclosed attributes:")
	for _, doc := range response.Documents {
		if dsd, ok := doc.(*mdoc.DeviceSignedDocument); ok {
			ns := dsd.GetIssuerNameSpace(mdoc.NamespaceMDL)
			for key, value := range ns {
				fmt.Printf("  - %s: %v\n", key, value)
			}
		}
	}

	encoded, _ := response.Encode()
	fmt.Printf("\nEncoded response size: %d bytes\n", len(encoded))
}

// demonstrateAgeVerification shows age_over_NN handling
func demonstrateAgeVerification(storedMDoc *mdoc.MDoc, devicePriv *ecdsa.PrivateKey) {
	fmt.Println("Scenario: Bar/club only needs to verify age >= 21")
	fmt.Println("(No name, address, or other PII needed)")

	// Create custom presentation definition for age only
	pd := &mdoc.PresentationDefinition{
		ID: "age-verification",
		InputDescriptors: []mdoc.InputDescriptor{
			{
				ID: string(mdoc.DocTypeMDL),
				Constraints: mdoc.Constraints{
					LimitDisclosure: "required",
					Fields: []mdoc.PresentationDefinitionField{
						{
							Path:           []string{"$['org.iso.18013.5.1']['age_over_21']"},
							IntentToRetain: false,
						},
					},
				},
			},
		},
	}

	// Create device response
	response, err := mdoc.DeviceResponseFrom(storedMDoc).
		UsingPresentationDefinition(pd).
		UsingSessionTranscriptForOID4VP("age-check-nonce", "bar-app", "https://bar.example/verify", "xyz").
		AuthenticateWithSignature(devicePriv, mdoc.AlgorithmES256).
		Sign()

	if err != nil {
		log.Fatalf("Failed to create device response: %v", err)
	}

	// Show what's disclosed
	fmt.Println("\nDisclosed attributes:")
	for _, doc := range response.Documents {
		if dsd, ok := doc.(*mdoc.DeviceSignedDocument); ok {
			ns := dsd.GetIssuerNameSpace(mdoc.NamespaceMDL)
			for key, value := range ns {
				fmt.Printf("  - %s: %v\n", key, value)
			}
			if len(ns) == 0 {
				fmt.Println("  (none - attribute not found or not included)")
			}
		}
	}

	encoded, _ := response.Encode()
	fmt.Printf("\nEncoded response size: %d bytes\n", len(encoded))
	fmt.Println("Note: Only age attestation disclosed, name and photo remain private!")
}

// demonstrateAuthenticationMethods shows MAC vs Signature authentication
func demonstrateAuthenticationMethods(storedMDoc *mdoc.MDoc, devicePriv *ecdsa.PrivateKey) {
	pd := mdoc.BuildMDLPresentationDefinition("auth-demo", "given_name")

	// Method 1: Signature-based authentication
	fmt.Println("Method 1: Signature-based device authentication")
	fmt.Println("  - Device signs with its private key")
	fmt.Println("  - Verifier uses device public key from MSO")
	fmt.Println("  - No shared secret needed")

	sigResponse, err := mdoc.DeviceResponseFrom(storedMDoc).
		UsingPresentationDefinition(pd).
		UsingSessionTranscriptForOID4VP("nonce1", "client", "https://v.example/cb", "v1").
		AuthenticateWithSignature(devicePriv, mdoc.AlgorithmES256).
		Sign()

	if err != nil {
		log.Fatalf("Signature auth failed: %v", err)
	}

	sigEncoded, _ := sigResponse.Encode()
	fmt.Printf("  Response size: %d bytes\n", len(sigEncoded))

	// Method 2: MAC-based authentication (requires reader key)
	fmt.Println("\nMethod 2: MAC-based device authentication")
	fmt.Println("  - Device and reader perform ECDH key agreement")
	fmt.Println("  - Shared secret used to compute HMAC")
	fmt.Println("  - Provides reader authentication too")

	// Generate reader's ephemeral key (verifier generates this)
	readerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	macResponse, err := mdoc.DeviceResponseFrom(storedMDoc).
		UsingPresentationDefinition(pd).
		UsingSessionTranscriptForOID4VP("nonce2", "client", "https://v.example/cb", "v2").
		AuthenticateWithMAC(devicePriv, &readerPriv.PublicKey, mdoc.MacAlgorithmHS256).
		Sign()

	if err != nil {
		log.Fatalf("MAC auth failed: %v", err)
	}

	macEncoded, _ := macResponse.Encode()
	fmt.Printf("  Response size: %d bytes\n", len(macEncoded))

	fmt.Println("\nComparison:")
	fmt.Println("  Signature: Simpler, device-only authentication")
	fmt.Println("  MAC: Mutual authentication, requires reader key exchange")
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
