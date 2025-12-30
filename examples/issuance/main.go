// Package main demonstrates how to issue an mDL document.
//
// This example shows:
// - Creating a new mDL document with personal information
// - Adding driving privileges with proper date handling
// - Setting validity information
// - Signing with an issuer certificate
// - Encoding the document for storage
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/georgepadayatti/mdoc/mdoc"
)

// Test issuer certificate and private key (for demonstration only)
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
	fmt.Println("=== mDL Document Issuance Example ===")
	fmt.Println()

	// Step 1: Parse the issuer's private key
	issuerPrivateKey, err := parsePrivateKey(issuerPrivateKeyPEM)
	if err != nil {
		log.Fatalf("Failed to parse issuer private key: %v", err)
	}
	fmt.Println("1. Parsed issuer private key")

	// Step 2: Generate a device key pair (in practice, this comes from the device)
	devicePrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate device key: %v", err)
	}
	fmt.Println("2. Generated device key pair")

	// Step 3: Prepare the mDL data
	mDLData := map[string]any{
		// Personal information
		"family_name":            "Jones",
		"given_name":             "Ava",
		"birth_date":             "2000-03-25", // Will be converted to DateOnly
		"portrait":               []byte("base64-encoded-portrait-image"),
		"sex":                    2, // ISO 5218: 1=male, 2=female
		"height":                 165,
		"weight":                 60,
		"eye_colour":             "brown",
		"hair_colour":            "black",
		"resident_address":       "123 Main St",
		"resident_city":          "Albany",
		"resident_state":         "NY",
		"resident_postal_code":   "12207",
		"resident_country":       "US",
		"nationality":            "US",
		"age_over_18":            true,
		"age_over_21":            true,

		// Document information
		"issue_date":             "2023-09-01",
		"expiry_date":            "2028-09-30",
		"issuing_country":        "US",
		"issuing_authority":      "NY DMV",
		"issuing_jurisdiction":   "US-NY",
		"document_number":        "DL-2023-001234",
		"administrative_number":  "ADM-2023-001234",
		"un_distinguishing_sign": "USA",

		// Driving privileges
		"driving_privileges": []map[string]any{
			{
				"vehicle_category_code": "B",
				"issue_date":            "2018-09-01",
				"expiry_date":           "2028-09-30",
			},
			{
				"vehicle_category_code": "A",
				"issue_date":            "2020-06-15",
				"expiry_date":           "2028-09-30",
			},
		},
	}
	fmt.Println("3. Prepared mDL data with", len(mDLData), "attributes")

	// Step 4: Set validity information
	now := time.Now().UTC()
	validityInfo := mdoc.ValidityInfo{
		Signed:     now,
		ValidFrom:  now,
		ValidUntil: now.AddDate(5, 0, 0), // Valid for 5 years
	}
	fmt.Printf("4. Set validity: %s to %s\n",
		validityInfo.ValidFrom.Format("2006-01-02"),
		validityInfo.ValidUntil.Format("2006-01-02"))

	// Step 5: Create and sign the document
	issuedDoc, err := mdoc.NewDocument(mdoc.DocTypeMDL).
		AddIssuerNameSpace(mdoc.NamespaceMDL, mDLData).
		AddDeviceKeyInfo(&devicePrivateKey.PublicKey).
		AddValidityInfo(validityInfo).
		UseDigestAlgorithm(mdoc.DigestAlgorithmSHA256).
		Sign(mdoc.SignParams{
			IssuerPrivateKey:  issuerPrivateKey,
			IssuerCertificate: []byte(issuerCertificatePEM),
			Algorithm:         mdoc.AlgorithmES256,
		})

	if err != nil {
		log.Fatalf("Failed to sign document: %v", err)
	}
	fmt.Println("5. Document signed successfully")

	// Step 6: Create MDoc container and encode
	mDoc := mdoc.NewMDoc(issuedDoc)
	encoded, err := mDoc.Encode()
	if err != nil {
		log.Fatalf("Failed to encode MDoc: %v", err)
	}
	fmt.Printf("6. Encoded MDoc size: %d bytes\n", len(encoded))

	// Step 7: Display document information
	fmt.Println("\n=== Issued Document Details ===")
	fmt.Printf("Document Type: %s\n", issuedDoc.DocType)
	fmt.Printf("Version: %s\n", mDoc.Version)

	// Show namespaces and attributes
	ns := issuedDoc.GetIssuerNameSpace(mdoc.NamespaceMDL)
	fmt.Printf("Namespace: %s (%d attributes)\n", mdoc.NamespaceMDL, len(ns))

	// Show MSO details
	mso := issuedDoc.IssuerSigned.IssuerAuth.MSO()
	if mso != nil {
		fmt.Printf("MSO Version: %s\n", mso.Version)
		fmt.Printf("Digest Algorithm: %s\n", mso.DigestAlgorithm)
		fmt.Printf("Validity: %s to %s\n",
			mso.ValidityInfo.ValidFrom.Format("2006-01-02"),
			mso.ValidityInfo.ValidUntil.Format("2006-01-02"))
	}

	// Show certificate info
	cert := issuedDoc.IssuerSigned.IssuerAuth.Certificate()
	if cert != nil {
		fmt.Printf("Issuer Certificate: %s\n", cert.Subject.CommonName)
		fmt.Printf("Issuer Country: %s\n", issuedDoc.IssuerSigned.IssuerAuth.CountryName())
	}

	// Step 8: Output the encoded document (hex for display)
	fmt.Println("\n=== Encoded Document (first 200 bytes hex) ===")
	displayLen := 200
	if len(encoded) < displayLen {
		displayLen = len(encoded)
	}
	fmt.Println(hex.EncodeToString(encoded[:displayLen]) + "...")

	fmt.Println("\n=== Issuance Complete ===")
	fmt.Println("The encoded document can now be stored on the device")
	fmt.Println("and presented to verifiers using selective disclosure.")
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
