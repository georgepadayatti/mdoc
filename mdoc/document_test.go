package mdoc

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/georgepadayatti/mdoc/mdoc/testdata"
)

func TestNewDocument(t *testing.T) {
	doc := NewDocument(DocTypeMDL)
	if doc.docType != DocTypeMDL {
		t.Errorf("expected docType %s, got %s", DocTypeMDL, doc.docType)
	}
	if doc.digestAlgorithm != DigestAlgorithmSHA256 {
		t.Errorf("expected digestAlgorithm SHA-256, got %s", doc.digestAlgorithm)
	}
}

func TestDocumentAddIssuerNameSpace(t *testing.T) {
	doc := NewDocument(DocTypeMDL).
		AddIssuerNameSpace(NamespaceMDL, map[string]any{
			"family_name": "Jones",
			"given_name":  "Ava",
		})

	ns := doc.GetIssuerNameSpace(NamespaceMDL)
	if ns == nil {
		t.Fatal("expected namespace to be set")
	}
	if ns["family_name"] != "Jones" {
		t.Errorf("expected family_name Jones, got %v", ns["family_name"])
	}
}

func TestDocumentAddValidityInfo(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	validUntil := now.AddDate(2, 0, 0)

	doc := NewDocument(DocTypeMDL).
		AddValidityInfo(ValidityInfo{
			Signed:     now,
			ValidFrom:  now,
			ValidUntil: validUntil,
		})

	if !doc.validityInfo.Signed.Equal(now) {
		t.Errorf("expected Signed %v, got %v", now, doc.validityInfo.Signed)
	}
	if !doc.validityInfo.ValidUntil.Equal(validUntil) {
		t.Errorf("expected ValidUntil %v, got %v", validUntil, doc.validityInfo.ValidUntil)
	}
}

func TestDocumentUseDigestAlgorithm(t *testing.T) {
	doc := NewDocument(DocTypeMDL).
		UseDigestAlgorithm(DigestAlgorithmSHA512)

	if doc.digestAlgorithm != DigestAlgorithmSHA512 {
		t.Errorf("expected SHA-512, got %s", doc.digestAlgorithm)
	}
}

func TestDocumentSign(t *testing.T) {
	// Parse private key
	block, _ := pem.Decode([]byte(testdata.IssuerPrivateKeyPEM))
	if block == nil {
		t.Fatal("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	// Create and sign document
	doc := NewDocument(DocTypeMDL).
		AddIssuerNameSpace(NamespaceMDL, map[string]any{
			"family_name":     "Jones",
			"given_name":      "Ava",
			"birth_date":      "2007-03-25",
			"issuing_country": "US",
		}).
		UseDigestAlgorithm(DigestAlgorithmSHA256).
		AddValidityInfo(ValidityInfo{
			Signed:     time.Now().UTC(),
			ValidFrom:  time.Now().UTC(),
			ValidUntil: time.Now().AddDate(1, 0, 0).UTC(),
		})

	issuedDoc, err := doc.Sign(SignParams{
		IssuerPrivateKey:  privateKey,
		IssuerCertificate: []byte(testdata.IssuerCertificatePEM),
		Algorithm:         AlgorithmES256,
	})
	if err != nil {
		t.Fatalf("failed to sign document: %v", err)
	}

	if issuedDoc == nil {
		t.Fatal("expected issued document to be non-nil")
	}
	if issuedDoc.DocType != DocTypeMDL {
		t.Errorf("expected docType %s, got %s", DocTypeMDL, issuedDoc.DocType)
	}
	if issuedDoc.IssuerSigned == nil {
		t.Fatal("expected IssuerSigned to be non-nil")
	}
	if issuedDoc.IssuerSigned.IssuerAuth == nil {
		t.Fatal("expected IssuerAuth to be non-nil")
	}

	// Check namespaces
	ns := issuedDoc.GetIssuerNameSpace(NamespaceMDL)
	if ns == nil {
		t.Fatal("expected namespace to be present")
	}
	if ns["family_name"] != "Jones" {
		t.Errorf("expected family_name Jones, got %v", ns["family_name"])
	}
}

func TestDocumentValidate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *Document
		wantErr bool
	}{
		{
			name: "valid document",
			setup: func() *Document {
				return NewDocument(DocTypeMDL).
					AddIssuerNameSpace(NamespaceMDL, map[string]any{
						"family_name": "Test",
					})
			},
			wantErr: false,
		},
		{
			name: "missing docType",
			setup: func() *Document {
				d := NewDocument(DocTypeMDL)
				d.docType = ""
				return d.AddIssuerNameSpace(NamespaceMDL, map[string]any{
					"family_name": "Test",
				})
			},
			wantErr: true,
		},
		{
			name: "missing namespace",
			setup: func() *Document {
				return NewDocument(DocTypeMDL)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := tt.setup()
			err := doc.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
