package mdoc

import (
	"fmt"

	"github.com/georgepadayatti/mdoc/cbor"
)

// IssuerSignedDocument represents a document signed by the issuer.
type IssuerSignedDocument struct {
	DocType      DocType
	IssuerSigned *IssuerSigned
}

// NewIssuerSignedDocument creates a new IssuerSignedDocument.
func NewIssuerSignedDocument(docType DocType, issuerSigned *IssuerSigned) *IssuerSignedDocument {
	return &IssuerSignedDocument{
		DocType:      docType,
		IssuerSigned: issuerSigned,
	}
}

// GetIssuerNameSpace returns the values for a specific namespace as a map.
func (d *IssuerSignedDocument) GetIssuerNameSpace(namespace string) map[string]any {
	if d.IssuerSigned == nil {
		return nil
	}
	items, ok := d.IssuerSigned.NameSpaces[namespace]
	if !ok {
		return nil
	}

	result := make(map[string]any)
	for _, item := range items {
		result[item.ElementIdentifier] = item.ElementValue
	}
	return result
}

// IssuerSignedNameSpaces returns the list of namespace identifiers.
func (d *IssuerSignedDocument) IssuerSignedNameSpaces() []string {
	if d.IssuerSigned == nil {
		return nil
	}
	namespaces := make([]string, 0, len(d.IssuerSigned.NameSpaces))
	for ns := range d.IssuerSigned.NameSpaces {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

// Prepare returns the document in a format suitable for CBOR encoding.
func (d *IssuerSignedDocument) Prepare() (map[string]any, error) {
	if d.IssuerSigned == nil {
		return nil, fmt.Errorf("IssuerSigned not set")
	}

	// Prepare namespaces as DataItems
	nameSpaces := make(map[string][]any)
	for ns, items := range d.IssuerSigned.NameSpaces {
		dataItems := make([]any, len(items))
		for i, item := range items {
			di, err := item.ToDataItem()
			if err != nil {
				return nil, fmt.Errorf("failed to create DataItem for %s: %w", item.ElementIdentifier, err)
			}
			dataItems[i] = di
		}
		nameSpaces[ns] = dataItems
	}

	// Encode IssuerAuth
	issuerAuthBytes, err := d.IssuerSigned.IssuerAuth.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode IssuerAuth: %w", err)
	}

	// Strip CBOR Tag 18 (COSE_Sign1_Tagged → COSE_Sign1) to match
	// ISO 18013-5 IssuerAuth = COSE_Sign1 (untagged array).
	// go-cose always produces Tag 18 (0xd2), but the spec and reference
	// implementations (pymdoccbor) use the untagged form.
	if len(issuerAuthBytes) > 0 && issuerAuthBytes[0] == 0xd2 {
		issuerAuthBytes = issuerAuthBytes[1:]
	}

	return map[string]any{
		"docType": string(d.DocType),
		"issuerSigned": map[string]any{
			"nameSpaces": nameSpaces,
			"issuerAuth": cbor.RawMessage(issuerAuthBytes),
		},
	}, nil
}

// Encode returns the CBOR-encoded representation of the full document
// (including docType wrapper).
func (d *IssuerSignedDocument) Encode() ([]byte, error) {
	prepared, err := d.Prepare()
	if err != nil {
		return nil, err
	}
	return cbor.Encode(prepared)
}

// EncodeIssuerSigned returns the CBOR-encoded representation of just the
// IssuerSigned structure (nameSpaces + issuerAuth), without the docType wrapper.
// This is the format required by OID4VCI Appendix A.2.4.
func (d *IssuerSignedDocument) EncodeIssuerSigned() ([]byte, error) {
	prepared, err := d.Prepare()
	if err != nil {
		return nil, err
	}
	issuerSigned, ok := prepared["issuerSigned"]
	if !ok {
		return nil, fmt.Errorf("issuerSigned not found in prepared document")
	}
	return cbor.Encode(issuerSigned)
}

// ValidateDigests validates all issuer-signed item digests against the MSO.
func (d *IssuerSignedDocument) ValidateDigests() (bool, []string) {
	if d.IssuerSigned == nil || d.IssuerSigned.IssuerAuth == nil {
		return false, []string{"IssuerSigned or IssuerAuth not set"}
	}

	var reasons []string
	allValid := true

	for ns, items := range d.IssuerSigned.NameSpaces {
		for _, item := range items {
			valid, err := item.IsValid(ns, d.IssuerSigned.IssuerAuth)
			if err != nil {
				reasons = append(reasons, fmt.Sprintf("%s.%s: %v", ns, item.ElementIdentifier, err))
				allValid = false
			} else if !valid {
				reasons = append(reasons, fmt.Sprintf("%s.%s: digest mismatch", ns, item.ElementIdentifier))
				allValid = false
			}
		}
	}

	return allValid, reasons
}

// GetDeviceKey returns the device public key from the MSO.
func (d *IssuerSignedDocument) GetDeviceKey() (map[any]any, error) {
	if d.IssuerSigned == nil || d.IssuerSigned.IssuerAuth == nil {
		return nil, fmt.Errorf("IssuerSigned or IssuerAuth not set")
	}

	mso := d.IssuerSigned.IssuerAuth.MSO()
	if mso == nil {
		return nil, fmt.Errorf("MSO not available")
	}

	if mso.DeviceKeyInfo == nil {
		return nil, ErrMissingDeviceKey
	}

	return mso.DeviceKeyInfo.DeviceKey, nil
}

// ValidityInfo returns the validity information from the MSO.
func (d *IssuerSignedDocument) ValidityInfo() *ValidityInfo {
	if d.IssuerSigned == nil || d.IssuerSigned.IssuerAuth == nil {
		return nil
	}

	mso := d.IssuerSigned.IssuerAuth.MSO()
	if mso == nil {
		return nil
	}

	return &mso.ValidityInfo
}
