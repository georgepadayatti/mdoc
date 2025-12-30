package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/georgepadayatti/mdoc/cbor"
	mcose "github.com/georgepadayatti/mdoc/cose"
)

// Document is a builder for creating new mDoc documents.
type Document struct {
	docType         DocType
	issuerNameSpaces map[string][]*IssuerSignedItem
	deviceKeyInfo   *DeviceKeyInfo
	validityInfo    ValidityInfo
	digestAlgorithm DigestAlgorithm
}

// NewDocument creates a new Document builder with the specified document type.
func NewDocument(docType DocType) *Document {
	now := time.Now().UTC()
	return &Document{
		docType:          docType,
		issuerNameSpaces: make(map[string][]*IssuerSignedItem),
		validityInfo: ValidityInfo{
			Signed:     now,
			ValidFrom:  now,
			ValidUntil: now.AddDate(1, 0, 0), // 1 year from now
		},
		digestAlgorithm: DigestAlgorithmSHA256,
	}
}

// AddIssuerNameSpace adds or updates a namespace with the given values.
func (d *Document) AddIssuerNameSpace(namespace string, values map[string]any) *Document {
	// Process values - convert date strings to DateOnly for MDL namespace
	for k, v := range values {
		processedValue := d.processValue(namespace, k, v)
		if d.issuerNameSpaces[namespace] == nil {
			d.issuerNameSpaces[namespace] = make([]*IssuerSignedItem, 0, len(values))
		}
		digestID := uint64(len(d.issuerNameSpaces[namespace]))
		item := MustNewIssuerSignedItem(digestID, k, processedValue)
		d.issuerNameSpaces[namespace] = append(d.issuerNameSpaces[namespace], item)
	}

	return d
}

// processValue handles special value processing for MDL namespace.
func (d *Document) processValue(namespace, key string, value any) any {
	// Only process MDL namespace
	if namespace != NamespaceMDL {
		return value
	}

	// Handle date fields
	dateFields := map[string]bool{
		"birth_date":  true,
		"issue_date":  true,
		"expiry_date": true,
	}

	if dateFields[key] {
		switch v := value.(type) {
		case string:
			// Parse string to DateOnly
			dateOnly, err := cbor.ParseDateOnly(v)
			if err == nil {
				return dateOnly
			}
		case time.Time:
			return cbor.DateOnlyFromTime(v)
		case cbor.DateOnly:
			return v
		}
	}

	// Handle driving_privileges array
	if key == "driving_privileges" {
		if privileges, ok := value.([]map[string]any); ok {
			processed := make([]map[string]any, len(privileges))
			for i, priv := range privileges {
				processed[i] = d.processDrivingPrivilege(priv)
			}
			return processed
		}
		if privileges, ok := value.([]any); ok {
			processed := make([]any, len(privileges))
			for i, priv := range privileges {
				if privMap, ok := priv.(map[string]any); ok {
					processed[i] = d.processDrivingPrivilege(privMap)
				} else {
					processed[i] = priv
				}
			}
			return processed
		}
	}

	return value
}

// processDrivingPrivilege processes a single driving privilege entry.
func (d *Document) processDrivingPrivilege(priv map[string]any) map[string]any {
	result := make(map[string]any)
	for k, v := range priv {
		if k == "issue_date" || k == "expiry_date" {
			switch val := v.(type) {
			case string:
				dateOnly, err := cbor.ParseDateOnly(val)
				if err == nil {
					result[k] = dateOnly
				} else {
					result[k] = v
				}
			case time.Time:
				result[k] = cbor.DateOnlyFromTime(val)
			default:
				result[k] = v
			}
		} else {
			result[k] = v
		}
	}
	return result
}

// GetIssuerNameSpace returns the values for a namespace.
func (d *Document) GetIssuerNameSpace(namespace string) map[string]any {
	items := d.issuerNameSpaces[namespace]
	if len(items) == 0 {
		return nil
	}
	result := make(map[string]any, len(items))
	for _, item := range items {
		result[item.ElementIdentifier] = item.ElementValue
	}
	return result
}

// AddDeviceKeyInfo adds the device's public key.
func (d *Document) AddDeviceKeyInfo(deviceKey any) *Document {
	var coseKey map[any]any

	switch k := deviceKey.(type) {
	case *ecdsa.PublicKey:
		key, err := mcose.FromECDSAPublicKey(k)
		if err == nil {
			coseKey = key
		}
	case ed25519.PublicKey:
		key, err := mcose.FromEd25519PublicKey(k)
		if err == nil {
			coseKey = key
		}
	case map[string]string, map[string]any, string, JWK, *JWK:
		jwk, err := ParseJWK(k)
		if err == nil {
			key, err := jwk.ToCOSEKey()
			if err == nil {
				coseKey = key
			}
		}
	case map[any]any:
		coseKey = k
	case mcose.COSEKey:
		coseKey = k
	case []byte:
		// Try JSON JWK first, then CBOR-encoded COSE key
		if jwk, err := ParseJWK(k); err == nil {
			if key, err := jwk.ToCOSEKey(); err == nil {
				coseKey = key
				break
			}
		}
		parsed, err := mcose.ParseCOSEKey(k)
		if err == nil {
			coseKey = parsed
		}
	}

	if coseKey != nil {
		d.deviceKeyInfo = &DeviceKeyInfo{DeviceKey: coseKey}
	}
	return d
}

// AddValidityInfo sets the validity information.
func (d *Document) AddValidityInfo(info ValidityInfo) *Document {
	if !info.Signed.IsZero() {
		d.validityInfo.Signed = info.Signed.UTC()
	}
	if !info.ValidFrom.IsZero() {
		d.validityInfo.ValidFrom = info.ValidFrom.UTC()
	} else {
		d.validityInfo.ValidFrom = d.validityInfo.Signed
	}
	if !info.ValidUntil.IsZero() {
		d.validityInfo.ValidUntil = info.ValidUntil.UTC()
	}
	if info.ExpectedUpdate != nil {
		t := info.ExpectedUpdate.UTC()
		d.validityInfo.ExpectedUpdate = &t
	}
	return d
}

// UseDigestAlgorithm sets the digest algorithm.
func (d *Document) UseDigestAlgorithm(alg DigestAlgorithm) *Document {
	d.digestAlgorithm = alg
	return d
}

// Sign signs the document and returns an IssuerSignedDocument.
func (d *Document) Sign(params SignParams) (*IssuerSignedDocument, error) {
	// Build namespaces with IssuerSignedItems
	nameSpaces := make(IssuerNameSpaces)
	valueDigests := make(map[string]map[uint64][]byte)

	for ns, items := range d.issuerNameSpaces {
		nameSpaces[ns] = make([]*IssuerSignedItem, 0, len(items))
		valueDigests[ns] = make(map[uint64][]byte)

		for _, item := range items {
			// Calculate digest
			digest, err := item.CalculateDigest(d.digestAlgorithm)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate digest for %s.%s: %w", ns, item.ElementIdentifier, err)
			}

			nameSpaces[ns] = append(nameSpaces[ns], item)
			valueDigests[ns][item.DigestID] = digest
		}
	}

	// Create MSO
	mso := &MSO{
		Version:         "1.0",
		DigestAlgorithm: d.digestAlgorithm,
		DocType:         d.docType,
		ValueDigests:    valueDigests,
		ValidityInfo:    d.validityInfo,
		DeviceKeyInfo:   d.deviceKeyInfo,
	}

	// Sign MSO
	issuerAuth, err := SignMSO(mso, params)
	if err != nil {
		return nil, fmt.Errorf("failed to sign MSO: %w", err)
	}

	// Create IssuerSigned
	issuerSigned := &IssuerSigned{
		NameSpaces: nameSpaces,
		IssuerAuth: issuerAuth,
	}

	return NewIssuerSignedDocument(d.docType, issuerSigned), nil
}

// Validate validates the document configuration before signing.
func (d *Document) Validate() error {
	if d.docType == "" {
		return fmt.Errorf("docType is required")
	}
	if len(d.issuerNameSpaces) == 0 {
		return fmt.Errorf("at least one namespace is required")
	}
	if d.validityInfo.Signed.IsZero() {
		return fmt.Errorf("validityInfo.Signed is required")
	}
	if d.validityInfo.ValidFrom.IsZero() {
		return fmt.Errorf("validityInfo.ValidFrom is required")
	}
	if d.validityInfo.ValidUntil.IsZero() {
		return fmt.Errorf("validityInfo.ValidUntil is required")
	}
	if d.validityInfo.ValidFrom.After(d.validityInfo.ValidUntil) {
		return fmt.Errorf("validityInfo.ValidFrom must be before ValidUntil")
	}
	return nil
}
