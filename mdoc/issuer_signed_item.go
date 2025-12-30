package mdoc

import (
	"fmt"

	"github.com/georgepadayatti/mdoc/cbor"
)

// IssuerSignedItem represents a single attribute signed by the issuer.
// It contains the attribute identifier, value, and random salt for digest calculation.
type IssuerSignedItem struct {
	DigestID          uint64 `cbor:"digestID"`
	Random            []byte `cbor:"random"`
	ElementIdentifier string `cbor:"elementIdentifier"`
	ElementValue      any    `cbor:"elementValue"`

	// Cached values
	rawBytes  []byte
	isValid   *bool
}

// NewIssuerSignedItem creates a new IssuerSignedItem with a random salt.
func NewIssuerSignedItem(digestID uint64, elementIdentifier string, elementValue any) (*IssuerSignedItem, error) {
	random, err := GetRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random: %w", err)
	}

	return &IssuerSignedItem{
		DigestID:          digestID,
		Random:            random,
		ElementIdentifier: elementIdentifier,
		ElementValue:      elementValue,
	}, nil
}

// MustNewIssuerSignedItem creates a new IssuerSignedItem and panics on error.
func MustNewIssuerSignedItem(digestID uint64, elementIdentifier string, elementValue any) *IssuerSignedItem {
	item, err := NewIssuerSignedItem(digestID, elementIdentifier, elementValue)
	if err != nil {
		panic(err)
	}
	return item
}

// Encode returns the CBOR-encoded representation of the item.
func (i *IssuerSignedItem) Encode() ([]byte, error) {
	if i.rawBytes != nil {
		return i.rawBytes, nil
	}

	// Create ordered map for encoding
	m := map[string]any{
		"digestID":          i.DigestID,
		"random":            i.Random,
		"elementIdentifier": i.ElementIdentifier,
		"elementValue":      i.ElementValue,
	}

	encoded, err := cbor.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("failed to encode IssuerSignedItem: %w", err)
	}
	i.rawBytes = encoded
	return encoded, nil
}

// MustEncode returns the CBOR-encoded representation and panics on error.
func (i *IssuerSignedItem) MustEncode() []byte {
	encoded, err := i.Encode()
	if err != nil {
		panic(err)
	}
	return encoded
}

// CalculateDigest calculates the digest of this item using the specified algorithm.
func (i *IssuerSignedItem) CalculateDigest(alg DigestAlgorithm) ([]byte, error) {
	encoded, err := i.Encode()
	if err != nil {
		return nil, err
	}
	return CalculateDigest(alg, encoded)
}

// IsValid validates this item against the MSO digests.
func (i *IssuerSignedItem) IsValid(namespace string, issuerAuth *IssuerAuth) (bool, error) {
	if i.isValid != nil {
		return *i.isValid, nil
	}

	mso := issuerAuth.MSO()
	if mso == nil {
		return false, fmt.Errorf("MSO not available")
	}

	// Get expected digest from MSO
	nsDigests, ok := mso.ValueDigests[namespace]
	if !ok {
		return false, fmt.Errorf("namespace %s not found in MSO", namespace)
	}

	expectedDigest, ok := nsDigests[i.DigestID]
	if !ok {
		return false, fmt.Errorf("digest ID %d not found in namespace %s", i.DigestID, namespace)
	}

	// Calculate actual digest
	actualDigest, err := i.CalculateDigest(mso.DigestAlgorithm)
	if err != nil {
		return false, err
	}

	// Compare digests
	valid := ConstantTimeCompare(expectedDigest, actualDigest)
	i.isValid = &valid
	return valid, nil
}

// MatchCertificate checks if specific MDL attributes match the issuer certificate.
// Returns nil if the attribute is not relevant for certificate matching.
func (i *IssuerSignedItem) MatchCertificate(namespace string, issuerAuth *IssuerAuth) *bool {
	// Only check MDL namespace
	if namespace != NamespaceMDL {
		return nil
	}

	var matches bool
	switch i.ElementIdentifier {
	case "issuing_country":
		if countryStr, ok := i.ElementValue.(string); ok {
			matches = countryStr == issuerAuth.CountryName()
		}
	case "issuing_jurisdiction":
		if jurisdictionStr, ok := i.ElementValue.(string); ok {
			matches = jurisdictionStr == issuerAuth.StateOrProvince()
		}
	default:
		return nil
	}
	return &matches
}

// ToDataItem wraps this item in a DataItem for CBOR encoding.
func (i *IssuerSignedItem) ToDataItem() (*cbor.DataItem, error) {
	encoded, err := i.Encode()
	if err != nil {
		return nil, err
	}
	return cbor.NewDataItemFromBytes(encoded), nil
}

// ParseIssuerSignedItem parses an IssuerSignedItem from CBOR bytes.
func ParseIssuerSignedItem(data []byte) (*IssuerSignedItem, error) {
	var raw map[string]any
	if err := cbor.Decode(data, &raw); err != nil {
		return nil, WrapParseError("failed to decode IssuerSignedItem", err)
	}

	item := &IssuerSignedItem{rawBytes: data}

	// Extract digestID
	if digestID, ok := raw["digestID"].(uint64); ok {
		item.DigestID = digestID
	} else if digestID, ok := raw["digestID"].(int64); ok {
		item.DigestID = uint64(digestID)
	} else {
		return nil, NewParseError("missing or invalid digestID")
	}

	// Extract random
	if random, ok := raw["random"].([]byte); ok {
		item.Random = random
	} else {
		return nil, NewParseError("missing or invalid random")
	}

	// Extract elementIdentifier
	if elementIdentifier, ok := raw["elementIdentifier"].(string); ok {
		item.ElementIdentifier = elementIdentifier
	} else {
		return nil, NewParseError("missing or invalid elementIdentifier")
	}

	// Extract elementValue (can be any type)
	item.ElementValue = raw["elementValue"]

	return item, nil
}

// ParseIssuerSignedItemFromDataItem parses an IssuerSignedItem from a DataItem.
func ParseIssuerSignedItemFromDataItem(dataItem *cbor.DataItem) (*IssuerSignedItem, error) {
	data, err := dataItem.Bytes()
	if err != nil {
		return nil, WrapParseError("failed to get DataItem bytes", err)
	}
	return ParseIssuerSignedItem(data)
}
