package mdoc

import (
	"fmt"

	"github.com/georgepadayatti/mdoc/cbor"
	"github.com/veraison/go-cose"
)

// Parse parses a CBOR-encoded MDoc (device response).
func Parse(data []byte) (*MDoc, error) {
	var raw map[string]any
	if err := cbor.Decode(data, &raw); err != nil {
		return nil, WrapParseError("failed to decode MDoc", err)
	}

	return parseRawMDoc(raw)
}

// parseRawMDoc parses an MDoc from a raw map.
func parseRawMDoc(raw map[string]any) (*MDoc, error) {
	mdoc := &MDoc{}

	// Extract version
	if v, ok := raw["version"].(string); ok {
		mdoc.Version = v
	} else {
		return nil, NewParseError("missing or invalid version")
	}

	// Extract status
	if s, ok := raw["status"]; ok {
		switch v := s.(type) {
		case int64:
			mdoc.Status = MDocStatus(v)
		case uint64:
			mdoc.Status = MDocStatus(v)
		case int:
			mdoc.Status = MDocStatus(v)
		}
	}

	// Extract documents
	docsRaw, ok := raw["documents"].([]any)
	if !ok {
		return nil, NewParseError("missing or invalid documents")
	}

	for i, docRaw := range docsRaw {
		docMap, ok := docRaw.(map[string]any)
		if !ok {
			if rawMap, ok := docRaw.(map[any]any); ok {
				docMap = make(map[string]any)
				for k, v := range rawMap {
					if ks, ok := k.(string); ok {
						docMap[ks] = v
					}
				}
			} else {
				return nil, NewParseError(fmt.Sprintf("invalid document at index %d", i))
			}
		}

		doc, err := parseDocument(docMap)
		if err != nil {
			return nil, WrapParseError(fmt.Sprintf("failed to parse document %d", i), err)
		}
		mdoc.Documents = append(mdoc.Documents, doc)
	}

	return mdoc, nil
}

// parseDocument parses a single document.
func parseDocument(raw map[string]any) (interface{}, error) {
	// Extract docType
	docType, ok := raw["docType"].(string)
	if !ok {
		return nil, NewParseError("missing or invalid docType")
	}

	// Parse issuerSigned
	issuerSignedRaw, ok := raw["issuerSigned"].(map[string]any)
	if !ok {
		if m, ok := raw["issuerSigned"].(map[any]any); ok {
			issuerSignedRaw = make(map[string]any)
			for k, v := range m {
				if ks, ok := k.(string); ok {
					issuerSignedRaw[ks] = v
				}
			}
		} else {
			return nil, NewParseError("missing or invalid issuerSigned")
		}
	}

	issuerSigned, err := parseIssuerSigned(issuerSignedRaw)
	if err != nil {
		return nil, WrapParseError("failed to parse issuerSigned", err)
	}
	if issuerSigned.IssuerAuth == nil || issuerSigned.IssuerAuth.MSO() == nil {
		return nil, NewParseError("issuerAuth MSO missing or invalid")
	}
	mso := issuerSigned.IssuerAuth.MSO()
	if mso.DocType != DocType(docType) {
		return nil, NewParseError(fmt.Sprintf("issuerAuth docType must be %s", docType))
	}
	if mso.Version != "1.0" {
		return nil, NewParseError("issuerAuth version must be 1.0")
	}

	// Check for deviceSigned
	deviceSignedRaw, hasDeviceSigned := raw["deviceSigned"].(map[string]any)
	if !hasDeviceSigned {
		if m, ok := raw["deviceSigned"].(map[any]any); ok {
			deviceSignedRaw = make(map[string]any)
			for k, v := range m {
				if ks, ok := k.(string); ok {
					deviceSignedRaw[ks] = v
				}
			}
			hasDeviceSigned = true
		}
	}
	if hasDeviceSigned {
		deviceSigned, err := parseDeviceSigned(deviceSignedRaw)
		if err != nil {
			return nil, WrapParseError("failed to parse deviceSigned", err)
		}
		return NewDeviceSignedDocument(DocType(docType), issuerSigned, deviceSigned), nil
	}

	return NewIssuerSignedDocument(DocType(docType), issuerSigned), nil
}

// parseIssuerSigned parses the issuerSigned portion.
func parseIssuerSigned(raw map[string]any) (*IssuerSigned, error) {
	issuerSigned := &IssuerSigned{
		NameSpaces: make(IssuerNameSpaces),
	}

	// Parse nameSpaces
	nameSpacesRaw, ok := raw["nameSpaces"].(map[string]any)
	if !ok {
		// Try map[any]any
		if nsMap, ok := raw["nameSpaces"].(map[any]any); ok {
			nameSpacesRaw = make(map[string]any)
			for k, v := range nsMap {
				if ks, ok := k.(string); ok {
					nameSpacesRaw[ks] = v
				}
			}
		}
	}

	for ns, itemsRaw := range nameSpacesRaw {
		items, err := parseNameSpaceItems(itemsRaw)
		if err != nil {
			return nil, WrapParseError(fmt.Sprintf("failed to parse namespace %s", ns), err)
		}
		issuerSigned.NameSpaces[ns] = items
	}

	// Parse issuerAuth
	issuerAuthRaw := raw["issuerAuth"]
	issuerAuth, err := parseIssuerAuth(issuerAuthRaw)
	if err != nil {
		return nil, WrapParseError("failed to parse issuerAuth", err)
	}
	issuerSigned.IssuerAuth = issuerAuth

	return issuerSigned, nil
}

// parseNameSpaceItems parses a list of IssuerSignedItems for a namespace.
func parseNameSpaceItems(itemsRaw any) ([]*IssuerSignedItem, error) {
	itemsList, ok := itemsRaw.([]any)
	if !ok {
		return nil, NewParseError("expected array of items")
	}

	items := make([]*IssuerSignedItem, 0, len(itemsList))
	for i, itemRaw := range itemsList {
		item, err := parseIssuerSignedItemFromRaw(itemRaw)
		if err != nil {
			return nil, WrapParseError(fmt.Sprintf("failed to parse item %d", i), err)
		}
		items = append(items, item)
	}

	return items, nil
}

// parseIssuerSignedItemFromRaw parses an IssuerSignedItem from various formats.
func parseIssuerSignedItemFromRaw(raw any) (*IssuerSignedItem, error) {
	switch v := raw.(type) {
	case []byte:
		return ParseIssuerSignedItem(v)
	case cbor.DataItem:
		data, err := v.Bytes()
		if err != nil {
			return nil, WrapParseError("failed to get DataItem bytes", err)
		}
		return ParseIssuerSignedItem(data)
	case *cbor.DataItem:
		return ParseIssuerSignedItemFromDataItem(v)
	case map[string]any:
		return parseIssuerSignedItemFromMap(v)
	case map[any]any:
		converted := make(map[string]any)
		for k, val := range v {
			if ks, ok := k.(string); ok {
				converted[ks] = val
			}
		}
		return parseIssuerSignedItemFromMap(converted)
	default:
		return nil, NewParseError(fmt.Sprintf("unexpected item type: %T", raw))
	}
}

// parseIssuerSignedItemFromMap parses an IssuerSignedItem from a map.
func parseIssuerSignedItemFromMap(m map[string]any) (*IssuerSignedItem, error) {
	item := &IssuerSignedItem{}

	// Extract digestID
	switch v := m["digestID"].(type) {
	case uint64:
		item.DigestID = v
	case int64:
		item.DigestID = uint64(v)
	case int:
		item.DigestID = uint64(v)
	default:
		return nil, NewParseError("missing or invalid digestID")
	}

	// Extract random
	if random, ok := m["random"].([]byte); ok {
		item.Random = random
	} else {
		return nil, NewParseError("missing or invalid random")
	}

	// Extract elementIdentifier
	if elementIdentifier, ok := m["elementIdentifier"].(string); ok {
		item.ElementIdentifier = elementIdentifier
	} else {
		return nil, NewParseError("missing or invalid elementIdentifier")
	}

	// Extract elementValue
	item.ElementValue = m["elementValue"]

	return item, nil
}

// parseIssuerAuth parses the issuerAuth from various formats.
func parseIssuerAuth(raw any) (*IssuerAuth, error) {
	switch v := raw.(type) {
	case []byte:
		return ParseIssuerAuth(v)
	case cbor.DataItem:
		data, err := v.Bytes()
		if err != nil {
			return nil, WrapParseError("failed to get DataItem bytes", err)
		}
		return ParseIssuerAuth(data)
	case *cbor.DataItem:
		data, err := v.Bytes()
		if err != nil {
			return nil, WrapParseError("failed to get DataItem bytes", err)
		}
		return ParseIssuerAuth(data)
	case []any:
		encoded, err := cbor.Encode(v)
		if err != nil {
			return nil, WrapParseError("failed to encode issuerAuth", err)
		}
		return ParseIssuerAuth(encoded)
	default:
		return nil, NewParseError(fmt.Sprintf("unexpected issuerAuth type: %T", raw))
	}
}

// parseDeviceSigned parses the deviceSigned portion.
func parseDeviceSigned(raw map[string]any) (*DeviceSigned, error) {
	deviceSigned := &DeviceSigned{
		NameSpaces: make(DeviceNameSpaces),
	}

	// Parse nameSpaces (it's a DataItem containing CBOR-encoded map)
	if nsRaw := raw["nameSpaces"]; nsRaw != nil {
		switch v := nsRaw.(type) {
		case cbor.DataItem:
			data, err := v.Bytes()
			if err != nil {
				return nil, WrapParseError("failed to get nameSpaces bytes", err)
			}
			var ns map[string]map[string]any
			if err := cbor.Decode(data, &ns); err != nil {
				return nil, WrapParseError("failed to decode nameSpaces", err)
			}
			deviceSigned.NameSpaces = ns
		case *cbor.DataItem:
			data, err := v.Bytes()
			if err != nil {
				return nil, WrapParseError("failed to get nameSpaces bytes", err)
			}
			var ns map[string]map[string]any
			if err := cbor.Decode(data, &ns); err != nil {
				return nil, WrapParseError("failed to decode nameSpaces", err)
			}
			deviceSigned.NameSpaces = ns
		case []byte:
			var ns map[string]map[string]any
			if err := cbor.Decode(v, &ns); err != nil {
				return nil, WrapParseError("failed to decode nameSpaces", err)
			}
			deviceSigned.NameSpaces = ns
		case map[string]any:
			for k, val := range v {
				if valMap, ok := val.(map[string]any); ok {
					deviceSigned.NameSpaces[k] = valMap
				}
			}
		}
	}

	// Parse deviceAuth
	if deviceAuthRaw, ok := raw["deviceAuth"].(map[string]any); ok {
		deviceAuth, err := parseDeviceAuth(deviceAuthRaw)
		if err != nil {
			return nil, WrapParseError("failed to parse deviceAuth", err)
		}
		deviceSigned.DeviceAuth = deviceAuth
	} else if deviceAuthRaw, ok := raw["deviceAuth"].(map[any]any); ok {
		converted := make(map[string]any)
		for k, v := range deviceAuthRaw {
			if ks, ok := k.(string); ok {
				converted[ks] = v
			}
		}
		deviceAuth, err := parseDeviceAuth(converted)
		if err != nil {
			return nil, WrapParseError("failed to parse deviceAuth", err)
		}
		deviceSigned.DeviceAuth = deviceAuth
	}

	return deviceSigned, nil
}

// parseDeviceAuth parses the deviceAuth structure.
func parseDeviceAuth(raw map[string]any) (*DeviceAuth, error) {
	deviceAuth := &DeviceAuth{}

	// Check for deviceMac
	if macRaw := raw["deviceMac"]; macRaw != nil {
		mac0, err := parseMac0(macRaw)
		if err != nil {
			return nil, WrapParseError("failed to parse deviceMac", err)
		}
		deviceAuth.DeviceMAC = mac0
	}

	// Check for deviceSignature
	if sigRaw := raw["deviceSignature"]; sigRaw != nil {
		sign1, err := parseSign1(sigRaw)
		if err != nil {
			return nil, WrapParseError("failed to parse deviceSignature", err)
		}
		deviceAuth.DeviceSignature = sign1
	}

	return deviceAuth, nil
}

// parseMac0 parses a COSE_Mac0 message.
func parseMac0(raw any) (*Mac0Message, error) {
	var data []byte
	switch v := raw.(type) {
	case []byte:
		data = v
	case cbor.DataItem:
		var err error
		data, err = v.Bytes()
		if err != nil {
			return nil, err
		}
	case *cbor.DataItem:
		var err error
		data, err = v.Bytes()
		if err != nil {
			return nil, err
		}
	case []any:
		var err error
		data, err = cbor.Encode(v)
		if err != nil {
			return nil, err
		}
	default:
		return nil, NewParseError(fmt.Sprintf("unexpected Mac0 type: %T", raw))
	}

	return DecodeMac0(data)
}

// parseSign1 parses a COSE_Sign1 message.
func parseSign1(raw any) (*cose.Sign1Message, error) {
	var data []byte
	switch v := raw.(type) {
	case []byte:
		data = v
	case cbor.DataItem:
		var err error
		data, err = v.Bytes()
		if err != nil {
			return nil, err
		}
	case *cbor.DataItem:
		var err error
		data, err = v.Bytes()
		if err != nil {
			return nil, err
		}
	case []any:
		var err error
		data, err = cbor.Encode(v)
		if err != nil {
			return nil, err
		}
	default:
		return nil, NewParseError(fmt.Sprintf("unexpected Sign1 type: %T", raw))
	}

	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(data); err != nil {
		if len(data) > 0 && data[0] == 0x84 {
			tagged := append([]byte{0xd2}, data...)
			if msg.UnmarshalCBOR(tagged) == nil {
				return msg, nil
			}
		}
		return nil, err
	}
	return msg, nil
}
