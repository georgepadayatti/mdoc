package mdoc

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/georgepadayatti/mdoc/cbor"
	"github.com/veraison/go-cose"
)

// DeviceSignedDocument extends IssuerSignedDocument with device-signed data.
type DeviceSignedDocument struct {
	*IssuerSignedDocument
	DeviceSigned *DeviceSigned
}

// NewDeviceSignedDocument creates a new DeviceSignedDocument.
func NewDeviceSignedDocument(
	docType DocType,
	issuerSigned *IssuerSigned,
	deviceSigned *DeviceSigned,
) *DeviceSignedDocument {
	return &DeviceSignedDocument{
		IssuerSignedDocument: NewIssuerSignedDocument(docType, issuerSigned),
		DeviceSigned:         deviceSigned,
	}
}

// GetDeviceNameSpace returns the values for a specific device namespace.
func (d *DeviceSignedDocument) GetDeviceNameSpace(namespace string) map[string]any {
	if d.DeviceSigned == nil {
		return nil
	}
	return d.DeviceSigned.NameSpaces[namespace]
}

// DeviceNameSpaceList returns the list of device namespace identifiers.
func (d *DeviceSignedDocument) DeviceNameSpaceList() []string {
	if d.DeviceSigned == nil {
		return nil
	}
	namespaces := make([]string, 0, len(d.DeviceSigned.NameSpaces))
	for ns := range d.DeviceSigned.NameSpaces {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

// Prepare returns the document in a format suitable for CBOR encoding.
func (d *DeviceSignedDocument) Prepare() (map[string]any, error) {
	// Get base preparation from IssuerSignedDocument
	result, err := d.IssuerSignedDocument.Prepare()
	if err != nil {
		return nil, err
	}

	if d.DeviceSigned == nil {
		return result, nil
	}

	// Prepare device namespaces
	deviceNameSpacesBytes, err := cbor.Encode(d.DeviceSigned.NameSpaces)
	if err != nil {
		return nil, fmt.Errorf("failed to encode device namespaces: %w", err)
	}

	// Prepare device auth
	deviceAuth := make(map[string]any)
	if d.DeviceSigned.DeviceAuth != nil {
		if d.DeviceSigned.DeviceAuth.DeviceMAC != nil {
			// Encode Mac0 with detached payload
			macBytes, err := EncodeMac0(d.DeviceSigned.DeviceAuth.DeviceMAC, true)
			if err != nil {
				return nil, fmt.Errorf("failed to encode deviceMac: %w", err)
			}
			deviceAuth["deviceMac"] = cbor.NewDataItemFromBytes(macBytes)
		}
		if d.DeviceSigned.DeviceAuth.DeviceSignature != nil {
			// Create detached payload version
			sign1 := d.DeviceSigned.DeviceAuth.DeviceSignature
			sign1WithDetached := *sign1
			sign1WithDetached.Payload = nil
			sigBytes, err := sign1WithDetached.MarshalCBOR()
			if err != nil {
				return nil, fmt.Errorf("failed to encode deviceSignature: %w", err)
			}
			deviceAuth["deviceSignature"] = cbor.NewDataItemFromBytes(sigBytes)
		}
	}

	result["deviceSigned"] = map[string]any{
		"nameSpaces": cbor.NewDataItemFromBytes(deviceNameSpacesBytes),
		"deviceAuth": deviceAuth,
	}

	return result, nil
}

// Encode returns the CBOR-encoded representation.
func (d *DeviceSignedDocument) Encode() ([]byte, error) {
	prepared, err := d.Prepare()
	if err != nil {
		return nil, err
	}
	return cbor.Encode(prepared)
}

// HasDeviceMAC returns true if the document has MAC-based device authentication.
func (d *DeviceSignedDocument) HasDeviceMAC() bool {
	return d.DeviceSigned != nil &&
		d.DeviceSigned.DeviceAuth != nil &&
		d.DeviceSigned.DeviceAuth.DeviceMAC != nil
}

// HasDeviceSignature returns true if the document has signature-based device authentication.
func (d *DeviceSignedDocument) HasDeviceSignature() bool {
	return d.DeviceSigned != nil &&
		d.DeviceSigned.DeviceAuth != nil &&
		d.DeviceSigned.DeviceAuth.DeviceSignature != nil
}

// VerifyDeviceSignature verifies the device signature against the device key in the MSO.
func (d *DeviceSignedDocument) VerifyDeviceSignature(sessionTranscript []byte) error {
	if !d.HasDeviceSignature() {
		return fmt.Errorf("no device signature present")
	}

	// Get device key from MSO
	deviceKeyMap, err := d.GetDeviceKey()
	if err != nil {
		return err
	}

	// Parse device key to public key
	deviceKey, err := ParseCOSEKeyToPublicKey(deviceKeyMap)
	if err != nil {
		return fmt.Errorf("failed to parse device key: %w", err)
	}

	// Calculate device authentication bytes
	deviceNameSpaces := d.DeviceSigned.NameSpaces
	if deviceNameSpaces == nil {
		deviceNameSpaces = make(DeviceNameSpaces)
	}

	deviceAuthBytes, err := CalculateDeviceAuthenticationBytes(
		sessionTranscript,
		d.DocType,
		deviceNameSpaces,
	)
	if err != nil {
		return fmt.Errorf("failed to calculate device auth bytes: %w", err)
	}

	// Get the signature
	sign1 := d.DeviceSigned.DeviceAuth.DeviceSignature

	// Create a copy with the payload for verification
	sign1WithPayload := *sign1
	sign1WithPayload.Payload = deviceAuthBytes

	// Get algorithm
	alg, err := sign1.Headers.Protected.Algorithm()
	if err != nil {
		return fmt.Errorf("failed to get algorithm: %w", err)
	}

	// Create verifier
	verifier, err := cose.NewVerifier(alg, deviceKey)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	// Verify
	if err := sign1WithPayload.Verify(nil, verifier); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	return nil
}

// EncodeMac0 encodes a Mac0Message to CBOR bytes.
func EncodeMac0(mac *Mac0Message, detached bool) ([]byte, error) {
	// Mac0 structure: [protected, unprotected, payload, tag]
	protected, err := encodeProtectedMap(mac.Headers.Protected)
	if err != nil {
		return nil, err
	}

	payload := mac.Payload
	if detached {
		payload = nil
	}

	arr := []any{
		protected,
		mac.Headers.Unprotected,
		payload,
		mac.Tag,
	}

	return cbor.Encode(arr)
}

// DecodeMac0 decodes CBOR bytes to a Mac0Message.
func DecodeMac0(data []byte) (*Mac0Message, error) {
	var arr []any
	if err := cbor.Decode(data, &arr); err != nil {
		return nil, err
	}
	if len(arr) != 4 {
		return nil, fmt.Errorf("invalid Mac0 structure: expected 4 elements, got %d", len(arr))
	}

	mac := &Mac0Message{
		Headers: cose.Headers{
			Protected:   make(cose.ProtectedHeader),
			Unprotected: make(cose.UnprotectedHeader),
		},
	}

	// Decode protected header
	if protectedBytes, ok := arr[0].([]byte); ok {
		var header map[any]any
		if err := cbor.Decode(protectedBytes, &header); err != nil {
			return nil, fmt.Errorf("failed to decode protected header: %w", err)
		}
		mac.Headers.Protected = header
	}

	// Decode unprotected header
	if unprotected, ok := arr[1].(map[any]any); ok {
		for k, v := range unprotected {
			mac.Headers.Unprotected[k] = v
		}
	}

	// Payload
	if payload, ok := arr[2].([]byte); ok {
		mac.Payload = payload
	}

	// Tag
	if tag, ok := arr[3].([]byte); ok {
		mac.Tag = tag
	}

	return mac, nil
}

// VerifyMac0 verifies a Mac0Message with the given key.
func VerifyMac0(mac *Mac0Message, key []byte, payload []byte) error {
	// Calculate expected MAC
	// Mac_structure = ["MAC0", protected, external_aad, payload]
	protected, err := encodeProtectedMap(mac.Headers.Protected)
	if err != nil {
		return err
	}

	macStructure := []any{
		"MAC0",
		protected,
		[]byte{}, // external_aad
		payload,
	}

	macInput, err := cbor.Encode(macStructure)
	if err != nil {
		return err
	}

	// Compute HMAC
	expectedTag := HMACSHA256(key, macInput)

	// Compare
	if !ConstantTimeCompare(mac.Tag, expectedTag) {
		return ErrInvalidMAC
	}

	return nil
}

// NewMac0Message creates a new Mac0Message.
func NewMac0Message() *Mac0Message {
	return &Mac0Message{
		Headers: cose.Headers{
			Protected:   make(cose.ProtectedHeader),
			Unprotected: make(cose.UnprotectedHeader),
		},
	}
}

// ComputeMAC computes and sets the MAC tag.
func (m *Mac0Message) ComputeMAC(key []byte) error {
	// Mac_structure = ["MAC0", protected, external_aad, payload]
	protected, err := encodeProtectedMap(m.Headers.Protected)
	if err != nil {
		return err
	}

	macStructure := []any{
		"MAC0",
		protected,
		[]byte{}, // external_aad
		m.Payload,
	}

	macInput, err := cbor.Encode(macStructure)
	if err != nil {
		return err
	}

	// Compute HMAC
	m.Tag = HMACSHA256(key, macInput)
	return nil
}

// SetAlgorithm sets the algorithm in the protected header.
func (m *Mac0Message) SetAlgorithm(alg int64) {
	m.Headers.Protected[int64(1)] = alg
}

// Algorithm returns the algorithm from the protected header.
func (m *Mac0Message) Algorithm() (int64, error) {
	// Try different key types that CBOR might decode to
	for _, key := range []any{int64(1), uint64(1), int(1)} {
		if v, ok := m.Headers.Protected[key]; ok {
			switch alg := v.(type) {
			case int64:
				return alg, nil
			case uint64:
				return int64(alg), nil
			case int:
				return int64(alg), nil
			}
		}
	}
	return 0, fmt.Errorf("algorithm not found in protected header")
}

func encodeProtectedMap(header cose.ProtectedHeader) ([]byte, error) {
	return cbor.Encode(map[any]any(header))
}

// HMAC algorithm identifiers
const (
	AlgHMAC256 int64 = 5 // HMAC 256/256
)

// VerifyMAC verifies the MAC using the device key and ephemeral reader key.
func (d *DeviceSignedDocument) VerifyMAC(
	ephemeralReaderKey *ecdsa.PrivateKey,
	sessionTranscript []byte,
) error {
	if !d.HasDeviceMAC() {
		return fmt.Errorf("no device MAC present")
	}

	// Get device key from MSO
	deviceKeyMap, err := d.GetDeviceKey()
	if err != nil {
		return err
	}

	deviceKey, err := ParseCOSEKeyToECDSA(deviceKeyMap)
	if err != nil {
		return fmt.Errorf("failed to parse device key: %w", err)
	}

	// Calculate MAC key
	macKey, err := CalculateEphemeralMacKey(ephemeralReaderKey, deviceKey, sessionTranscript)
	if err != nil {
		return fmt.Errorf("failed to calculate MAC key: %w", err)
	}

	// Calculate device authentication bytes
	deviceNameSpaces := d.DeviceSigned.NameSpaces
	if deviceNameSpaces == nil {
		deviceNameSpaces = make(DeviceNameSpaces)
	}

	deviceAuthBytes, err := CalculateDeviceAuthenticationBytes(
		sessionTranscript,
		d.DocType,
		deviceNameSpaces,
	)
	if err != nil {
		return fmt.Errorf("failed to calculate device auth bytes: %w", err)
	}

	// Verify MAC
	return VerifyMac0(d.DeviceSigned.DeviceAuth.DeviceMAC, macKey, deviceAuthBytes)
}
