package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/georgepadayatti/mdoc/cbor"
	"github.com/veraison/go-cose"
)

// DeviceResponse is a builder for creating device responses.
type DeviceResponse struct {
	mdoc                   *MDoc
	presentationDefinition *PresentationDefinition
	sessionTranscriptBytes []byte
	useMAC                 bool
	devicePrivateKey       any
	ephemeralPublicKey     *ecdsa.PublicKey
	signatureAlgorithm     SignatureAlgorithm
	macAlgorithm           MacAlgorithm
	deviceNameSpaces       DeviceNameSpaces
	err                    error
}

// DeviceResponseFrom creates a new DeviceResponse builder from an MDoc.
func DeviceResponseFrom(mdoc *MDoc) *DeviceResponse {
	return &DeviceResponse{
		mdoc:             mdoc,
		useMAC:           true, // Default to MAC
		deviceNameSpaces: make(DeviceNameSpaces),
		macAlgorithm:     MacAlgorithmHS256,
	}
}

// DeviceResponseFromBytes creates a new DeviceResponse builder from CBOR bytes.
func DeviceResponseFromBytes(data []byte) (*DeviceResponse, error) {
	mdoc, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MDoc: %w", err)
	}
	return DeviceResponseFrom(mdoc), nil
}

// UsingPresentationDefinition sets the presentation definition for selective disclosure.
func (dr *DeviceResponse) UsingPresentationDefinition(pd *PresentationDefinition) *DeviceResponse {
	dr.presentationDefinition = pd
	return dr
}

// UsingSessionTranscriptBytes sets the session transcript bytes directly.
func (dr *DeviceResponse) UsingSessionTranscriptBytes(transcriptBytes []byte) *DeviceResponse {
	if dr.sessionTranscriptBytes != nil {
		dr.err = fmt.Errorf("session transcript already set")
		return dr
	}
	dr.sessionTranscriptBytes = transcriptBytes
	return dr
}

// UsingSessionTranscriptForOID4VP creates and sets a session transcript for OID4VP.
func (dr *DeviceResponse) UsingSessionTranscriptForOID4VP(
	mdocGeneratedNonce, clientID, responseURI, verifierGeneratedNonce string,
) *DeviceResponse {
	transcript, err := CreateSessionTranscriptOID4VP(
		mdocGeneratedNonce, clientID, responseURI, verifierGeneratedNonce,
	)
	if err != nil {
		dr.err = err
		return dr
	}
	dr.UsingSessionTranscriptBytes(transcript)
	return dr
}

// UsingHandover sets the session transcript using a raw OID4VP handover array.
// Deprecated: prefer UsingSessionTranscriptForOID4VP.
func (dr *DeviceResponse) UsingHandover(handover []string) *DeviceResponse {
	transcript := cbor.NewDataItem([]any{nil, nil, handover})
	encoded, err := cbor.Encode(transcript)
	if err != nil {
		dr.err = err
		return dr
	}
	return dr.UsingSessionTranscriptBytes(encoded)
}

// UsingSessionTranscriptForWebAPI creates and sets a session transcript for Web API.
func (dr *DeviceResponse) UsingSessionTranscriptForWebAPI(
	deviceEngagementBytes, eReaderKeyBytes, readerEngagementBytes []byte,
) *DeviceResponse {
	transcript, err := CreateSessionTranscriptWebAPI(
		deviceEngagementBytes, eReaderKeyBytes, readerEngagementBytes,
	)
	if err != nil {
		dr.err = err
		return dr
	}
	dr.UsingSessionTranscriptBytes(transcript)
	return dr
}

// AddDeviceNameSpace adds device-signed attributes.
func (dr *DeviceResponse) AddDeviceNameSpace(namespace string, data map[string]any) *DeviceResponse {
	dr.deviceNameSpaces[namespace] = data
	return dr
}

// AuthenticateWithSignature configures signature-based device authentication.
func (dr *DeviceResponse) AuthenticateWithSignature(
	devicePrivateKey any,
	alg SignatureAlgorithm,
) *DeviceResponse {
	key, err := ParsePrivateKey(devicePrivateKey)
	if err != nil {
		dr.err = err
		return dr
	}
	dr.useMAC = false
	dr.devicePrivateKey = key
	dr.signatureAlgorithm = alg
	return dr
}

// AuthenticateWithMAC configures MAC-based device authentication.
func (dr *DeviceResponse) AuthenticateWithMAC(
	devicePrivateKey any,
	ephemeralPublicKey any,
	alg MacAlgorithm,
) *DeviceResponse {
	privKey, err := ParseECDSAPrivateKey(devicePrivateKey)
	if err != nil {
		dr.err = err
		return dr
	}
	pubKey, err := ParseECDSAPublicKey(ephemeralPublicKey)
	if err != nil {
		dr.err = err
		return dr
	}
	dr.useMAC = true
	dr.devicePrivateKey = privKey
	dr.ephemeralPublicKey = pubKey
	dr.macAlgorithm = alg
	return dr
}

// Sign builds and signs the device response, returning an MDoc.
func (dr *DeviceResponse) Sign() (*MDoc, error) {
	if dr.mdoc == nil {
		return nil, fmt.Errorf("source MDoc not set")
	}
	if dr.err != nil {
		return nil, dr.err
	}
	if dr.presentationDefinition == nil {
		return nil, fmt.Errorf("presentation definition not set")
	}
	if err := dr.presentationDefinition.Validate(); err != nil {
		return nil, fmt.Errorf("invalid presentation definition: %w", err)
	}
	if dr.sessionTranscriptBytes == nil {
		return nil, ErrMissingSessionTranscript
	}

	// Process each input descriptor
	var documents []interface{}
	for _, inputDescriptor := range dr.presentationDefinition.InputDescriptors {
		doc, err := dr.handleInputDescriptor(inputDescriptor)
		if err != nil {
			return nil, fmt.Errorf("failed to process input descriptor %s: %w", inputDescriptor.ID, err)
		}
		if doc != nil {
			documents = append(documents, doc)
		}
	}

	return &MDoc{
		Version:   "1.0",
		Documents: documents,
		Status:    StatusOK,
	}, nil
}

// handleInputDescriptor processes a single input descriptor.
func (dr *DeviceResponse) handleInputDescriptor(id InputDescriptor) (*DeviceSignedDocument, error) {
	docType := DocType(id.ID)

	// Find the source document
	var sourceDoc *IssuerSignedDocument
	for _, doc := range dr.mdoc.Documents {
		switch d := doc.(type) {
		case *IssuerSignedDocument:
			if d.DocType == docType {
				sourceDoc = d
				break
			}
		case *DeviceSignedDocument:
			if d.DocType == docType {
				sourceDoc = d.IssuerSignedDocument
				break
			}
		}
	}

	if sourceDoc == nil {
		return nil, fmt.Errorf("document type %s not found in source MDoc", docType)
	}

	// Filter namespaces based on constraints
	filteredNameSpaces, err := dr.prepareNamespaces(id, sourceDoc)
	if err != nil {
		return nil, err
	}

	// Create device signed structure
	deviceSigned, err := dr.getDeviceSigned(docType)
	if err != nil {
		return nil, err
	}

	// Create new IssuerSigned with filtered namespaces
	issuerSigned := &IssuerSigned{
		NameSpaces: filteredNameSpaces,
		IssuerAuth: sourceDoc.IssuerSigned.IssuerAuth,
	}

	return NewDeviceSignedDocument(docType, issuerSigned, deviceSigned), nil
}

// prepareNamespaces filters namespaces based on the input descriptor.
func (dr *DeviceResponse) prepareNamespaces(
	id InputDescriptor,
	sourceDoc *IssuerSignedDocument,
) (IssuerNameSpaces, error) {
	result := make(IssuerNameSpaces)

	for _, field := range id.Constraints.Fields {
		for _, path := range field.Path {
			parsed, err := ParsePath(path)
			if err != nil {
				continue
			}

			// Find the item in source document
			item := dr.findItem(sourceDoc, parsed.Namespace, parsed.ElementIdentifier)
			if item != nil {
				if result[parsed.Namespace] == nil {
					result[parsed.Namespace] = make([]*IssuerSignedItem, 0)
				}
				result[parsed.Namespace] = append(result[parsed.Namespace], item)
			} else if IsAgeOverField(parsed.ElementIdentifier) {
				// Handle age_over_NN special case
				item := dr.handleAgeOverNN(parsed.ElementIdentifier, parsed.Namespace, sourceDoc)
				if item != nil {
					if result[parsed.Namespace] == nil {
						result[parsed.Namespace] = make([]*IssuerSignedItem, 0)
					}
					result[parsed.Namespace] = append(result[parsed.Namespace], item)
				}
			}
		}
	}

	return result, nil
}

// findItem finds an IssuerSignedItem by namespace and element identifier.
func (dr *DeviceResponse) findItem(
	doc *IssuerSignedDocument,
	namespace, elementIdentifier string,
) *IssuerSignedItem {
	if doc.IssuerSigned == nil {
		return nil
	}
	items, ok := doc.IssuerSigned.NameSpaces[namespace]
	if !ok {
		return nil
	}
	for _, item := range items {
		if item.ElementIdentifier == elementIdentifier {
			return item
		}
	}
	return nil
}

// handleAgeOverNN handles the special age_over_NN attribute selection.
func (dr *DeviceResponse) handleAgeOverNN(
	requestedField, namespace string,
	doc *IssuerSignedDocument,
) *IssuerSignedItem {
	requestedAge, err := ParseAgeOverValue(requestedField)
	if err != nil {
		return nil
	}

	if doc.IssuerSigned == nil {
		return nil
	}
	items, ok := doc.IssuerSigned.NameSpaces[namespace]
	if !ok {
		return nil
	}

	// Collect all age_over_NN fields
	type ageField struct {
		age   int
		value bool
		item  *IssuerSignedItem
	}
	var ageFields []ageField

	for _, item := range items {
		if !IsAgeOverField(item.ElementIdentifier) {
			continue
		}
		age, err := ParseAgeOverValue(item.ElementIdentifier)
		if err != nil {
			continue
		}
		val, ok := item.ElementValue.(bool)
		if !ok {
			continue
		}
		ageFields = append(ageFields, ageField{age: age, value: val, item: item})
	}

	if len(ageFields) == 0 {
		return nil
	}

	// Sort by age
	sort.Slice(ageFields, func(i, j int) bool {
		return ageFields[i].age < ageFields[j].age
	})

	// Find the nearest true value >= requested age
	for _, af := range ageFields {
		if af.value && af.age >= requestedAge {
			return af.item
		}
	}

	// If no true found, find the nearest false value <= requested age
	for i := len(ageFields) - 1; i >= 0; i-- {
		af := ageFields[i]
		if !af.value && af.age <= requestedAge {
			return af.item
		}
	}

	return nil
}

// getDeviceSigned creates the DeviceSigned structure.
func (dr *DeviceResponse) getDeviceSigned(docType DocType) (*DeviceSigned, error) {
	deviceAuthBytes, err := CalculateDeviceAuthenticationBytes(
		dr.sessionTranscriptBytes,
		docType,
		dr.deviceNameSpaces,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate device auth bytes: %w", err)
	}

	var deviceAuth *DeviceAuth
	if dr.useMAC {
		deviceAuth, err = dr.getDeviceAuthMAC(deviceAuthBytes)
	} else {
		deviceAuth, err = dr.getDeviceAuthSign(deviceAuthBytes)
	}
	if err != nil {
		return nil, err
	}

	return &DeviceSigned{
		NameSpaces: dr.deviceNameSpaces,
		DeviceAuth: deviceAuth,
	}, nil
}

// getDeviceAuthSign creates signature-based device authentication.
func (dr *DeviceResponse) getDeviceAuthSign(deviceAuthBytes []byte) (*DeviceAuth, error) {
	if dr.devicePrivateKey == nil {
		return nil, fmt.Errorf("device private key not set")
	}

	// Create COSE Sign1 message
	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.Algorithm(dr.signatureAlgorithm))
	msg.Payload = deviceAuthBytes

	// Create signer
	signerKey, ok := dr.devicePrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("device private key is not a signer")
	}
	signer, err := cose.NewSigner(cose.Algorithm(dr.signatureAlgorithm), signerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// Sign
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("failed to sign device auth: %w", err)
	}

	return &DeviceAuth{DeviceSignature: msg}, nil
}

// getDeviceAuthMAC creates MAC-based device authentication.
func (dr *DeviceResponse) getDeviceAuthMAC(deviceAuthBytes []byte) (*DeviceAuth, error) {
	if dr.devicePrivateKey == nil {
		return nil, fmt.Errorf("device private key not set")
	}
	if dr.ephemeralPublicKey == nil {
		return nil, fmt.Errorf("ephemeral public key not set")
	}

	privKey, ok := dr.devicePrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("device private key is not ECDSA")
	}

	// Calculate ephemeral MAC key
	macKey, err := CalculateEphemeralMacKey(
		privKey,
		dr.ephemeralPublicKey,
		dr.sessionTranscriptBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate MAC key: %w", err)
	}

	// Create Mac0 message
	msg := NewMac0Message()
	msg.SetAlgorithm(AlgHMAC256)
	msg.Payload = deviceAuthBytes

	// Compute MAC
	if err := msg.ComputeMAC(macKey); err != nil {
		return nil, fmt.Errorf("failed to compute MAC: %w", err)
	}

	return &DeviceAuth{DeviceMAC: msg}, nil
}

// GenerateMdocNonce generates a random nonce for OID4VP.
func GenerateMdocNonce() (string, error) {
	bytes, err := GetRandomBytes(16)
	if err != nil {
		return "", err
	}
	// Convert to hex string
	var sb strings.Builder
	for _, b := range bytes {
		sb.WriteString(strconv.FormatInt(int64(b), 16))
	}
	return sb.String(), nil
}
