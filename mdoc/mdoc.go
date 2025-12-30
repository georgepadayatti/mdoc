package mdoc

import (
	"fmt"

	"github.com/georgepadayatti/mdoc/cbor"
)

// MDocStatus represents the status of an MDoc.
type MDocStatus int

const (
	StatusOK              MDocStatus = 0
	StatusGeneralError    MDocStatus = 10
	StatusCBORDecodeError MDocStatus = 11
	StatusCBORValidError  MDocStatus = 12
)

// DocumentError represents an error for a specific document.
type DocumentError struct {
	DocType   DocType
	ErrorCode int
}

// MDoc is the top-level container for mobile documents.
type MDoc struct {
	Version        string
	Documents      []interface{} // Can be IssuerSignedDocument or DeviceSignedDocument
	Status         MDocStatus
	DocumentErrors []DocumentError
}

// NewMDoc creates a new MDoc container.
func NewMDoc(documents ...interface{}) *MDoc {
	return &MDoc{
		Version:   "1.0",
		Documents: documents,
		Status:    StatusOK,
	}
}

// AddDocument adds a document to the MDoc.
// The document must be an IssuerSignedDocument or DeviceSignedDocument.
func (m *MDoc) AddDocument(doc interface{}) error {
	switch d := doc.(type) {
	case *IssuerSignedDocument:
		if d.IssuerSigned == nil {
			return fmt.Errorf("document must be signed")
		}
		m.Documents = append(m.Documents, d)
	case *DeviceSignedDocument:
		if d.IssuerSigned == nil {
			return fmt.Errorf("document must be signed")
		}
		m.Documents = append(m.Documents, d)
	default:
		return fmt.Errorf("unsupported document type: %T", doc)
	}
	return nil
}

// Encode returns the CBOR-encoded representation of the MDoc.
func (m *MDoc) Encode() ([]byte, error) {
	// Prepare documents
	preparedDocs := make([]any, len(m.Documents))
	for i, doc := range m.Documents {
		switch d := doc.(type) {
		case *IssuerSignedDocument:
			prepared, err := d.Prepare()
			if err != nil {
				return nil, fmt.Errorf("failed to prepare document %d: %w", i, err)
			}
			preparedDocs[i] = prepared
		case *DeviceSignedDocument:
			prepared, err := d.Prepare()
			if err != nil {
				return nil, fmt.Errorf("failed to prepare document %d: %w", i, err)
			}
			preparedDocs[i] = prepared
		default:
			return nil, fmt.Errorf("unsupported document type at index %d: %T", i, doc)
		}
	}

	// Create the MDoc structure
	result := map[string]any{
		"version":   m.Version,
		"documents": preparedDocs,
		"status":    int(m.Status),
	}

	return cbor.Encode(result)
}

// GetDocument returns the document at the specified index.
func (m *MDoc) GetDocument(index int) interface{} {
	if index < 0 || index >= len(m.Documents) {
		return nil
	}
	return m.Documents[index]
}

// GetDocumentByType returns the first document with the specified type.
func (m *MDoc) GetDocumentByType(docType DocType) interface{} {
	for _, doc := range m.Documents {
		switch d := doc.(type) {
		case *IssuerSignedDocument:
			if d.DocType == docType {
				return d
			}
		case *DeviceSignedDocument:
			if d.DocType == docType {
				return d
			}
		}
	}
	return nil
}

// DocumentCount returns the number of documents.
func (m *MDoc) DocumentCount() int {
	return len(m.Documents)
}

// IsOK returns true if the status is OK.
func (m *MDoc) IsOK() bool {
	return m.Status == StatusOK
}

// GetIssuerSignedDocuments returns all IssuerSignedDocuments.
func (m *MDoc) GetIssuerSignedDocuments() []*IssuerSignedDocument {
	var result []*IssuerSignedDocument
	for _, doc := range m.Documents {
		if d, ok := doc.(*IssuerSignedDocument); ok {
			result = append(result, d)
		}
	}
	return result
}

// GetDeviceSignedDocuments returns all DeviceSignedDocuments.
func (m *MDoc) GetDeviceSignedDocuments() []*DeviceSignedDocument {
	var result []*DeviceSignedDocument
	for _, doc := range m.Documents {
		if d, ok := doc.(*DeviceSignedDocument); ok {
			result = append(result, d)
		}
	}
	return result
}

// HasDeviceSignedDocuments returns true if any document is device-signed.
func (m *MDoc) HasDeviceSignedDocuments() bool {
	for _, doc := range m.Documents {
		if _, ok := doc.(*DeviceSignedDocument); ok {
			return true
		}
	}
	return false
}
