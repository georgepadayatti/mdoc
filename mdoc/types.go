// Package mdoc provides functionality for ISO 18013-5/7 mobile Driver License (mDL) documents.
package mdoc

import (
	"time"

	"github.com/veraison/go-cose"
)

// DocType is the document type identifier.
type DocType string

// Common document types
const (
	DocTypeMDL DocType = "org.iso.18013.5.1.mDL"
)

// Common namespaces
const (
	NamespaceMDL = "org.iso.18013.5.1"
)

// DigestAlgorithm is the algorithm used for calculating digests.
type DigestAlgorithm string

const (
	DigestAlgorithmSHA256 DigestAlgorithm = "SHA-256"
	DigestAlgorithmSHA384 DigestAlgorithm = "SHA-384"
	DigestAlgorithmSHA512 DigestAlgorithm = "SHA-512"
)

// SignatureAlgorithm is the algorithm used for signing.
type SignatureAlgorithm cose.Algorithm

var (
	AlgorithmES256 = SignatureAlgorithm(cose.AlgorithmES256)
	AlgorithmES384 = SignatureAlgorithm(cose.AlgorithmES384)
	AlgorithmES512 = SignatureAlgorithm(cose.AlgorithmES512)
	AlgorithmEdDSA = SignatureAlgorithm(cose.AlgorithmEdDSA)
)

// MacAlgorithm is the algorithm used for MAC operations.
type MacAlgorithm string

const (
	MacAlgorithmHS256 MacAlgorithm = "HS256"
)

// ValidityInfo contains the validity period of a document.
type ValidityInfo struct {
	Signed         time.Time  `cbor:"signed"`
	ValidFrom      time.Time  `cbor:"validFrom"`
	ValidUntil     time.Time  `cbor:"validUntil"`
	ExpectedUpdate *time.Time `cbor:"expectedUpdate,omitempty"`
}

// DeviceKeyInfo contains information about the device's public key.
type DeviceKeyInfo struct {
	DeviceKey map[any]any `cbor:"deviceKey"` // COSE Key as map
}

// MSO (Mobile Security Object) contains the issuer's signed data.
type MSO struct {
	Version          string                       `cbor:"version"`
	DigestAlgorithm  DigestAlgorithm              `cbor:"digestAlgorithm"`
	DocType          DocType                      `cbor:"docType"`
	ValueDigests     map[string]map[uint64][]byte `cbor:"valueDigests"`
	ValidityDigests  map[string]map[uint64][]byte `cbor:"validityDigests,omitempty"`
	DeviceKeyInfo    *DeviceKeyInfo               `cbor:"deviceKeyInfo,omitempty"`
	ValidityInfo     ValidityInfo                 `cbor:"validityInfo"`
}

// IssuerNameSpaces maps namespace identifiers to lists of IssuerSignedItems.
type IssuerNameSpaces map[string][]*IssuerSignedItem

// DeviceNameSpaces maps namespace identifiers to attribute maps.
type DeviceNameSpaces map[string]map[string]any

// IssuerSigned contains the issuer-signed portion of a document.
type IssuerSigned struct {
	NameSpaces IssuerNameSpaces
	IssuerAuth *IssuerAuth
}

// Mac0Message represents a COSE_Mac0 message.
type Mac0Message struct {
	Headers   cose.Headers
	Payload   []byte
	Tag       []byte
}

// DeviceAuth contains device authentication information.
// It can be either a MAC (deviceMac) or a signature (deviceSignature).
type DeviceAuth struct {
	DeviceMAC       *Mac0Message       // COSE_Mac0 for MAC authentication
	DeviceSignature *cose.Sign1Message // COSE_Sign1 for signature authentication
}

// IsMAC returns true if the device auth uses MAC.
func (d *DeviceAuth) IsMAC() bool {
	return d.DeviceMAC != nil
}

// IsSignature returns true if the device auth uses a signature.
func (d *DeviceAuth) IsSignature() bool {
	return d.DeviceSignature != nil
}

// DeviceSigned contains the device-signed portion of a document.
type DeviceSigned struct {
	NameSpaces DeviceNameSpaces
	DeviceAuth *DeviceAuth
}

// VerificationCategory categorizes verification checks.
type VerificationCategory string

const (
	CategoryDocumentFormat VerificationCategory = "DOCUMENT_FORMAT"
	CategoryIssuerAuth     VerificationCategory = "ISSUER_AUTH"
	CategoryDeviceAuth     VerificationCategory = "DEVICE_AUTH"
	CategoryDataIntegrity  VerificationCategory = "DATA_INTEGRITY"
)

// VerificationStatus is the result of a verification check.
type VerificationStatus string

const (
	StatusPassed  VerificationStatus = "PASSED"
	StatusFailed  VerificationStatus = "FAILED"
	StatusWarning VerificationStatus = "WARNING"
)

// VerificationCheck identifies a specific verification check.
type VerificationCheck string

// Verification checks
const (
	CheckDeviceResponseVersion         VerificationCheck = "DEVICE_RESPONSE_VERSION"
	CheckDeviceResponseVersionSupported VerificationCheck = "DEVICE_RESPONSE_VERSION_SUPPORTED"
	CheckDocumentPresent               VerificationCheck = "DOCUMENT_PRESENT"
	CheckIssuerCertValid               VerificationCheck = "ISSUER_CERTIFICATE_VALID"
	CheckIssuerSignatureValid          VerificationCheck = "ISSUER_SIGNATURE_VALID"
	CheckMSOSignedDateValid            VerificationCheck = "MSO_SIGNED_DATE_VALID"
	CheckMSOValidAtVerification        VerificationCheck = "MSO_VALID_AT_VERIFICATION"
	CheckCountryNamePresent            VerificationCheck = "COUNTRY_NAME_PRESENT"
	CheckDeviceSignaturePresent        VerificationCheck = "DEVICE_SIGNATURE_PRESENT"
	CheckSessionTranscriptProvided     VerificationCheck = "SESSION_TRANSCRIPT_PROVIDED"
	CheckDeviceKeyAvailable            VerificationCheck = "DEVICE_KEY_AVAILABLE"
	CheckDeviceSignatureValid          VerificationCheck = "DEVICE_SIGNATURE_VALID"
	CheckDeviceMACPresent              VerificationCheck = "DEVICE_MAC_PRESENT"
	CheckDeviceMACAlgorithm            VerificationCheck = "DEVICE_MAC_ALGORITHM"
	CheckEphemeralKeyProvided          VerificationCheck = "EPHEMERAL_KEY_PROVIDED"
	CheckDeviceMACValid                VerificationCheck = "DEVICE_MAC_VALID"
	CheckDigestAlgorithmSupported      VerificationCheck = "DIGEST_ALGORITHM_SUPPORTED"
	CheckNamespaceDigestsPresent       VerificationCheck = "NAMESPACE_DIGESTS_PRESENT"
	CheckAttributeDigestValid          VerificationCheck = "ATTRIBUTE_DIGEST_VALID"
	CheckIssuingCountryMatchesCert     VerificationCheck = "ISSUING_COUNTRY_MATCHES_CERT"
	CheckIssuingJurisdictionMatchesCert VerificationCheck = "ISSUING_JURISDICTION_MATCHES_CERT"
)

// VerificationAssessment is the result of a single verification check.
type VerificationAssessment struct {
	Status   VerificationStatus
	Check    VerificationCheck
	Category VerificationCategory
	Reason   string
}

// VerifyCallback is called for each verification check.
type VerifyCallback func(assessment VerificationAssessment) error

// VerifyOptions contains options for verification.
type VerifyOptions struct {
	EphemeralReaderKey       []byte // For MAC verification
	EncodedSessionTranscript []byte // Session transcript for device auth
	OnCheck                  VerifyCallback
	DisableCertificateChainValidation bool
}

// DiagnosticAttribute contains diagnostic info for an attribute.
type DiagnosticAttribute struct {
	Namespace        string
	Identifier       string
	Value            any
	IsValid          bool
	MatchCertificate *bool
}

// DiagnosticIssuerCert contains diagnostic info for the issuer certificate.
type DiagnosticIssuerCert struct {
	SubjectName  string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber string
	Thumbprint   string
	PEM          string
}

// DiagnosticSignature contains diagnostic info for a signature.
type DiagnosticSignature struct {
	Algorithm string
	IsValid   bool
	Reasons   []string
}

// DiagnosticInfo contains comprehensive diagnostic information.
type DiagnosticInfo struct {
	General struct {
		Type      DocType
		Version   string
		Status    MDocStatus
		Documents int
	}
	ValidityInfo      *ValidityInfo
	Attributes        []DiagnosticAttribute
	DeviceAttributes  []DiagnosticAttribute
	IssuerCertificate *DiagnosticIssuerCert
	IssuerSignature   DiagnosticSignature
	DeviceKey         map[string]any
	DeviceSignature   DiagnosticSignature
	DataIntegrity     struct {
		DisclosedAttributes int
		IsValid             bool
		Reasons             []string
	}
}

// SignParams contains parameters for signing a document.
type SignParams struct {
	IssuerPrivateKey  any    // *ecdsa.PrivateKey or ed25519.PrivateKey
	IssuerCertificate []byte // PEM-encoded certificate(s)
	Algorithm         SignatureAlgorithm
	KeyID             []byte // Optional key ID
}
