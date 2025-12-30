package mdoc

import (
	"errors"
	"fmt"
)

// Common errors
var (
	ErrInvalidDocument       = errors.New("invalid document")
	ErrInvalidSignature      = errors.New("invalid signature")
	ErrInvalidCertificate    = errors.New("invalid certificate")
	ErrInvalidMAC            = errors.New("invalid MAC")
	ErrMissingDeviceKey      = errors.New("missing device key")
	ErrMissingSessionTranscript = errors.New("missing session transcript")
	ErrUnsupportedAlgorithm  = errors.New("unsupported algorithm")
	ErrUnsupportedCurve      = errors.New("unsupported curve")
	ErrDigestMismatch        = errors.New("digest mismatch")
	ErrCertificateExpired    = errors.New("certificate expired")
	ErrCertificateNotYetValid = errors.New("certificate not yet valid")
	ErrDocumentExpired       = errors.New("document expired")
	ErrDocumentNotYetValid   = errors.New("document not yet valid")
)

// MDLError is a custom error type for MDL-specific errors.
type MDLError struct {
	Code    string
	Message string
	Cause   error
}

func (e *MDLError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *MDLError) Unwrap() error {
	return e.Cause
}

// NewMDLError creates a new MDLError.
func NewMDLError(code, message string) *MDLError {
	return &MDLError{Code: code, Message: message}
}

// NewMDLErrorf creates a new MDLError with a formatted message.
func NewMDLErrorf(code, format string, args ...any) *MDLError {
	return &MDLError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WrapMDLError wraps an error with an MDLError.
func WrapMDLError(code, message string, cause error) *MDLError {
	return &MDLError{Code: code, Message: message, Cause: cause}
}

// ParseError is returned when CBOR parsing fails.
type ParseError struct {
	Message string
	Cause   error
}

func (e *ParseError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("parse error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("parse error: %s", e.Message)
}

func (e *ParseError) Unwrap() error {
	return e.Cause
}

// NewParseError creates a new ParseError.
func NewParseError(message string) *ParseError {
	return &ParseError{Message: message}
}

// WrapParseError wraps an error with a ParseError.
func WrapParseError(message string, cause error) *ParseError {
	return &ParseError{Message: message, Cause: cause}
}

// VerificationError is returned when verification fails.
type VerificationError struct {
	Assessment VerificationAssessment
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("verification failed: %s - %s", e.Assessment.Check, e.Assessment.Reason)
}

// NewVerificationError creates a new VerificationError.
func NewVerificationError(assessment VerificationAssessment) *VerificationError {
	return &VerificationError{Assessment: assessment}
}

// Error codes
const (
	ErrCodeParseFailed       = "PARSE_FAILED"
	ErrCodeInvalidVersion    = "INVALID_VERSION"
	ErrCodeInvalidDocType    = "INVALID_DOCTYPE"
	ErrCodeSigningFailed     = "SIGNING_FAILED"
	ErrCodeVerificationFailed = "VERIFICATION_FAILED"
	ErrCodeEncodingFailed    = "ENCODING_FAILED"
	ErrCodeDecodingFailed    = "DECODING_FAILED"
)
