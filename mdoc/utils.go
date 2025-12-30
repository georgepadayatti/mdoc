package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strconv"

	"github.com/georgepadayatti/mdoc/cbor"
	mcose "github.com/georgepadayatti/mdoc/cose"
	"golang.org/x/crypto/hkdf"
)

// GetRandomBytes returns cryptographically secure random bytes.
func GetRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// MustRandomBytes returns cryptographically secure random bytes and panics on error.
func MustRandomBytes(n int) []byte {
	b, err := GetRandomBytes(n)
	if err != nil {
		panic(err)
	}
	return b
}

// CalculateDigest calculates the digest of data using the specified algorithm.
func CalculateDigest(alg DigestAlgorithm, data []byte) ([]byte, error) {
	var h hash.Hash
	switch alg {
	case DigestAlgorithmSHA256:
		h = sha256.New()
	case DigestAlgorithmSHA384:
		h = sha512.New384()
	case DigestAlgorithmSHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// HMACSHA256 computes HMAC-SHA256 of data with the given key.
func HMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ConstantTimeCompare compares two byte slices in constant time.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// CalculateEphemeralMacKey derives the ephemeral MAC key using ECDH and HKDF.
// This is used for device MAC authentication per ISO 18013-5.
//
// Parameters:
//   - devicePrivateKey: Device's static private key (SDeviceKey.Priv) or reader's ephemeral private key (EReaderKey.Priv)
//   - otherPublicKey: Other party's public key (EReaderKey.Pub or SDeviceKey.Pub)
//   - sessionTranscript: CBOR-encoded session transcript
//
// Returns the 32-byte ephemeral MAC key.
func CalculateEphemeralMacKey(devicePrivateKey *ecdsa.PrivateKey, otherPublicKey *ecdsa.PublicKey, sessionTranscript []byte) ([]byte, error) {
	// Perform ECDH to get shared secret
	sharedX, _ := devicePrivateKey.Curve.ScalarMult(otherPublicKey.X, otherPublicKey.Y, devicePrivateKey.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Pad to curve size if needed
	byteSize := (devicePrivateKey.Curve.Params().BitSize + 7) / 8
	if len(sharedSecret) < byteSize {
		padded := make([]byte, byteSize)
		copy(padded[byteSize-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	// Calculate salt as SHA-256 of session transcript
	salt := sha256.Sum256(sessionTranscript)

	// HKDF with info "EMacKey"
	info := []byte("EMacKey")
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt[:], info)

	// Derive 32 bytes for the MAC key
	macKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, macKey); err != nil {
		return nil, fmt.Errorf("failed to derive MAC key: %w", err)
	}

	return macKey, nil
}

// CalculateDeviceAuthenticationBytes constructs the data to be signed/MACed for device authentication.
// Format: ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
func CalculateDeviceAuthenticationBytes(sessionTranscript []byte, docType DocType, deviceNameSpaces DeviceNameSpaces) ([]byte, error) {
	// Decode session transcript if needed
	var decodedTranscript any
	if err := cbor.Decode(sessionTranscript, &decodedTranscript); err != nil {
		return nil, fmt.Errorf("failed to decode session transcript: %w", err)
	}
	switch v := decodedTranscript.(type) {
	case cbor.DataItem:
		data, err := v.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to decode session transcript DataItem: %w", err)
		}
		decodedTranscript = data
	case *cbor.DataItem:
		data, err := v.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to decode session transcript DataItem: %w", err)
		}
		decodedTranscript = data
	}

	// Encode device namespaces
	deviceNameSpacesBytes, err := cbor.Encode(deviceNameSpaces)
	if err != nil {
		return nil, fmt.Errorf("failed to encode device namespaces: %w", err)
	}

	// Create the DeviceAuthentication structure
	// Tag 24 wrapping for deviceNameSpaces (embedded CBOR)
	deviceAuth := []any{
		"DeviceAuthentication",
		decodedTranscript,
		string(docType),
		cbor.NewDataItemFromBytes(deviceNameSpacesBytes),
	}

	// Encode the whole structure
	encoded, err := cbor.Encode(deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to encode device authentication: %w", err)
	}

	return encoded, nil
}

// CreateSessionTranscriptOID4VP creates a session transcript for OID4VP (OpenID for Verifiable Presentations).
// Format: [null, null, [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce]]
func CreateSessionTranscriptOID4VP(mdocGeneratedNonce, clientID, responseURI, verifierGeneratedNonce string) ([]byte, error) {
	handover := []any{mdocGeneratedNonce, clientID, responseURI, verifierGeneratedNonce}
	transcript := cbor.NewDataItem([]any{nil, nil, handover})
	return cbor.Encode(transcript)
}

// CreateSessionTranscriptWebAPI creates a session transcript for the Web API.
// Format: [DeviceEngagementBytes, EReaderKeyBytes, ReaderEngagementBytes]
func CreateSessionTranscriptWebAPI(deviceEngagementBytes, eReaderKeyBytes, readerEngagementBytes []byte) ([]byte, error) {
	// Wrap as DataItems (tag 24)
	transcript := cbor.NewDataItem([]any{
		cbor.NewDataItemFromBytes(deviceEngagementBytes),
		cbor.NewDataItemFromBytes(eReaderKeyBytes),
		readerEngagementBytes,
	})
	return cbor.Encode(transcript)
}

// ParseCOSEKeyToECDSA parses a COSE key (as map or bytes) to an ECDSA public key.
func ParseCOSEKeyToECDSA(key any) (*ecdsa.PublicKey, error) {
	coseKey, err := ParseCOSEKey(key)
	if err != nil {
		return nil, err
	}
	return coseKey.ToECDSAPublicKey()
}

// ParseCOSEKeyToPublicKey parses a COSE key to a crypto public key (ECDSA or Ed25519).
func ParseCOSEKeyToPublicKey(key any) (any, error) {
	coseKey, err := ParseCOSEKey(key)
	if err != nil {
		return nil, err
	}
	switch coseKey.KeyType() {
	case mcose.KeyTypeEC2:
		return coseKey.ToECDSAPublicKey()
	case mcose.KeyTypeOKP:
		return coseKey.ToEd25519PublicKey()
	default:
		return nil, fmt.Errorf("unsupported COSE key type: %d", coseKey.KeyType())
	}
}

// ParseCOSEKeyToPrivateKey parses a COSE key to a crypto private key (ECDSA or Ed25519).
func ParseCOSEKeyToPrivateKey(key any) (any, error) {
	coseKey, err := ParseCOSEKey(key)
	if err != nil {
		return nil, err
	}
	switch coseKey.KeyType() {
	case mcose.KeyTypeEC2:
		return coseKey.ToECDSAPrivateKey()
	case mcose.KeyTypeOKP:
		return coseKey.ToEd25519PrivateKey()
	default:
		return nil, fmt.Errorf("unsupported COSE key type: %d", coseKey.KeyType())
	}
}

// ParseECDSAPublicKey normalizes an ECDSA public key from supported formats.
func ParseECDSAPublicKey(key any) (*ecdsa.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return k, nil
	case map[string]string, string, JWK, *JWK:
		jwk, err := ParseJWK(k)
		if err == nil && jwk.Kty == "EC" {
			return jwk.ToECDSAPublicKey()
		}
	case mcose.COSEKey, map[any]any:
		return ParseCOSEKeyToECDSA(k)
	case map[string]any:
		if jwk, err := ParseJWK(k); err == nil && jwk.Kty == "EC" {
			return jwk.ToECDSAPublicKey()
		}
		return ParseCOSEKeyToECDSA(k)
	}

	if data, ok := key.([]byte); ok {
		if jwk, err := ParseJWK(data); err == nil && jwk.Kty == "EC" {
			return jwk.ToECDSAPublicKey()
		}
		if coseKey, err := mcose.ParseCOSEKey(data); err == nil {
			return coseKey.ToECDSAPublicKey()
		}
	}

	return nil, fmt.Errorf("unsupported ECDSA public key type: %T", key)
}

// ParseECDSAPrivateKey normalizes an ECDSA private key from supported formats.
func ParseECDSAPrivateKey(key any) (*ecdsa.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case map[string]string, string, JWK, *JWK:
		jwk, err := ParseJWK(k)
		if err == nil && jwk.Kty == "EC" {
			return jwk.ToECDSAPrivateKey()
		}
	case mcose.COSEKey, map[any]any:
		priv, err := ParseCOSEKeyToPrivateKey(k)
		if err != nil {
			return nil, err
		}
		if key, ok := priv.(*ecdsa.PrivateKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("COSE key is not ECDSA")
	case map[string]any:
		if jwk, err := ParseJWK(k); err == nil && jwk.Kty == "EC" {
			return jwk.ToECDSAPrivateKey()
		}
		priv, err := ParseCOSEKeyToPrivateKey(k)
		if err != nil {
			return nil, err
		}
		if key, ok := priv.(*ecdsa.PrivateKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("COSE key is not ECDSA")
	}

	if data, ok := key.([]byte); ok {
		if jwk, err := ParseJWK(data); err == nil && jwk.Kty == "EC" {
			return jwk.ToECDSAPrivateKey()
		}
		if coseKey, err := mcose.ParseCOSEKey(data); err == nil {
			return coseKey.ToECDSAPrivateKey()
		}
	}

	return nil, fmt.Errorf("unsupported ECDSA private key type: %T", key)
}

// ParsePrivateKey normalizes an ECDSA or Ed25519 private key from supported formats.
func ParsePrivateKey(key any) (any, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	}

	if jwk, err := ParseJWK(key); err == nil {
		switch jwk.Kty {
		case "EC":
			return jwk.ToECDSAPrivateKey()
		case "OKP":
			return jwk.ToEd25519PrivateKey()
		}
	}

	if priv, err := ParseCOSEKeyToPrivateKey(key); err == nil {
		return priv, nil
	}

	return nil, fmt.Errorf("unsupported private key type: %T", key)
}

// ParseCOSEKey normalizes a COSE key from supported input formats.
func ParseCOSEKey(key any) (mcose.COSEKey, error) {
	switch k := key.(type) {
	case mcose.COSEKey:
		return k, nil
	case map[any]any:
		return mcose.COSEKey(k), nil
	case map[string]any:
		converted := make(map[any]any, len(k))
		for ks, v := range k {
			if intKey, err := strconv.ParseInt(ks, 10, 64); err == nil {
				converted[int64(intKey)] = v
			}
		}
		if len(converted) == 0 {
			return nil, fmt.Errorf("invalid COSE key map")
		}
		return mcose.COSEKey(converted), nil
	case []byte:
		return mcose.ParseCOSEKey(k)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// ECDSASharedSecret performs ECDH and returns the shared secret.
func ECDSASharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	if priv.Curve != pub.Curve {
		return nil, fmt.Errorf("curve mismatch")
	}

	x, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	if x == nil {
		return nil, fmt.Errorf("ECDH computation failed")
	}

	// Pad to curve size
	byteSize := (priv.Curve.Params().BitSize + 7) / 8
	sharedSecret := x.Bytes()
	if len(sharedSecret) < byteSize {
		padded := make([]byte, byteSize)
		copy(padded[byteSize-len(sharedSecret):], sharedSecret)
		return padded, nil
	}
	return sharedSecret, nil
}

// GetHashFunc returns the hash function for a signature algorithm.
func GetHashFunc(alg SignatureAlgorithm) crypto.Hash {
	switch alg {
	case AlgorithmES256:
		return crypto.SHA256
	case AlgorithmES384:
		return crypto.SHA384
	case AlgorithmES512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// GetCurveForAlgorithm returns the elliptic curve for a signature algorithm.
func GetCurveForAlgorithm(alg SignatureAlgorithm) elliptic.Curve {
	switch alg {
	case AlgorithmES256:
		return elliptic.P256()
	case AlgorithmES384:
		return elliptic.P384()
	case AlgorithmES512:
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}

// GenerateECDSAKeyPair generates a new ECDSA key pair for the given algorithm.
func GenerateECDSAKeyPair(alg SignatureAlgorithm) (*ecdsa.PrivateKey, error) {
	curve := GetCurveForAlgorithm(alg)
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// ECDSAPublicKeyFromBytes parses an uncompressed EC public key.
func ECDSAPublicKeyFromBytes(curve elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty public key data")
	}

	// Handle uncompressed format (0x04 prefix)
	if data[0] == 0x04 {
		byteLen := (curve.Params().BitSize + 7) / 8
		if len(data) != 1+2*byteLen {
			return nil, fmt.Errorf("invalid public key length")
		}
		x := new(big.Int).SetBytes(data[1 : 1+byteLen])
		y := new(big.Int).SetBytes(data[1+byteLen:])
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}

	return nil, fmt.Errorf("unsupported public key format")
}
