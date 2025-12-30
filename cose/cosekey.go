// Package cose provides COSE key utilities for mDocs.
package cose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// COSE Key Types
const (
	KeyTypeOKP = 1 // Octet Key Pair (EdDSA)
	KeyTypeEC2 = 2 // Elliptic Curve (ECDSA)
)

// COSE Key Parameters
const (
	ParamKty = 1  // Key type
	ParamCrv = -1 // Curve
	ParamX   = -2 // X coordinate
	ParamY   = -3 // Y coordinate
	ParamD   = -4 // Private key
)

// COSE Curves
const (
	CurveP256 = 1 // P-256 (secp256r1)
	CurveP384 = 2 // P-384 (secp384r1)
	CurveP521 = 3 // P-521 (secp521r1)
	CurveX25519 = 4 // X25519
	CurveX448   = 5 // X448
	CurveEd25519 = 6 // Ed25519
	CurveEd448   = 7 // Ed448
)

// COSEKey represents a COSE key as a map.
type COSEKey map[any]any

func (k COSEKey) getParam(param int) (any, bool) {
	if v, ok := k[param]; ok {
		return v, true
	}
	if v, ok := k[int64(param)]; ok {
		return v, true
	}
	if v, ok := k[uint64(param)]; ok {
		return v, true
	}
	return nil, false
}

// ParseCOSEKey parses a CBOR-encoded COSE key.
func ParseCOSEKey(data []byte) (COSEKey, error) {
	var key COSEKey
	if err := cbor.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("failed to parse COSE key: %w", err)
	}
	return key, nil
}

// KeyType returns the key type (kty).
func (k COSEKey) KeyType() int {
	if v, ok := k.getParam(ParamKty); ok {
		if kty, ok := v.(int64); ok {
			return int(kty)
		}
		if kty, ok := v.(uint64); ok {
			return int(kty)
		}
		if kty, ok := v.(int); ok {
			return kty
		}
	}
	if kty, ok := k[ParamKty].(int64); ok {
		return int(kty)
	}
	if kty, ok := k[ParamKty].(uint64); ok {
		return int(kty)
	}
	return 0
}

// Curve returns the curve identifier.
func (k COSEKey) Curve() int {
	if v, ok := k.getParam(ParamCrv); ok {
		if crv, ok := v.(int64); ok {
			return int(crv)
		}
		if crv, ok := v.(uint64); ok {
			return int(crv)
		}
		if crv, ok := v.(int); ok {
			return crv
		}
	}
	if crv, ok := k[ParamCrv].(int64); ok {
		return int(crv)
	}
	if crv, ok := k[ParamCrv].(uint64); ok {
		return int(crv)
	}
	return 0
}

// X returns the X coordinate.
func (k COSEKey) X() []byte {
	if v, ok := k.getParam(ParamX); ok {
		if x, ok := v.([]byte); ok {
			return x
		}
	}
	if x, ok := k[ParamX].([]byte); ok {
		return x
	}
	return nil
}

// Y returns the Y coordinate.
func (k COSEKey) Y() []byte {
	if v, ok := k.getParam(ParamY); ok {
		if y, ok := v.([]byte); ok {
			return y
		}
	}
	if y, ok := k[ParamY].([]byte); ok {
		return y
	}
	return nil
}

// D returns the private key (D value).
func (k COSEKey) D() []byte {
	if v, ok := k.getParam(ParamD); ok {
		if d, ok := v.([]byte); ok {
			return d
		}
	}
	if d, ok := k[ParamD].([]byte); ok {
		return d
	}
	return nil
}

// HasPrivateKey returns true if the key has a private key component.
func (k COSEKey) HasPrivateKey() bool {
	return k.D() != nil
}

// ToRaw converts a COSE key to raw key bytes.
// For public keys: 0x04 || X || Y (uncompressed point format)
// For private keys: just the D value
func (k COSEKey) ToRaw() ([]byte, error) {
	kty := k.KeyType()
	switch kty {
	case KeyTypeEC2:
		if k.HasPrivateKey() {
			return k.D(), nil
		}

		x := k.X()
		y := k.Y()
		if x == nil || y == nil {
			return nil, fmt.Errorf("missing X or Y coordinate")
		}

		// Uncompressed point format: 0x04 || X || Y
		raw := make([]byte, 1+len(x)+len(y))
		raw[0] = 0x04
		copy(raw[1:], x)
		copy(raw[1+len(x):], y)
		return raw, nil
	case KeyTypeOKP:
		if k.HasPrivateKey() {
			return k.D(), nil
		}
		x := k.X()
		if x == nil {
			return nil, fmt.Errorf("missing X coordinate")
		}
		return x, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %d", kty)
	}
}

// ToECDSAPublicKey converts a COSE key to an ECDSA public key.
func (k COSEKey) ToECDSAPublicKey() (*ecdsa.PublicKey, error) {
	kty := k.KeyType()
	if kty != KeyTypeEC2 {
		return nil, fmt.Errorf("unsupported key type: %d", kty)
	}

	curve, err := k.getCurve()
	if err != nil {
		return nil, err
	}

	x := k.X()
	y := k.Y()
	if x == nil || y == nil {
		return nil, fmt.Errorf("missing X or Y coordinate")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

// ToECDSAPrivateKey converts a COSE key to an ECDSA private key.
func (k COSEKey) ToECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	pub, err := k.ToECDSAPublicKey()
	if err != nil {
		return nil, err
	}

	d := k.D()
	if d == nil {
		return nil, fmt.Errorf("missing private key component D")
	}

	return &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(d),
	}, nil
}

// ToEd25519PublicKey converts a COSE key to an Ed25519 public key.
func (k COSEKey) ToEd25519PublicKey() (ed25519.PublicKey, error) {
	if k.KeyType() != KeyTypeOKP || k.Curve() != CurveEd25519 {
		return nil, fmt.Errorf("unsupported OKP curve: %d", k.Curve())
	}
	x := k.X()
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size")
	}
	return ed25519.PublicKey(x), nil
}

// ToEd25519PrivateKey converts a COSE key to an Ed25519 private key.
func (k COSEKey) ToEd25519PrivateKey() (ed25519.PrivateKey, error) {
	if k.KeyType() != KeyTypeOKP || k.Curve() != CurveEd25519 {
		return nil, fmt.Errorf("unsupported OKP curve: %d", k.Curve())
	}
	d := k.D()
	if len(d) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid Ed25519 private key size")
	}
	return ed25519.NewKeyFromSeed(d), nil
}

func (k COSEKey) getCurve() (elliptic.Curve, error) {
	switch k.Curve() {
	case CurveP256:
		return elliptic.P256(), nil
	case CurveP384:
		return elliptic.P384(), nil
	case CurveP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %d", k.Curve())
	}
}

// Encode returns the CBOR-encoded representation of the key.
func (k COSEKey) Encode() ([]byte, error) {
	return cbor.Marshal(k)
}

// FromECDSAPublicKey creates a COSE key from an ECDSA public key.
func FromECDSAPublicKey(pub *ecdsa.PublicKey) (COSEKey, error) {
	crv, err := getCurveID(pub.Curve)
	if err != nil {
		return nil, err
	}

	return COSEKey{
		ParamKty: KeyTypeEC2,
		ParamCrv: crv,
		ParamX:   pub.X.Bytes(),
		ParamY:   pub.Y.Bytes(),
	}, nil
}

// FromECDSAPrivateKey creates a COSE key from an ECDSA private key.
func FromECDSAPrivateKey(priv *ecdsa.PrivateKey) (COSEKey, error) {
	key, err := FromECDSAPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	key[ParamD] = priv.D.Bytes()
	return key, nil
}

func getCurveID(curve elliptic.Curve) (int, error) {
	switch curve {
	case elliptic.P256():
		return CurveP256, nil
	case elliptic.P384():
		return CurveP384, nil
	case elliptic.P521():
		return CurveP521, nil
	default:
		return 0, fmt.Errorf("unsupported curve: %v", curve)
	}
}

// FromEd25519PublicKey creates a COSE key from an Ed25519 public key.
func FromEd25519PublicKey(pub ed25519.PublicKey) (COSEKey, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size")
	}
	return COSEKey{
		ParamKty: KeyTypeOKP,
		ParamCrv: CurveEd25519,
		ParamX:   []byte(pub),
	}, nil
}

// FromEd25519PrivateKey creates a COSE key from an Ed25519 private key.
func FromEd25519PrivateKey(priv ed25519.PrivateKey) (COSEKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size")
	}
	pub := priv.Public().(ed25519.PublicKey)
	key, err := FromEd25519PublicKey(pub)
	if err != nil {
		return nil, err
	}
	key[ParamD] = []byte(priv.Seed())
	return key, nil
}

// ParsePEMCertificate parses a PEM-encoded X.509 certificate.
func ParsePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParsePEMCertificates parses multiple PEM-encoded X.509 certificates.
func ParsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
		pemData = rest
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return certs, nil
}

// ParsePEMPrivateKey parses a PEM-encoded ECDSA private key.
func ParsePEMPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an ECDSA private key")
		}
		return ecKey, nil
	}
	return key, nil
}
