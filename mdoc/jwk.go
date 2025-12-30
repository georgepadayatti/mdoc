package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	mcose "github.com/georgepadayatti/mdoc/cose"
)

// JWK represents a minimal JSON Web Key for EC/OKP keys.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// ParseJWK parses a JWK from common input formats.
func ParseJWK(key any) (*JWK, error) {
	switch v := key.(type) {
	case JWK:
		return &v, nil
	case *JWK:
		return v, nil
	case map[string]string:
		return &JWK{
			Kty: v["kty"],
			Crv: v["crv"],
			X:   v["x"],
			Y:   v["y"],
			D:   v["d"],
			Alg: v["alg"],
			Kid: v["kid"],
		}, nil
	case map[string]any:
		return &JWK{
			Kty: stringField(v, "kty"),
			Crv: stringField(v, "crv"),
			X:   stringField(v, "x"),
			Y:   stringField(v, "y"),
			D:   stringField(v, "d"),
			Alg: stringField(v, "alg"),
			Kid: stringField(v, "kid"),
		}, nil
	case []byte:
		trimmed := strings.TrimSpace(string(v))
		if len(trimmed) == 0 {
			return nil, fmt.Errorf("empty JWK")
		}
		if trimmed[0] != '{' {
			return nil, fmt.Errorf("unsupported JWK byte format")
		}
		var jwk JWK
		if err := json.Unmarshal(v, &jwk); err != nil {
			return nil, err
		}
		return &jwk, nil
	case string:
		return ParseJWK([]byte(v))
	default:
		return nil, fmt.Errorf("unsupported JWK type: %T", key)
	}
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func decodeB64URL(v string) ([]byte, error) {
	if v == "" {
		return nil, fmt.Errorf("missing value")
	}
	return base64.RawURLEncoding.DecodeString(v)
}

// ToECDSAPublicKey converts an EC JWK to an ECDSA public key.
func (j *JWK) ToECDSAPublicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" {
		return nil, fmt.Errorf("unsupported kty: %s", j.Kty)
	}
	curve, err := jwkCurve(j.Crv)
	if err != nil {
		return nil, err
	}
	xBytes, err := decodeB64URL(j.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := decodeB64URL(j.Y)
	if err != nil {
		return nil, err
	}
	x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ToECDSAPrivateKey converts an EC JWK to an ECDSA private key.
func (j *JWK) ToECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	if j.Kty != "EC" {
		return nil, fmt.Errorf("unsupported kty: %s", j.Kty)
	}
	curve, err := jwkCurve(j.Crv)
	if err != nil {
		return nil, err
	}
	dBytes, err := decodeB64URL(j.D)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(dBytes)

	var pub *ecdsa.PublicKey
	if j.X != "" && j.Y != "" {
		pub, err = j.ToECDSAPublicKey()
		if err != nil {
			return nil, err
		}
	} else {
		x, y := curve.ScalarBaseMult(dBytes)
		pub = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}

	return &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         d,
	}, nil
}

// ToEd25519PublicKey converts an OKP JWK to an Ed25519 public key.
func (j *JWK) ToEd25519PublicKey() (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %s", j.Crv)
	}
	xBytes, err := decodeB64URL(j.X)
	if err != nil {
		return nil, err
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size")
	}
	return ed25519.PublicKey(xBytes), nil
}

// ToEd25519PrivateKey converts an OKP JWK to an Ed25519 private key.
func (j *JWK) ToEd25519PrivateKey() (ed25519.PrivateKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %s", j.Crv)
	}
	dBytes, err := decodeB64URL(j.D)
	if err != nil {
		return nil, err
	}
	if len(dBytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid Ed25519 private key size")
	}
	return ed25519.NewKeyFromSeed(dBytes), nil
}

// ToCOSEKey converts a JWK to a COSE key map.
func (j *JWK) ToCOSEKey() (mcose.COSEKey, error) {
	switch j.Kty {
	case "EC":
		curveID, err := jwkCurveID(j.Crv)
		if err != nil {
			return nil, err
		}
		xBytes, err := decodeB64URL(j.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := decodeB64URL(j.Y)
		if err != nil {
			return nil, err
		}
		key := mcose.COSEKey{
			mcose.ParamKty: mcose.KeyTypeEC2,
			mcose.ParamCrv: curveID,
			mcose.ParamX:   xBytes,
			mcose.ParamY:   yBytes,
		}
		if j.D != "" {
			dBytes, err := decodeB64URL(j.D)
			if err != nil {
				return nil, err
			}
			key[mcose.ParamD] = dBytes
		}
		return key, nil
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve: %s", j.Crv)
		}
		xBytes, err := decodeB64URL(j.X)
		if err != nil {
			return nil, err
		}
		key := mcose.COSEKey{
			mcose.ParamKty: mcose.KeyTypeOKP,
			mcose.ParamCrv: mcose.CurveEd25519,
			mcose.ParamX:   xBytes,
		}
		if j.D != "" {
			dBytes, err := decodeB64URL(j.D)
			if err != nil {
				return nil, err
			}
			key[mcose.ParamD] = dBytes
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported kty: %s", j.Kty)
	}
}

func jwkCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}
}

func jwkCurveID(crv string) (int, error) {
	switch crv {
	case "P-256":
		return mcose.CurveP256, nil
	case "P-384":
		return mcose.CurveP384, nil
	case "P-521":
		return mcose.CurveP521, nil
	default:
		return 0, fmt.Errorf("unsupported curve: %s", crv)
	}
}

// COSEKeyToJWKMap converts a COSE key to a JWK-like map.
func COSEKeyToJWKMap(key any) (map[string]any, error) {
	coseKey, err := ParseCOSEKey(key)
	if err != nil {
		return nil, err
	}
	encode := func(b []byte) string {
		return base64.RawURLEncoding.EncodeToString(b)
	}

	switch coseKey.KeyType() {
	case mcose.KeyTypeEC2:
		crv := ""
		switch coseKey.Curve() {
		case mcose.CurveP256:
			crv = "P-256"
		case mcose.CurveP384:
			crv = "P-384"
		case mcose.CurveP521:
			crv = "P-521"
		default:
			return nil, fmt.Errorf("unsupported curve: %d", coseKey.Curve())
		}
		jwk := map[string]any{
			"kty": "EC",
			"crv": crv,
			"x":   encode(coseKey.X()),
			"y":   encode(coseKey.Y()),
		}
		if coseKey.D() != nil {
			jwk["d"] = encode(coseKey.D())
		}
		return jwk, nil
	case mcose.KeyTypeOKP:
		if coseKey.Curve() != mcose.CurveEd25519 {
			return nil, fmt.Errorf("unsupported OKP curve: %d", coseKey.Curve())
		}
		jwk := map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   encode(coseKey.X()),
		}
		if coseKey.D() != nil {
			jwk["d"] = encode(coseKey.D())
		}
		return jwk, nil
	default:
		return nil, fmt.Errorf("unsupported COSE key type: %d", coseKey.KeyType())
	}
}
