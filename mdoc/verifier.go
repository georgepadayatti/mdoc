package mdoc

import (
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/veraison/go-cose"
)

// Verifier verifies mDoc device responses.
type Verifier struct {
	trustedRoots *x509.CertPool
}

// NewVerifier creates a new Verifier with the given trusted root certificates.
func NewVerifier(trustedCerts [][]byte) (*Verifier, error) {
	pool := x509.NewCertPool()

	for i, certPEM := range trustedCerts {
		cert, err := x509.ParseCertificate(certPEM)
		if err != nil {
			// Try PEM format
			certs, err := parsePEMCerts(certPEM)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate %d: %w", i, err)
			}
			for _, c := range certs {
				pool.AddCert(c)
			}
		} else {
			pool.AddCert(cert)
		}
	}

	return &Verifier{trustedRoots: pool}, nil
}

// parsePEMCerts parses PEM-encoded certificates.
func parsePEMCerts(pemData []byte) ([]*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(pemData)
	if err == nil && len(certs) > 0 {
		return certs, nil
	}

	var parsed []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, cert)
	}
	if len(parsed) == 0 {
		return nil, fmt.Errorf("failed to parse PEM certificates")
	}
	return parsed, nil
}

// Verify verifies a device response and returns the parsed MDoc.
func (v *Verifier) Verify(data []byte, opts VerifyOptions) (*MDoc, error) {
	// Parse the response
	mdoc, err := Parse(data)
	if err != nil {
		return nil, err
	}

	if mdoc.Version == "" {
		if err := v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceResponseVersion,
			Category: CategoryDocumentFormat,
			Reason:   "DeviceResponse missing version",
		}); err != nil {
			return nil, err
		}
	} else if err := v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckDeviceResponseVersion,
		Category: CategoryDocumentFormat,
	}); err != nil {
		return nil, err
	}

	if !isSupportedVersion(mdoc.Version) {
		if err := v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceResponseVersionSupported,
			Category: CategoryDocumentFormat,
			Reason:   "DeviceResponse version must be 1.0 or greater",
		}); err != nil {
			return nil, err
		}
	} else if err := v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckDeviceResponseVersionSupported,
		Category: CategoryDocumentFormat,
	}); err != nil {
		return nil, err
	}

	if len(mdoc.Documents) == 0 {
		if err := v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDocumentPresent,
			Category: CategoryDocumentFormat,
			Reason:   "DeviceResponse must include at least one document",
		}); err != nil {
			return nil, err
		}
	} else if err := v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckDocumentPresent,
		Category: CategoryDocumentFormat,
	}); err != nil {
		return nil, err
	}

	// Verify each document
	for _, doc := range mdoc.Documents {
		if err := v.verifyDocument(doc, opts); err != nil {
			return nil, err
		}
	}

	return mdoc, nil
}

// verifyDocument verifies a single document.
func (v *Verifier) verifyDocument(doc interface{}, opts VerifyOptions) error {
	var issuerSigned *IssuerSigned
	var deviceSigned *DeviceSigned
	var docType DocType

	switch d := doc.(type) {
	case *IssuerSignedDocument:
		issuerSigned = d.IssuerSigned
		docType = d.DocType
	case *DeviceSignedDocument:
		issuerSigned = d.IssuerSigned
		deviceSigned = d.DeviceSigned
		docType = d.DocType
	default:
		return fmt.Errorf("unknown document type: %T", doc)
	}

	// Verify issuer signature
	if err := v.verifyIssuerSignature(issuerSigned, opts); err != nil {
		return err
	}

	// Verify device signature if present
	if deviceSigned != nil {
		if err := v.verifyDeviceSignature(docType, issuerSigned, deviceSigned, opts); err != nil {
			return err
		}
	} else {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceSignaturePresent,
			Category: CategoryDeviceAuth,
			Reason:   "Document is not device-signed",
		})
	}

	// Verify data integrity
	if err := v.verifyData(issuerSigned, opts); err != nil {
		return err
	}

	return nil
}

// verifyIssuerSignature verifies the issuer's signature.
func (v *Verifier) verifyIssuerSignature(issuerSigned *IssuerSigned, opts VerifyOptions) error {
	if issuerSigned == nil || issuerSigned.IssuerAuth == nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckIssuerSignatureValid,
			Category: CategoryIssuerAuth,
			Reason:   "IssuerAuth not present",
		})
	}

	issuerAuth := issuerSigned.IssuerAuth

	// Verify certificate
	cert := issuerAuth.Certificate()
	if cert == nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckIssuerCertValid,
			Category: CategoryIssuerAuth,
			Reason:   "Certificate not found in issuerAuth",
		})
	}

	// Verify certificate chain
	verifyOpts := x509.VerifyOptions{
		Roots:       v.trustedRoots,
		CurrentTime: time.Now(),
	}
	if !opts.DisableCertificateChainValidation {
		if _, err := cert.Verify(verifyOpts); err != nil {
			return v.check(opts, VerificationAssessment{
				Status:   StatusFailed,
				Check:    CheckIssuerCertValid,
				Category: CategoryIssuerAuth,
				Reason:   fmt.Sprintf("Certificate validation failed: %v", err),
			})
		}

		if err := v.check(opts, VerificationAssessment{
			Status:   StatusPassed,
			Check:    CheckIssuerCertValid,
			Category: CategoryIssuerAuth,
		}); err != nil {
			return err
		}
	}

	// Verify signature
	if err := issuerAuth.Verify(); err != nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckIssuerSignatureValid,
			Category: CategoryIssuerAuth,
			Reason:   fmt.Sprintf("Signature verification failed: %v", err),
		})
	}

	if err := v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckIssuerSignatureValid,
		Category: CategoryIssuerAuth,
	}); err != nil {
		return err
	}

	// Verify MSO dates
	mso := issuerAuth.MSO()
	if mso != nil {
		now := time.Now()

		// Check signed date within certificate validity
		if mso.ValidityInfo.Signed.Before(cert.NotBefore) || mso.ValidityInfo.Signed.After(cert.NotAfter) {
			return v.check(opts, VerificationAssessment{
				Status:   StatusFailed,
				Check:    CheckMSOSignedDateValid,
				Category: CategoryIssuerAuth,
				Reason:   "MSO signed date outside certificate validity period",
			})
		}

		if err := v.check(opts, VerificationAssessment{
			Status:   StatusPassed,
			Check:    CheckMSOSignedDateValid,
			Category: CategoryIssuerAuth,
		}); err != nil {
			return err
		}

		// Check MSO validity at verification time
		if now.Before(mso.ValidityInfo.ValidFrom) {
			return v.check(opts, VerificationAssessment{
				Status:   StatusFailed,
				Check:    CheckMSOValidAtVerification,
				Category: CategoryIssuerAuth,
				Reason:   "MSO not yet valid",
			})
		}
		if now.After(mso.ValidityInfo.ValidUntil) {
			return v.check(opts, VerificationAssessment{
				Status:   StatusFailed,
				Check:    CheckMSOValidAtVerification,
				Category: CategoryIssuerAuth,
				Reason:   "MSO expired",
			})
		}

		if err := v.check(opts, VerificationAssessment{
			Status:   StatusPassed,
			Check:    CheckMSOValidAtVerification,
			Category: CategoryIssuerAuth,
		}); err != nil {
			return err
		}
	}

	// Check country name present
	if issuerAuth.CountryName() == "" {
		return v.check(opts, VerificationAssessment{
			Status:   StatusWarning,
			Check:    CheckCountryNamePresent,
			Category: CategoryIssuerAuth,
			Reason:   "Country name not present in certificate",
		})
	}

	return v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckCountryNamePresent,
		Category: CategoryIssuerAuth,
	})
}

// verifyDeviceSignature verifies the device's signature or MAC.
func (v *Verifier) verifyDeviceSignature(
	docType DocType,
	issuerSigned *IssuerSigned,
	deviceSigned *DeviceSigned,
	opts VerifyOptions,
) error {
	if deviceSigned.DeviceAuth == nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceSignaturePresent,
			Category: CategoryDeviceAuth,
			Reason:   "DeviceAuth not present",
		})
	}

	// Check session transcript
	if opts.EncodedSessionTranscript == nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckSessionTranscriptProvided,
			Category: CategoryDeviceAuth,
			Reason:   "Session transcript not provided",
		})
	}

	if err := v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckSessionTranscriptProvided,
		Category: CategoryDeviceAuth,
	}); err != nil {
		return err
	}

	// Get device key from MSO
	mso := issuerSigned.IssuerAuth.MSO()
	if mso == nil || mso.DeviceKeyInfo == nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceKeyAvailable,
			Category: CategoryDeviceAuth,
			Reason:   "Device key not available in MSO",
		})
	}

	deviceKey, err := ParseCOSEKeyToPublicKey(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceKeyAvailable,
			Category: CategoryDeviceAuth,
			Reason:   fmt.Sprintf("Failed to parse device key: %v", err),
		})
	}

	if err := v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckDeviceKeyAvailable,
		Category: CategoryDeviceAuth,
	}); err != nil {
		return err
	}

	// Calculate device authentication bytes
	deviceAuthBytes, err := CalculateDeviceAuthenticationBytes(
		opts.EncodedSessionTranscript,
		docType,
		deviceSigned.NameSpaces,
	)
	if err != nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceSignatureValid,
			Category: CategoryDeviceAuth,
			Reason:   fmt.Sprintf("Failed to calculate device auth bytes: %v", err),
		})
	}

	// Verify based on auth type
	if deviceSigned.DeviceAuth.IsSignature() {
		return v.verifyDeviceAuthSignature(deviceKey, deviceSigned.DeviceAuth.DeviceSignature, deviceAuthBytes, opts)
	} else if deviceSigned.DeviceAuth.IsMAC() {
		ecKey, ok := deviceKey.(*ecdsa.PublicKey)
		if !ok {
			return v.check(opts, VerificationAssessment{
				Status:   StatusFailed,
				Check:    CheckDeviceKeyAvailable,
				Category: CategoryDeviceAuth,
				Reason:   "Device key is not an ECDSA key",
			})
		}
		return v.verifyDeviceAuthMAC(ecKey, deviceSigned.DeviceAuth.DeviceMAC, deviceAuthBytes, opts)
	}

	return v.check(opts, VerificationAssessment{
		Status:   StatusFailed,
		Check:    CheckDeviceSignaturePresent,
		Category: CategoryDeviceAuth,
		Reason:   "Neither signature nor MAC present in deviceAuth",
	})
}

// verifyDeviceAuthSignature verifies a device signature.
func (v *Verifier) verifyDeviceAuthSignature(
	deviceKey interface{},
	sign1 *cose.Sign1Message,
	deviceAuthBytes []byte,
	opts VerifyOptions,
) error {
	// Get algorithm
	alg, err := sign1.Headers.Protected.Algorithm()
	if err != nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceSignatureValid,
			Category: CategoryDeviceAuth,
			Reason:   fmt.Sprintf("Failed to get algorithm: %v", err),
		})
	}

	// Create verifier
	verifier, err := cose.NewVerifier(alg, deviceKey)
	if err != nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceSignatureValid,
			Category: CategoryDeviceAuth,
			Reason:   fmt.Sprintf("Failed to create verifier: %v", err),
		})
	}

	// Create copy with payload for verification
	sign1WithPayload := *sign1
	sign1WithPayload.Payload = deviceAuthBytes

	// Verify
	if err := sign1WithPayload.Verify(nil, verifier); err != nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceSignatureValid,
			Category: CategoryDeviceAuth,
			Reason:   fmt.Sprintf("Signature verification failed: %v", err),
		})
	}

	return v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckDeviceSignatureValid,
		Category: CategoryDeviceAuth,
	})
}

// verifyDeviceAuthMAC verifies a device MAC.
func (v *Verifier) verifyDeviceAuthMAC(
	deviceKey *ecdsa.PublicKey,
	mac0 *Mac0Message,
	deviceAuthBytes []byte,
	opts VerifyOptions,
) error {
	// Check ephemeral key provided
	if opts.EphemeralReaderKey == nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckEphemeralKeyProvided,
			Category: CategoryDeviceAuth,
			Reason:   "Ephemeral reader key not provided",
		})
	}

	if err := v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckEphemeralKeyProvided,
		Category: CategoryDeviceAuth,
	}); err != nil {
		return err
	}

	// Check algorithm
	alg, err := mac0.Algorithm()
	if err != nil || alg != AlgHMAC256 {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceMACAlgorithm,
			Category: CategoryDeviceAuth,
			Reason:   "Expected HMAC 256/256 algorithm",
		})
	}

	if err := v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckDeviceMACAlgorithm,
		Category: CategoryDeviceAuth,
	}); err != nil {
		return err
	}

	ephemeralPriv, err := parseEphemeralReaderKey(opts.EphemeralReaderKey, deviceKey)
	if err != nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceMACValid,
			Category: CategoryDeviceAuth,
			Reason:   fmt.Sprintf("Failed to parse ephemeral reader key: %v", err),
		})
	}

	macKey, err := CalculateEphemeralMacKey(ephemeralPriv, deviceKey, opts.EncodedSessionTranscript)
	if err != nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceMACValid,
			Category: CategoryDeviceAuth,
			Reason:   fmt.Sprintf("Failed to calculate MAC key: %v", err),
		})
	}

	if err := VerifyMac0(mac0, macKey, deviceAuthBytes); err != nil {
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDeviceMACValid,
			Category: CategoryDeviceAuth,
			Reason:   fmt.Sprintf("Device MAC verification failed: %v", err),
		})
	}

	return v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckDeviceMACValid,
		Category: CategoryDeviceAuth,
	})
}

// verifyData verifies the data integrity (digests).
func (v *Verifier) verifyData(issuerSigned *IssuerSigned, opts VerifyOptions) error {
	if issuerSigned == nil || issuerSigned.IssuerAuth == nil {
		return nil
	}

	mso := issuerSigned.IssuerAuth.MSO()
	if mso == nil {
		return nil
	}

	// Check digest algorithm
	switch mso.DigestAlgorithm {
	case DigestAlgorithmSHA256, DigestAlgorithmSHA384, DigestAlgorithmSHA512:
		// Supported
	default:
		return v.check(opts, VerificationAssessment{
			Status:   StatusFailed,
			Check:    CheckDigestAlgorithmSupported,
			Category: CategoryDataIntegrity,
			Reason:   fmt.Sprintf("Unsupported digest algorithm: %s", mso.DigestAlgorithm),
		})
	}

	if err := v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckDigestAlgorithmSupported,
		Category: CategoryDataIntegrity,
	}); err != nil {
		return err
	}

	// Verify each namespace
	for ns, items := range issuerSigned.NameSpaces {
		// Check namespace digests present
		if _, ok := mso.ValueDigests[ns]; !ok {
			return v.check(opts, VerificationAssessment{
				Status:   StatusFailed,
				Check:    CheckNamespaceDigestsPresent,
				Category: CategoryDataIntegrity,
				Reason:   fmt.Sprintf("No digests for namespace: %s", ns),
			})
		}

		// Verify each item
		for _, item := range items {
			valid, err := item.IsValid(ns, issuerSigned.IssuerAuth)
			if err != nil {
				return v.check(opts, VerificationAssessment{
					Status:   StatusFailed,
					Check:    CheckAttributeDigestValid,
					Category: CategoryDataIntegrity,
					Reason:   fmt.Sprintf("Failed to validate %s.%s: %v", ns, item.ElementIdentifier, err),
				})
			}
			if !valid {
				return v.check(opts, VerificationAssessment{
					Status:   StatusFailed,
					Check:    CheckAttributeDigestValid,
					Category: CategoryDataIntegrity,
					Reason:   fmt.Sprintf("Digest mismatch for %s.%s", ns, item.ElementIdentifier),
				})
			}

			// Check certificate match for MDL namespace
			if match := item.MatchCertificate(ns, issuerSigned.IssuerAuth); match != nil {
				check := CheckIssuingCountryMatchesCert
				if item.ElementIdentifier == "issuing_jurisdiction" {
					check = CheckIssuingJurisdictionMatchesCert
				}
				if !*match {
					return v.check(opts, VerificationAssessment{
						Status:   StatusFailed,
						Check:    check,
						Category: CategoryDataIntegrity,
						Reason:   fmt.Sprintf("%s does not match certificate", item.ElementIdentifier),
					})
				}
			}
		}
	}

	return v.check(opts, VerificationAssessment{
		Status:   StatusPassed,
		Check:    CheckAttributeDigestValid,
		Category: CategoryDataIntegrity,
	})
}

// check calls the verification callback and handles the result.
func (v *Verifier) check(opts VerifyOptions, assessment VerificationAssessment) error {
	if opts.OnCheck != nil {
		return opts.OnCheck(assessment)
	}

	// Default behavior: fail on FAILED status
	if assessment.Status == StatusFailed {
		return NewVerificationError(assessment)
	}

	return nil
}

// GetDiagnosticInformation returns detailed diagnostic information about a device response.
func (v *Verifier) GetDiagnosticInformation(data []byte, opts VerifyOptions) (*DiagnosticInfo, error) {
	var assessments []VerificationAssessment
	mdoc, err := v.Verify(data, VerifyOptions{
		EphemeralReaderKey:              opts.EphemeralReaderKey,
		EncodedSessionTranscript:        opts.EncodedSessionTranscript,
		DisableCertificateChainValidation: opts.DisableCertificateChainValidation,
		OnCheck: func(a VerificationAssessment) error {
			assessments = append(assessments, a)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}

	info := &DiagnosticInfo{}
	info.General.Version = mdoc.Version
	info.General.Status = mdoc.Status
	info.General.Documents = len(mdoc.Documents)

	// Process first document for detailed info
	if len(mdoc.Documents) > 0 {
		switch d := mdoc.Documents[0].(type) {
		case *IssuerSignedDocument:
			v.fillDiagnosticInfo(info, d, nil)
		case *DeviceSignedDocument:
			v.fillDiagnosticInfo(info, d.IssuerSignedDocument, d.DeviceSigned)
		}
	}

	setAssessmentSummary := func(category VerificationCategory, dest *DiagnosticSignature) {
		var reasons []string
		allPassed := true
		for _, a := range assessments {
			if a.Category != category {
				continue
			}
			if a.Status == StatusFailed {
				allPassed = false
				if a.Reason != "" {
					reasons = append(reasons, a.Reason)
				} else {
					reasons = append(reasons, string(a.Check))
				}
			}
		}
		dest.IsValid = allPassed
		dest.Reasons = reasons
	}

	setAssessmentSummary(CategoryIssuerAuth, &info.IssuerSignature)
	if info.DeviceSignature.Algorithm != "" {
		setAssessmentSummary(CategoryDeviceAuth, &info.DeviceSignature)
	}
	{
		var reasons []string
		allPassed := true
		for _, a := range assessments {
			if a.Category != CategoryDataIntegrity {
				continue
			}
			if a.Status == StatusFailed {
				allPassed = false
				if a.Reason != "" {
					reasons = append(reasons, a.Reason)
				} else {
					reasons = append(reasons, string(a.Check))
				}
			}
		}
		info.DataIntegrity.IsValid = allPassed
		info.DataIntegrity.Reasons = reasons
		info.DataIntegrity.DisclosedAttributes = countValidAttributes(info.Attributes)
	}

	return info, nil
}

// fillDiagnosticInfo fills diagnostic information from a document.
func (v *Verifier) fillDiagnosticInfo(
	info *DiagnosticInfo,
	issuerDoc *IssuerSignedDocument,
	deviceSigned *DeviceSigned,
) {
	info.General.Type = issuerDoc.DocType

	if issuerDoc.IssuerSigned != nil && issuerDoc.IssuerSigned.IssuerAuth != nil {
		issuerAuth := issuerDoc.IssuerSigned.IssuerAuth

		// Validity info
		mso := issuerAuth.MSO()
		if mso != nil {
			info.ValidityInfo = &mso.ValidityInfo
			if mso.DeviceKeyInfo != nil {
				if jwk, err := COSEKeyToJWKMap(mso.DeviceKeyInfo.DeviceKey); err == nil {
					info.DeviceKey = jwk
				}
			}
		}

		// Certificate info
		if cert := issuerAuth.Certificate(); cert != nil {
			thumbprint := sha1.Sum(cert.Raw)
			info.IssuerCertificate = &DiagnosticIssuerCert{
				SubjectName:  cert.Subject.String(),
				NotBefore:    cert.NotBefore,
				NotAfter:     cert.NotAfter,
				SerialNumber: cert.SerialNumber.String(),
				Thumbprint:   fmt.Sprintf("%x", thumbprint[:]),
				PEM:          string(EncodeCertificateToPEM(cert)),
			}
		}

		// Signature info
		alg, _ := issuerAuth.Sign1().Headers.Protected.Algorithm()
		info.IssuerSignature = DiagnosticSignature{
			Algorithm: alg.String(),
			IsValid:   issuerAuth.Verify() == nil,
		}

		// Attributes
		for ns, items := range issuerDoc.IssuerSigned.NameSpaces {
			for _, item := range items {
				valid, _ := item.IsValid(ns, issuerAuth)
				attr := DiagnosticAttribute{
					Namespace:  ns,
					Identifier: item.ElementIdentifier,
					Value:      item.ElementValue,
					IsValid:    valid,
				}
				if match := item.MatchCertificate(ns, issuerAuth); match != nil {
					attr.MatchCertificate = match
				}
				info.Attributes = append(info.Attributes, attr)
			}
		}
	}

	// Device attributes
	if deviceSigned != nil {
		if deviceSigned.DeviceAuth != nil {
			switch {
			case deviceSigned.DeviceAuth.DeviceSignature != nil:
				if alg, err := deviceSigned.DeviceAuth.DeviceSignature.Headers.Protected.Algorithm(); err == nil {
					info.DeviceSignature.Algorithm = alg.String()
				}
			case deviceSigned.DeviceAuth.DeviceMAC != nil:
				if alg, err := deviceSigned.DeviceAuth.DeviceMAC.Algorithm(); err == nil {
					info.DeviceSignature.Algorithm = fmt.Sprintf("%d", alg)
				}
			}
		}
		for ns, attrs := range deviceSigned.NameSpaces {
			for id, val := range attrs {
				info.DeviceAttributes = append(info.DeviceAttributes, DiagnosticAttribute{
					Namespace:  ns,
					Identifier: id,
					Value:      val,
					IsValid:    true,
				})
			}
		}
	}
}

func isSupportedVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) == 0 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minor := 0
	if len(parts) > 1 {
		if m, err := strconv.Atoi(parts[1]); err == nil {
			minor = m
		}
	}
	if major > 1 {
		return true
	}
	return major == 1 && minor >= 0
}

func parseEphemeralReaderKey(raw []byte, deviceKey *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty ephemeral reader key")
	}
	if key, err := ParseCOSEKeyToPrivateKey(raw); err == nil {
		if priv, ok := key.(*ecdsa.PrivateKey); ok {
			return priv, nil
		}
	}
	d := new(big.Int).SetBytes(raw)
	if d.Sign() == 0 {
		return nil, fmt.Errorf("invalid ephemeral reader key")
	}
	x, y := deviceKey.Curve.ScalarBaseMult(raw)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: deviceKey.Curve, X: x, Y: y},
		D:         d,
	}, nil
}

func countValidAttributes(attrs []DiagnosticAttribute) int {
	count := 0
	for _, attr := range attrs {
		if attr.IsValid {
			count++
		}
	}
	return count
}
