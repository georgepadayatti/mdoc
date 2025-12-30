// Package testdata contains test vectors and utilities for mdoc tests.
package testdata

// IssuerCertificatePEM is a test issuer certificate for NY DMV.
const IssuerCertificatePEM = `-----BEGIN CERTIFICATE-----
MIICKjCCAdCgAwIBAgIUV8bM0wi95D7KN0TyqHE42ru4hOgwCgYIKoZIzj0EAwIw
UzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMQ8wDQYDVQQHDAZBbGJh
bnkxDzANBgNVBAoMBk5ZIERNVjEPMA0GA1UECwwGTlkgRE1WMB4XDTIzMDkxNDE0
NTUxOFoXDTMzMDkxMTE0NTUxOFowUzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5l
dyBZb3JrMQ8wDQYDVQQHDAZBbGJhbnkxDzANBgNVBAoMBk5ZIERNVjEPMA0GA1UE
CwwGTlkgRE1WMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiTwtg0eQbcbNabf2
Nq9L/VM/lhhPCq2s0Qgw2kRx29tgrBcNHPxTT64tnc1Ij3dH/fl42SXqMenpCDw4
K6ntU6OBgTB/MB0GA1UdDgQWBBSrbS4DuR1JIkAzj7zK3v2TM+r2xzAfBgNVHSME
GDAWgBSrbS4DuR1JIkAzj7zK3v2TM+r2xzAPBgNVHRMBAf8EBTADAQH/MCwGCWCG
SAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAKBggqhkjO
PQQDAgNIADBFAiAJ/Qyrl7A+ePZOdNfc7ohmjEdqCvxaos6//gfTvncuqQIhANo4
q8mKCA9J8k/+zh//yKbN1bLAtdqPx7dnrDqV3Lg+
-----END CERTIFICATE-----`

// IssuerPrivateKeyPEM is the test issuer private key.
const IssuerPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCjo+vMGbV0J9LCokdb
oNWqYk4JBIgCiysI99sUkMw2ng==
-----END PRIVATE KEY-----`

// DeviceKeyJWK is a test device key in JWK format.
// X and Y are base64url encoded.
var DeviceKeyJWK = map[string]string{
	"kty": "EC",
	"crv": "P-256",
	"x":   "iBh5ynojixm_D0wfjADpouGbp6b3Pq6SuFHU3htQhVk",
	"y":   "oxS1OAORJ7XNUHNfVFGeM8E0RQVFxWA62fJj-sxW03c",
	"d":   "eRpAZr3eV5xMMnPG3kWjg90Y-bBff9LqmlQuk49HUtA",
}

// TestMDLData contains sample mDL data.
var TestMDLData = map[string]any{
	"family_name":         "Jones",
	"given_name":          "Ava",
	"birth_date":          "2007-03-25",
	"issue_date":          "2023-09-01",
	"expiry_date":         "2028-09-30",
	"issuing_country":     "US",
	"issuing_authority":   "NY DMV",
	"issuing_jurisdiction": "New York",
	"document_number":     "01-856-5050",
	"portrait":            []byte("portrait-data"),
	"driving_privileges": []map[string]any{
		{
			"vehicle_category_code": "A",
			"issue_date":            "2021-09-02",
			"expiry_date":           "2026-09-20",
		},
	},
}

// PresentationDefinitionAllFields is a presentation definition requesting all mDL fields.
var PresentationDefinitionAllFields = map[string]any{
	"id": "mdl-test-all-data",
	"input_descriptors": []map[string]any{
		{
			"id": "org.iso.18013.5.1.mDL",
			"format": map[string]any{
				"mso_mdoc": map[string]any{
					"alg": []string{"EdDSA", "ES256"},
				},
			},
			"constraints": map[string]any{
				"limit_disclosure": "required",
				"fields": []map[string]any{
					{"path": []string{"$['org.iso.18013.5.1']['family_name']"}, "intent_to_retain": false},
					{"path": []string{"$['org.iso.18013.5.1']['given_name']"}, "intent_to_retain": false},
					{"path": []string{"$['org.iso.18013.5.1']['birth_date']"}, "intent_to_retain": false},
					{"path": []string{"$['org.iso.18013.5.1']['issue_date']"}, "intent_to_retain": false},
					{"path": []string{"$['org.iso.18013.5.1']['expiry_date']"}, "intent_to_retain": false},
					{"path": []string{"$['org.iso.18013.5.1']['issuing_country']"}, "intent_to_retain": false},
					{"path": []string{"$['org.iso.18013.5.1']['issuing_authority']"}, "intent_to_retain": false},
					{"path": []string{"$['org.iso.18013.5.1']['document_number']"}, "intent_to_retain": false},
				},
			},
		},
	},
}
