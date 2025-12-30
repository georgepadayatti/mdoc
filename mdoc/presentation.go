package mdoc

import (
	"fmt"
	"regexp"
	"strings"
)

// PresentationDefinitionField represents a field in a presentation definition.
type PresentationDefinitionField struct {
	Path           []string `json:"path"`
	IntentToRetain bool     `json:"intent_to_retain"`
}

// Format specifies the accepted format for credentials.
type Format struct {
	MsoMdoc *MsoMdocFormat `json:"mso_mdoc,omitempty"`
}

// MsoMdocFormat specifies the mso_mdoc format constraints.
type MsoMdocFormat struct {
	Alg []string `json:"alg"`
}

// Constraints specifies the constraints for an input descriptor.
type Constraints struct {
	LimitDisclosure string                        `json:"limit_disclosure,omitempty"`
	Fields          []PresentationDefinitionField `json:"fields"`
}

// InputDescriptor describes a required credential.
type InputDescriptor struct {
	ID          string      `json:"id"`
	Format      Format      `json:"format"`
	Constraints Constraints `json:"constraints"`
}

// PresentationDefinition defines what credentials are requested.
type PresentationDefinition struct {
	ID               string            `json:"id"`
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
}

// Validate validates the presentation definition.
func (pd *PresentationDefinition) Validate() error {
	if pd.ID == "" {
		return fmt.Errorf("presentation definition ID is required")
	}
	if len(pd.InputDescriptors) == 0 {
		return fmt.Errorf("at least one input descriptor is required")
	}

	// Check for duplicate IDs
	seenIDs := make(map[string]bool)
	for _, id := range pd.InputDescriptors {
		if seenIDs[id.ID] {
			return fmt.Errorf("duplicate input descriptor ID: %s", id.ID)
		}
		seenIDs[id.ID] = true
	}

	return nil
}

// GetInputDescriptor returns the input descriptor for a document type.
func (pd *PresentationDefinition) GetInputDescriptor(docType DocType) *InputDescriptor {
	for i := range pd.InputDescriptors {
		if pd.InputDescriptors[i].ID == string(docType) {
			return &pd.InputDescriptors[i]
		}
	}
	return nil
}

// ParsedPath represents a parsed JSON path from a presentation definition.
type ParsedPath struct {
	Namespace         string
	ElementIdentifier string
}

// ParsePath parses a JSON path from a presentation definition.
// Format: "$['namespace']['element_identifier']"
func ParsePath(path string) (*ParsedPath, error) {
	// Match pattern like $['org.iso.18013.5.1']['family_name']
	re := regexp.MustCompile(`\$\['([^']+)'\]\['([^']+)'\]`)
	matches := re.FindStringSubmatch(path)
	if len(matches) != 3 {
		return nil, fmt.Errorf("invalid path format: %s", path)
	}

	return &ParsedPath{
		Namespace:         matches[1],
		ElementIdentifier: matches[2],
	}, nil
}

// ParsePaths parses multiple paths.
func ParsePaths(paths []string) ([]*ParsedPath, error) {
	result := make([]*ParsedPath, len(paths))
	for i, path := range paths {
		parsed, err := ParsePath(path)
		if err != nil {
			return nil, err
		}
		result[i] = parsed
	}
	return result, nil
}

// IsAgeOverField returns true if the element identifier is an age_over_NN field.
func IsAgeOverField(elementIdentifier string) bool {
	return strings.HasPrefix(elementIdentifier, "age_over_")
}

// ParseAgeOverValue extracts the age value from an age_over_NN field name.
func ParseAgeOverValue(elementIdentifier string) (int, error) {
	if !IsAgeOverField(elementIdentifier) {
		return 0, fmt.Errorf("not an age_over field: %s", elementIdentifier)
	}

	var age int
	_, err := fmt.Sscanf(elementIdentifier, "age_over_%d", &age)
	if err != nil {
		return 0, fmt.Errorf("failed to parse age from %s: %w", elementIdentifier, err)
	}
	return age, nil
}

// BuildMDLPresentationDefinition creates a presentation definition for mDL.
func BuildMDLPresentationDefinition(id string, fields ...string) *PresentationDefinition {
	pdfFields := make([]PresentationDefinitionField, len(fields))
	for i, field := range fields {
		pdfFields[i] = PresentationDefinitionField{
			Path:           []string{fmt.Sprintf("$['%s']['%s']", NamespaceMDL, field)},
			IntentToRetain: false,
		}
	}

	return &PresentationDefinition{
		ID: id,
		InputDescriptors: []InputDescriptor{
			{
				ID: string(DocTypeMDL),
				Format: Format{
					MsoMdoc: &MsoMdocFormat{
						Alg: []string{"ES256", "EdDSA"},
					},
				},
				Constraints: Constraints{
					LimitDisclosure: "required",
					Fields:          pdfFields,
				},
			},
		},
	}
}

// GetRequestedFields returns all requested namespace/field combinations.
func (pd *PresentationDefinition) GetRequestedFields() map[string][]string {
	result := make(map[string][]string)

	for _, id := range pd.InputDescriptors {
		for _, field := range id.Constraints.Fields {
			for _, path := range field.Path {
				parsed, err := ParsePath(path)
				if err != nil {
					continue
				}
				result[parsed.Namespace] = append(result[parsed.Namespace], parsed.ElementIdentifier)
			}
		}
	}

	return result
}
