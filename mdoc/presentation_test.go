package mdoc

import (
	"testing"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		path      string
		namespace string
		element   string
		wantErr   bool
	}{
		{
			path:      "$['org.iso.18013.5.1']['family_name']",
			namespace: "org.iso.18013.5.1",
			element:   "family_name",
			wantErr:   false,
		},
		{
			path:      "$['org.iso.18013.5.1']['birth_date']",
			namespace: "org.iso.18013.5.1",
			element:   "birth_date",
			wantErr:   false,
		},
		{
			path:    "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			parsed, err := ParsePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if parsed.Namespace != tt.namespace {
					t.Errorf("expected namespace %s, got %s", tt.namespace, parsed.Namespace)
				}
				if parsed.ElementIdentifier != tt.element {
					t.Errorf("expected element %s, got %s", tt.element, parsed.ElementIdentifier)
				}
			}
		})
	}
}

func TestIsAgeOverField(t *testing.T) {
	tests := []struct {
		field string
		want  bool
	}{
		{"age_over_18", true},
		{"age_over_21", true},
		{"age_over_65", true},
		{"family_name", false},
		{"birth_date", false},
		{"age", false},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			got := IsAgeOverField(tt.field)
			if got != tt.want {
				t.Errorf("IsAgeOverField(%s) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

func TestParseAgeOverValue(t *testing.T) {
	tests := []struct {
		field   string
		want    int
		wantErr bool
	}{
		{"age_over_18", 18, false},
		{"age_over_21", 21, false},
		{"age_over_65", 65, false},
		{"family_name", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			got, err := ParseAgeOverValue(tt.field)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAgeOverValue(%s) error = %v, wantErr %v", tt.field, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseAgeOverValue(%s) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

func TestPresentationDefinitionValidate(t *testing.T) {
	tests := []struct {
		name    string
		pd      *PresentationDefinition
		wantErr bool
	}{
		{
			name: "valid",
			pd: &PresentationDefinition{
				ID: "test",
				InputDescriptors: []InputDescriptor{
					{ID: "org.iso.18013.5.1.mDL"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			pd: &PresentationDefinition{
				InputDescriptors: []InputDescriptor{
					{ID: "org.iso.18013.5.1.mDL"},
				},
			},
			wantErr: true,
		},
		{
			name: "no descriptors",
			pd: &PresentationDefinition{
				ID:               "test",
				InputDescriptors: []InputDescriptor{},
			},
			wantErr: true,
		},
		{
			name: "duplicate IDs",
			pd: &PresentationDefinition{
				ID: "test",
				InputDescriptors: []InputDescriptor{
					{ID: "org.iso.18013.5.1.mDL"},
					{ID: "org.iso.18013.5.1.mDL"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pd.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildMDLPresentationDefinition(t *testing.T) {
	pd := BuildMDLPresentationDefinition("test-id", "family_name", "given_name", "birth_date")

	if pd.ID != "test-id" {
		t.Errorf("expected ID test-id, got %s", pd.ID)
	}
	if len(pd.InputDescriptors) != 1 {
		t.Fatalf("expected 1 input descriptor, got %d", len(pd.InputDescriptors))
	}

	id := pd.InputDescriptors[0]
	if id.ID != string(DocTypeMDL) {
		t.Errorf("expected ID %s, got %s", DocTypeMDL, id.ID)
	}
	if len(id.Constraints.Fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(id.Constraints.Fields))
	}

	// Validate paths
	for i, field := range id.Constraints.Fields {
		if len(field.Path) != 1 {
			t.Errorf("field %d: expected 1 path, got %d", i, len(field.Path))
		}
		parsed, err := ParsePath(field.Path[0])
		if err != nil {
			t.Errorf("field %d: failed to parse path: %v", i, err)
		}
		if parsed.Namespace != NamespaceMDL {
			t.Errorf("field %d: expected namespace %s, got %s", i, NamespaceMDL, parsed.Namespace)
		}
	}
}

func TestGetRequestedFields(t *testing.T) {
	pd := BuildMDLPresentationDefinition("test", "family_name", "given_name")

	fields := pd.GetRequestedFields()
	if len(fields) != 1 {
		t.Fatalf("expected 1 namespace, got %d", len(fields))
	}

	mdlFields := fields[NamespaceMDL]
	if len(mdlFields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(mdlFields))
	}

	// Check fields are present
	hasFamily := false
	hasGiven := false
	for _, f := range mdlFields {
		if f == "family_name" {
			hasFamily = true
		}
		if f == "given_name" {
			hasGiven = true
		}
	}

	if !hasFamily {
		t.Error("expected family_name in fields")
	}
	if !hasGiven {
		t.Error("expected given_name in fields")
	}
}
