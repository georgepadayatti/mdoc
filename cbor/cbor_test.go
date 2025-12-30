package cbor

import (
	"testing"
	"time"
)

func TestDateOnlyParse(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"2023-09-14", false},
		{"2007-03-25", false},
		{"invalid", true},
		{"2023/09/14", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			d, err := ParseDateOnly(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDateOnly(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err == nil && d.String() != tt.input {
				t.Errorf("expected %s, got %s", tt.input, d.String())
			}
		})
	}
}

func TestDateOnlyFromTime(t *testing.T) {
	now := time.Date(2023, 9, 14, 10, 30, 0, 0, time.UTC)
	d := DateOnlyFromTime(now)

	if d.Year != 2023 {
		t.Errorf("expected year 2023, got %d", d.Year)
	}
	if d.Month != 9 {
		t.Errorf("expected month 9, got %d", d.Month)
	}
	if d.Day != 14 {
		t.Errorf("expected day 14, got %d", d.Day)
	}
}

func TestDateOnlyString(t *testing.T) {
	d := NewDateOnly(2023, 9, 14)
	expected := "2023-09-14"
	if d.String() != expected {
		t.Errorf("expected %s, got %s", expected, d.String())
	}
}

func TestDateOnlyTime(t *testing.T) {
	d := NewDateOnly(2023, 9, 14)
	tm := d.Time()

	if tm.Year() != 2023 || tm.Month() != 9 || tm.Day() != 14 {
		t.Errorf("unexpected time: %v", tm)
	}
	if tm.Hour() != 0 || tm.Minute() != 0 || tm.Second() != 0 {
		t.Errorf("expected midnight, got %v", tm)
	}
}

func TestDateOnlyComparison(t *testing.T) {
	d1 := NewDateOnly(2023, 9, 14)
	d2 := NewDateOnly(2023, 9, 15)
	d3 := NewDateOnly(2023, 9, 14)

	if !d1.Before(d2) {
		t.Error("expected d1 before d2")
	}
	if !d2.After(d1) {
		t.Error("expected d2 after d1")
	}
	if !d1.Equal(d3) {
		t.Error("expected d1 equal to d3")
	}
}

func TestEncodeDecode(t *testing.T) {
	testCases := []struct {
		name  string
		value any
	}{
		{"string", "hello"},
		{"int", 42},
		{"bytes", []byte{1, 2, 3}},
		{"map", map[string]any{"key": "value"}},
		{"array", []any{1, 2, 3}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := Encode(tc.value)
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			var decoded any
			if err := Decode(encoded, &decoded); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}
		})
	}
}

func TestDataItem(t *testing.T) {
	data := map[string]any{
		"key1": "value1",
		"key2": 42,
	}

	// Create DataItem from data
	item := NewDataItem(data)

	// Get bytes
	bytes, err := item.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}
	if len(bytes) == 0 {
		t.Error("expected non-empty bytes")
	}

	// Create DataItem from bytes
	item2 := NewDataItemFromBytes(bytes)

	// Get data back
	decoded, err := item2.Data()
	if err != nil {
		t.Fatalf("Data failed: %v", err)
	}
	if decoded == nil {
		t.Error("expected non-nil data")
	}
}

func TestDataItemDecodeInto(t *testing.T) {
	original := map[string]string{
		"name": "test",
	}

	encoded, err := Encode(original)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	item := NewDataItemFromBytes(encoded)

	var decoded map[string]string
	if err := item.DecodeInto(&decoded); err != nil {
		t.Fatalf("DecodeInto failed: %v", err)
	}

	if decoded["name"] != "test" {
		t.Errorf("expected name=test, got %s", decoded["name"])
	}
}
