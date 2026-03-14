// Package cbor provides CBOR encoding and decoding utilities for mDocs.
package cbor

import (
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

// TagDateOnly is the CBOR tag for RFC 3339 full-date (YYYY-MM-DD)
const TagDateOnly = 1004

// TagDataItem is the CBOR tag for embedded CBOR data items (RFC 8949)
const TagDataItem = 24

// TagDateTime is the CBOR tag for RFC 3339 datetime
const TagDateTime = 0

// encMode is the default encoding mode with mDoc-specific settings
var encMode cbor.EncMode

// decMode is the default decoding mode with mDoc-specific settings
var decMode cbor.DecMode

// tagSet contains custom tag handlers for mDoc types
var tagSet cbor.TagSet

func init() {
	var err error

	// Create tag set with custom handlers
	tagSet = cbor.NewTagSet()

	// Register DateOnly tag (1004)
	err = tagSet.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(DateOnly{}),
		TagDateOnly,
	)
	if err != nil {
		panic(err)
	}

	// Register DataItem tag (24)
	err = tagSet.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(DataItem{}),
		TagDataItem,
	)
	if err != nil {
		panic(err)
	}

	// Create encoding mode
	encMode, err = cbor.EncOptions{
		Time:    cbor.TimeRFC3339,
		TimeTag: cbor.EncTagRequired,
		Sort:    cbor.SortCanonical,
	}.EncModeWithTags(tagSet)
	if err != nil {
		panic(err)
	}

	// Create decoding mode
	decMode, err = cbor.DecOptions{
		TimeTag: cbor.DecTagRequired,
	}.DecModeWithTags(tagSet)
	if err != nil {
		panic(err)
	}
}

// Encode encodes a value to CBOR bytes.
func Encode(v any) ([]byte, error) {
	return encMode.Marshal(v)
}

// Decode decodes CBOR bytes into a value.
func Decode(data []byte, v any) error {
	return decMode.Unmarshal(data, v)
}

// DecodeToMap decodes CBOR bytes into a map[any]any.
func DecodeToMap(data []byte) (map[any]any, error) {
	var result map[any]any
	if err := decMode.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// RawMessage is a raw encoded CBOR value that is included as-is during encoding.
type RawMessage = cbor.RawMessage

// MustEncode encodes a value to CBOR bytes and panics on error.
func MustEncode(v any) []byte {
	data, err := Encode(v)
	if err != nil {
		panic(err)
	}
	return data
}
