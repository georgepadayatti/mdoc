package cbor

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// DataItem represents an embedded CBOR data item (RFC 8949, tag 24).
// It allows lazy encoding/decoding of nested CBOR structures.
type DataItem struct {
	data   any    // Decoded data (may be nil if only buffer is set)
	buffer []byte // CBOR-encoded bytes (may be nil if only data is set)
}

// NewDataItem creates a DataItem from decoded data.
func NewDataItem(data any) *DataItem {
	return &DataItem{data: data}
}

// NewDataItemFromBytes creates a DataItem from CBOR-encoded bytes.
func NewDataItemFromBytes(buffer []byte) *DataItem {
	return &DataItem{buffer: buffer}
}

// Data returns the decoded data, decoding from buffer if necessary.
func (d *DataItem) Data() (any, error) {
	if d.data != nil {
		return d.data, nil
	}
	if d.buffer == nil {
		return nil, nil
	}
	var result any
	if err := Decode(d.buffer, &result); err != nil {
		return nil, fmt.Errorf("failed to decode DataItem: %w", err)
	}
	d.data = result
	return d.data, nil
}

// MustData returns the decoded data and panics on error.
func (d *DataItem) MustData() any {
	data, err := d.Data()
	if err != nil {
		panic(err)
	}
	return data
}

// Bytes returns the CBOR-encoded bytes, encoding from data if necessary.
func (d *DataItem) Bytes() ([]byte, error) {
	if d.buffer != nil {
		return d.buffer, nil
	}
	if d.data == nil {
		return nil, nil
	}
	encoded, err := Encode(d.data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode DataItem: %w", err)
	}
	d.buffer = encoded
	return d.buffer, nil
}

// MustBytes returns the CBOR-encoded bytes and panics on error.
func (d *DataItem) MustBytes() []byte {
	bytes, err := d.Bytes()
	if err != nil {
		panic(err)
	}
	return bytes
}

// MarshalCBOR implements cbor.Marshaler for CBOR tag 24.
func (d DataItem) MarshalCBOR() ([]byte, error) {
	// Get the inner CBOR bytes
	innerBytes, err := d.Bytes()
	if err != nil {
		return nil, err
	}
	// Wrap in tag 24
	tag := cbor.Tag{
		Number:  TagDataItem,
		Content: innerBytes,
	}
	return cbor.Marshal(tag)
}

// UnmarshalCBOR implements cbor.Unmarshaler for CBOR tag 24.
func (d *DataItem) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Number != TagDataItem {
		return fmt.Errorf("expected CBOR tag %d, got %d", TagDataItem, tag.Number)
	}
	// The content should be raw CBOR bytes
	switch v := tag.Content.(type) {
	case []byte:
		d.buffer = v
	default:
		return fmt.Errorf("expected bytes content for DataItem, got %T", tag.Content)
	}
	return nil
}

// DecodeInto decodes the DataItem's contents into the provided value.
func (d *DataItem) DecodeInto(v any) error {
	bytes, err := d.Bytes()
	if err != nil {
		return err
	}
	return Decode(bytes, v)
}
