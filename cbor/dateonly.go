package cbor

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// DateOnly represents an RFC 3339 full-date (YYYY-MM-DD) without time components.
// It is encoded as CBOR tag 1004 with a text string value.
type DateOnly struct {
	Year  int
	Month time.Month
	Day   int
}

// NewDateOnly creates a new DateOnly from year, month, and day.
func NewDateOnly(year int, month time.Month, day int) DateOnly {
	return DateOnly{Year: year, Month: month, Day: day}
}

// DateOnlyFromTime creates a DateOnly from a time.Time.
func DateOnlyFromTime(t time.Time) DateOnly {
	return DateOnly{
		Year:  t.Year(),
		Month: t.Month(),
		Day:   t.Day(),
	}
}

// ParseDateOnly parses a date string in YYYY-MM-DD format.
func ParseDateOnly(s string) (DateOnly, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return DateOnly{}, fmt.Errorf("invalid date format: %w", err)
	}
	return DateOnlyFromTime(t), nil
}

// MustParseDateOnly parses a date string and panics on error.
func MustParseDateOnly(s string) DateOnly {
	d, err := ParseDateOnly(s)
	if err != nil {
		panic(err)
	}
	return d
}

// String returns the date in YYYY-MM-DD format.
func (d DateOnly) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day)
}

// Time returns a time.Time at midnight UTC for this date.
func (d DateOnly) Time() time.Time {
	return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
}

// MarshalCBOR implements cbor.Marshaler for CBOR tag 1004.
func (d DateOnly) MarshalCBOR() ([]byte, error) {
	// Tag 1004 with text string value
	tag := cbor.Tag{
		Number:  TagDateOnly,
		Content: d.String(),
	}
	return cbor.Marshal(tag)
}

// UnmarshalCBOR implements cbor.Unmarshaler for CBOR tag 1004.
func (d *DateOnly) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Number != TagDateOnly {
		return fmt.Errorf("expected CBOR tag %d, got %d", TagDateOnly, tag.Number)
	}
	s, ok := tag.Content.(string)
	if !ok {
		return fmt.Errorf("expected string content for DateOnly, got %T", tag.Content)
	}
	parsed, err := ParseDateOnly(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// IsZero returns true if the date is the zero value.
func (d DateOnly) IsZero() bool {
	return d.Year == 0 && d.Month == 0 && d.Day == 0
}

// Equal returns true if two dates are equal.
func (d DateOnly) Equal(other DateOnly) bool {
	return d.Year == other.Year && d.Month == other.Month && d.Day == other.Day
}

// Before returns true if d is before other.
func (d DateOnly) Before(other DateOnly) bool {
	if d.Year != other.Year {
		return d.Year < other.Year
	}
	if d.Month != other.Month {
		return d.Month < other.Month
	}
	return d.Day < other.Day
}

// After returns true if d is after other.
func (d DateOnly) After(other DateOnly) bool {
	return other.Before(d)
}
