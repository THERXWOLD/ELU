package value_test

import (
	"strings"
	"testing"

	"github.com/therxwold/elu/value"
)

func TestParseScalarOverflow(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"max int64 + 1", "9223372036854775808"},
		{"very large", "99999999999999999999999999999999999999999999999999"},
		{"negative overflow", "-9223372036854775809"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := value.ParseScalar(tt.raw, 1, 1)
			if err == nil {
				t.Fatalf("expected overflow error for %q", tt.raw)
			}
			if !strings.Contains(err.Error(), "overflows int64") {
				t.Fatalf("expected overflow error, got: %v", err)
			}
		})
	}
}

func TestParseScalarValidIntegers(t *testing.T) {
	tests := []struct {
		raw string
		val int64
	}{
		{"0", 0},
		{"42", 42},
		{"-1", -1},
		{"9223372036854775807", 9223372036854775807},
		{"-9223372036854775808", -9223372036854775808},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			v, err := value.ParseScalar(tt.raw, 1, 1)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.raw, err)
			}
			if v.Kind != value.Int || v.I != tt.val {
				t.Fatalf("expected int %d, got %+v", tt.val, v)
			}
		})
	}
}

func TestParseScalarLeadingZeroRejected(t *testing.T) {
	_, err := value.ParseScalar("042", 1, 1)
	if err == nil {
		t.Fatal("expected error for leading zero")
	}
}
