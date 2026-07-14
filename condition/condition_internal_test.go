package condition

import (
	"math"
	"testing"
)

func TestFloatEqualBasicCases(t *testing.T) {
	tests := []struct {
		name string
		a, b float64
		want bool
	}{
		{"identical", 1.0, 1.0, true},
		{"zero and zero", 0, 0, true},
		{"classic 0.1+0.2", 0.1 + 0.2, 0.3, true},
		{"small diff", 1.0, 1.0000000001, true},
		{"large diff", 1.0, 2.0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := floatEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("floatEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestFloatEqualEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		a, b float64
		want bool
	}{
		{"zero vs tiny", 0, 1e-15, false},
		{"large values", 1e15, 1e15 + 1, true},
		{"tiny values", 1e-15, 1e-15 + 1e-25, true},
		{"NaN vs NaN", math.NaN(), math.NaN(), false},
		{"inf equals inf", math.Inf(1), math.Inf(1), true},
		{"inf vs large", math.Inf(1), 1e308, true},
		{"neg zero equals zero", math.Copysign(0, -1), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := floatEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("floatEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareEqualCrossType(t *testing.T) {
	tests := []struct {
		name string
		a, b any
		want bool
	}{
		{"int vs float", int64(1), float64(1.0), true},
		{"float vs int", float64(2.5), int64(2), false},
		{"string vs string", "hello", "hello", true},
		{"bool vs bool", true, true, true},
		{"nil vs nil", nil, nil, true},
		{"string vs int", "1", int64(1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("compareEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
