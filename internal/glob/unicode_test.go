package glob

import "testing"

func TestUnicodeLiteralAndWildcards(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"café", "café", true},
		{"caf?", "café", true},
		{"資料/*.elu", "資料/規則.elu", true},
		{"данные/**", "данные/личное/файл.txt", true},
		{"cafe", "café", false},
	}

	for _, tc := range tests {
		if got := Match(tc.pattern, tc.value); got != tc.want {
			t.Errorf("Match(%q, %q) = %v; want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}
