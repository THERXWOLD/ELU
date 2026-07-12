package glob

import "testing"

func TestPathTraversal(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"safe/*.go", "../safe/main.go", false},
		{"safe/*.go", "safe/../main.go", false},
		{"a/b/*.txt", "a/b/../c/file.txt", false},
		{"data/**", "../data/secret.txt", false},
		{"**/*.go", "a/../../etc/passwd", false},
		{"a/**/b", "a/../../b", false},
		{"a/**/b", "a/b", true},
		{"a/b/c", "a/b/c", true},
		{"a/b/c", "a/b/./c", true},
	}

	for _, tc := range tests {
		if got := Match(tc.pattern, tc.value); got != tc.want {
			t.Errorf("Match(%q, %q) = %v; want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestNormalizeCleansDots(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"./bar", "bar"},
		{"a/./b", "a/b"},
		{"a/b/../c", "a/c"},
	}

	for _, tc := range tests {
		if got := normalize(tc.input); got != tc.want {
			t.Errorf("normalize(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}
