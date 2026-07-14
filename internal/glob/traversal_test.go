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

func TestGlobCacheHitReturnsSameResult(t *testing.T) {
	r1, err1 := globRegexp("*.go")
	r2, err2 := globRegexp("*.go")
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v, %v", err1, err2)
	}
	if r1 != r2 {
		t.Fatal("expected cache hit to return same *regexp.Regexp pointer")
	}
}

func TestGlobCacheMissCompilesFresh(t *testing.T) {
	r1, _ := globRegexp("*.go")
	r2, _ := globRegexp("*.md")
	if r1 == r2 {
		t.Fatal("expected different patterns to produce different regexp pointers")
	}
}

func TestMatchInvalidPatternReturnsFalse(t *testing.T) {
	if Match("*invalid", "anything") {
		t.Fatal("expected invalid pattern to return false")
	}
}
