package glob

import "testing"

func FuzzGlobMatch(f *testing.F) {
	seeds := []struct {
		pattern, value string
	}{
		{"*.go", "main.go"},
		{"**/*.md", "docs/readme.md"},
		{"backend/**/*.go", "backend/internal/auth.go"},
		{"/api/*", "/api/users"},
		{"?", "a"},
		{"**", "any/path/here"},
		{"*", "no-slash"},
		{"café*", "café.md"},
		{"", ""},
		{`\\server\share`, `\\server\share`},
		{"docs/../etc/passwd", "etc/passwd"},
	}
	for _, s := range seeds {
		f.Add(s.pattern, s.value)
	}
	f.Fuzz(func(t *testing.T, pattern, value string) {
		_ = Match(pattern, value)
	})
}
