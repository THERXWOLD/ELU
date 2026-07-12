// Package glob implements ELU's portable glob matching.
// No filesystem access, just pattern math.
package glob

import (
	"path"
	"regexp"
	"strings"
	"sync"
)

// Match reports whether value matches pattern using ELU's portable glob syntax.
//
// Supported syntax:
//   - matches any characters except '/'
//     ?  matches one character except '/'
//     ** matches across path separators
//
// A pattern segment of "**/" matches zero or more directories, so
// "backend/**/*.go" matches both "backend/main.go" and
// "backend/internal/auth/session.go".
func Match(pattern, value string) bool {
	pattern = normalize(pattern)
	value = normalize(value)
	if pattern == "*" || pattern == "**" || pattern == value {
		return true
	}
	if strings.HasSuffix(pattern, "/**") && value == strings.TrimSuffix(pattern, "/**") {
		return true
	}
	re, err := globRegexp(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// normalize swaps backslashes for forward slashes so Windows paths
// don't break everything, then cleans path traversal segments.
func normalize(s string) string {
	s = strings.ReplaceAll(s, "\\", "/")
	s = path.Clean(s)
	return s
}

var cachedRegex = sync.Map{}

// globRegexp compiles a glob pattern into a regexp.
//
//   - → [^/]*   (anything but slash)
//     ?  → [^/]    (one anything-but-slash)
//     ** → .*      (absolutely everything)
//     **/ → (?:.*/)? (zero or more directory levels)
func globRegexp(pattern string) (*regexp.Regexp, error) {
	// Check the cache first. This is a hot path, and compiling regexps is  expensive.
	if cached, ok := cachedRegex.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	var b strings.Builder
	b.WriteString("^")

	// Iterate over Unicode code points, not UTF-8 bytes. Quoting one byte at a
	// time corrupts non-ASCII literals such as "café" or "資料".
	runes := []rune(pattern)
	for i := 0; i < len(runes); {
		switch runes[i] {
		case '*':
			if i+1 < len(runes) && runes[i+1] == '*' {
				if i+2 < len(runes) && runes[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 3
					continue
				}
				b.WriteString(".*")
				i += 2
				continue
			}
			b.WriteString("[^/]*")
			i++
		case '?':
			b.WriteString("[^/]")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(runes[i])))
			i++
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	cachedRegex.Store(pattern, re)
	return re, nil
}
