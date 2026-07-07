package parser_test

import (
	"testing"

	"github.com/therxwold/elu/parser"
)

func FuzzParseString(f *testing.F) {
	seeds := []string{
		`pack "x" version 1
type = "access_policy"
access "site":
  default = "deny"
`,
		`pack "x" version 1
type = "route_policy"
routes "site":
  public:
    - method = "GET"
      path = "/"
`,
		`not elu`,
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		_, _ = parser.ParseString("fuzz.elu", src)
	})
}
