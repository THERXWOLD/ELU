package access_test

import (
	"testing"

	"github.com/therxwold/elu/access"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/parser"
)

func BenchmarkEvaluateAccessPolicy(b *testing.B) {
	src := `pack "x" version 1
type = "access_policy"
access "site":
  default = "deny"
  role "admin":
    allow:
      read:
        - "*"
      update:
        - "blog.post"
    approval:
      update:
        - "system.settings"
`
	f, err := parser.ParseString("bench.elu", src)
	if err != nil {
		b.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		b.Fatal(err)
	}
	reg := extension.NewRegistry()
	req := access.Request{Roles: []string{"admin"}, Action: "update", Resource: "blog.post"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Evaluate(req, reg)
	}
}
