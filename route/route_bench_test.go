package route_test

import (
	"testing"

	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/route"
)

func BenchmarkEvaluateRoutePolicy(b *testing.B) {
	src := `pack "x" version 1
type = "route_policy"
routes "site":
  default = "deny"
  public:
    - method = "GET"
      path = "/"
  protected:
    - method = "GET"
      path = "/dashboard"
      require_role = "user"
  route "settings":
    method = "POST"
    path = "/admin/settings"
    effect = "approval"
    require_role = "admin"
    require_2fa = true
`
	f, err := parser.ParseString("bench.elu", src)
	if err != nil {
		b.Fatal(err)
	}
	p, err := route.Decode(f)
	if err != nil {
		b.Fatal(err)
	}
	reg := extension.NewRegistry()
	req := route.Request{Method: "POST", Path: "/admin/settings", Roles: []string{"admin"}, MFA: true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Evaluate(req, reg)
	}
}
