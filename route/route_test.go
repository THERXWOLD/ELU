package route_test

import (
	"testing"

	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/route"
)

const routePolicySrc = `pack "app.security.routes" version 1
type = "route_policy"

routes "website":
  default = "deny"

  public:
    - method = "GET"
      path = "/"

    - method = "GET"
      path = "/blog/**"

  protected:
    - method = "GET"
      path = "/dashboard"
      require_role = "user"

    - method = "POST"
      path = "/admin/settings"
      require_role = "admin"
      require_2fa = true
      audit = true
      effect = "approval"

  route "api_draft_post":
    method = "POST"
    path = "/api/posts/*"
    effect = "allow"
    require_role = "author"

    when:
      all:
        - field = "resource.status"
          op = "eq"
          value = "draft"
`

func decodeRoute(t *testing.T) *route.Policy {
	t.Helper()
	f, err := parser.ParseString("routes.elu", routePolicySrc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := route.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoutePolicyEvaluation(t *testing.T) {
	p := decodeRoute(t)
	reg := extension.NewRegistry()
	cases := []struct {
		method, path string
		roles        []string
		mfa          bool
		ctx          condition.EvalContext
		want         policy.Effect
		audit        bool
	}{
		{"GET", "/", nil, false, nil, policy.EffectAllow, false},
		{"GET", "/blog/hello/world", nil, false, nil, policy.EffectAllow, false},
		{"GET", "/dashboard", nil, false, nil, policy.EffectDeny, false},
		{"GET", "/dashboard", []string{"user"}, false, nil, policy.EffectAllow, false},
		{"POST", "/admin/settings", []string{"admin"}, false, nil, policy.EffectDeny, true},
		{"POST", "/admin/settings", []string{"admin"}, true, nil, policy.EffectApproval, true},
		{"POST", "/api/posts/123", []string{"author"}, false, condition.EvalContext{"resource.status": "draft"}, policy.EffectAllow, false},
		{"POST", "/api/posts/123", []string{"author"}, false, condition.EvalContext{"resource.status": "published"}, policy.EffectDeny, false},
	}
	for _, tc := range cases {
		d := p.Evaluate(route.Request{Method: tc.method, Path: tc.path, Roles: tc.roles, MFA: tc.mfa, Context: tc.ctx}, reg)
		if d.Effect != tc.want || d.Audit != tc.audit {
			t.Fatalf("%s %s expected %s/audit=%v got %s/audit=%v matched=%v errors=%v", tc.method, tc.path, tc.want, tc.audit, d.Effect, d.Audit, d.MatchedRoutes, d.Errors)
		}
	}
}

func TestRouteRejectsProtectedWithoutGuard(t *testing.T) {
	src := `pack "app.security.routes" version 1
type = "route_policy"

routes "website":
  protected:
    - method = "GET"
      path = "/dashboard"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Decode(f); err == nil {
		t.Fatal("expected protected route without role/condition to fail")
	}
}

func TestRouteCustomOperatorValidatedWithRegistry(t *testing.T) {
	src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  route "internal":
    method = "GET"
    path = "/internal/**"
    effect = "allow"

    when:
      all:
        - field = "request.ip"
          op = "within_cidr"
          value = "10.0.0.0/8"
`
	f, err := parser.ParseString("routes.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := route.Decode(f)
	if err != nil {
		t.Fatalf("decode should not reject custom operator before registry validation: %v", err)
	}
	if err := route.ValidatePolicy(p, extension.NewRegistry()); err == nil {
		t.Fatal("expected validation error without custom operator")
	}
	reg := extension.NewRegistry()
	reg.RegisterOperator("within_cidr", func(left, right any) (bool, error) { return left == "10.1.2.3" && right == "10.0.0.0/8", nil })
	if err := route.ValidatePolicy(p, reg); err != nil {
		t.Fatalf("expected validation with registered operator: %v", err)
	}
	d := p.Evaluate(route.Request{Method: "GET", Path: "/internal/status", Context: condition.EvalContext{"request.ip": "10.1.2.3"}}, reg)
	if d.Effect != policy.EffectAllow {
		t.Fatalf("expected allow, got %s errors=%v", d.Effect, d.Errors)
	}
}

func TestExplicitRouteRequiresEffect(t *testing.T) {
	src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  route "admin":
    method = "GET"
    path = "/admin"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Decode(f); err == nil {
		t.Fatal("expected explicit route without effect to fail")
	}
}

func TestProtectedRouteConditionMustReferenceAuthOrSubject(t *testing.T) {
	src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  protected:
    - method = "GET"
      path = "/admin"
      when:
        all:
          - field = "env.name"
            op = "eq"
            value = "prod"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Decode(f); err == nil {
		t.Fatal("expected protected route guarded only by env condition to fail")
	}
}

func TestRouteRejectsInvalidMethod(t *testing.T) {
	src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  public:
    - method = "GTE"
      path = "/"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Decode(f); err == nil {
		t.Fatal("expected invalid HTTP method to fail")
	}
}

func TestRouteConditionErrorFailsClosedNever(t *testing.T) {
	src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  route "custom":
    method = "GET"
    path = "/admin"
    effect = "allow"
    when:
      all:
        - field = "request.ip"
          op = "missing_custom_operator"
          value = "127.0.0.1"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := route.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(route.Request{Method: "GET", Path: "/admin", Context: condition.EvalContext{"request.ip": "127.0.0.1"}}, extension.NewRegistry())
	if d.Effect != policy.EffectNever || len(d.Errors) == 0 {
		t.Fatalf("expected never with error, got %s errors=%v", d.Effect, d.Errors)
	}
}

func TestRouteRejectsDuplicateSections(t *testing.T) {
	src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  public:
    - method = "GET"
      path = "/one"
  public:
    - method = "GET"
      path = "/two"
`
	f, err := parser.ParseString("dup.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Decode(f); err == nil {
		t.Fatal("expected duplicate routes section to fail")
	}
}

func TestProtectedRouteRequiresRequireRoleEvenWithSubjectCondition(t *testing.T) {
	tests := []string{
		`when:
        all:
          - field = "subject.roles"
            op = "exists"`,
		`require_2fa = true`,
	}
	for _, extra := range tests {
		src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  protected:
    - method = "GET"
      path = "/admin"
      ` + extra + `
`
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := route.Decode(f); err == nil {
			t.Fatalf("expected protected route without require_role to fail:\n%s", src)
		}
	}
}

func TestRouteTrailingDoubleStarMatchesBasePath(t *testing.T) {
	p := decodeRoute(t)
	d := p.Evaluate(route.Request{Method: "GET", Path: "/blog"}, extension.NewRegistry())
	if d.Effect != policy.EffectAllow {
		t.Fatalf("expected /blog/** to match /blog, got %s", d.Effect)
	}
}

func TestPublicRouteRejectsAuthFields(t *testing.T) {
	tests := []string{
		`require_role = "admin"`,
		`require_2fa = true`,
	}
	for _, extra := range tests {
		src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  public:
    - method = "GET"
      path = "/public"
      ` + extra + `
`
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := route.Decode(f); err == nil {
			t.Fatalf("expected public route auth field to fail:\n%s", src)
		}
	}
}

func TestRouteRejectsPublicProtectedConflicts(t *testing.T) {
	src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  public:
    - method = "GET"
      path = "/admin/**"

  protected:
    - method = "GET"
      path = "/admin/settings"
      require_role = "admin"
`
	f, err := parser.ParseString("conflict.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Decode(f); err == nil {
		t.Fatal("expected overlapping public/protected routes to be rejected")
	}
}

func TestExplicitRouteRequire2FARequiresRole(t *testing.T) {
	src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  route "admin":
    method = "GET"
    path = "/admin"
    effect = "allow"
    require_2fa = true
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Decode(f); err == nil {
		t.Fatal("expected require_2fa without require_role to fail")
	}
}

func TestRouteRejectsInvalidPaths(t *testing.T) {
	for _, path := range []string{"admin", " /admin", "/admin "} {
		src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  route "bad":
    method = "GET"
    path = "` + path + `"
    effect = "allow"
`
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := route.Decode(f); err == nil {
			t.Fatalf("expected invalid path %q to fail", path)
		}
	}
}

func TestRouteRequestInjectsSubjectID(t *testing.T) {
	src := `pack "app.routes" version 1
type = "route_policy"

routes "site":
  route "mine":
    method = "GET"
    path = "/me"
    effect = "allow"
    when:
      all:
        - field = "subject.id"
          op = "eq"
          value = "u1"
`
	f, err := parser.ParseString("route.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := route.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(route.Request{SubjectID: "u1", Method: "GET", Path: "/me"}, extension.NewRegistry())
	if d.Effect != policy.EffectAllow {
		t.Fatalf("expected allow, got %s errors=%v", d.Effect, d.Errors)
	}
}
