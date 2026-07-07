package e2e_test

import (
	"testing"

	"github.com/therxwold/elu/access"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/filter"
	"github.com/therxwold/elu/guardrail"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/route"
	"github.com/therxwold/elu/validate"
)

func TestE2EStrictSecurityValidationRejectsDangerousPolicies(t *testing.T) {
	cases := []struct{ name, src string }{
		{"public route with role", `pack "x" version 1
type = "route_policy"
routes "site":
  public:
    - method = "GET"
      path = "/admin"
      require_role = "admin"
`},
		{"route mfa without role", `pack "x" version 1
type = "route_policy"
routes "site":
  route "admin":
    method = "GET"
    path = "/admin"
    effect = "allow"
    require_2fa = true
`},
		{"filter replacement without redact", `pack "x" version 1
type = "filter_pack"
filter "paths":
  applies_to:
    - "repo.patch"
  block_paths:
    - ".env*"
  action:
    on_match = "deny"
    replacement = "[REDACTED]"
`},
		{"critical guardrail report only", `pack "x" version 1
type = "guardrail_pack"
guardrail "g":
  severity = "critical"
  never:
    - "expose secrets"
  on_violation:
    action = "report"
`},
	}
	reg := extension.NewRegistry()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseString(tc.name+".elu", tc.src)
			if err != nil {
				t.Fatal(err)
			}
			if diags := validate.File(f, reg, true); !diags.HasErrors() {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestE2EAccessNestedResourceContextIsPreserved(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"
access "site":
  default = "deny"
  role "admin":
    rule "special_resource":
      effect = "allow"
      action = "read"
      resource = "blog.post"
      when:
        all:
          - field = "resource.type"
            op = "eq"
            value = "special"
`
	reg := extension.NewRegistry()
	f := mustParseAndValidate(t, "access-nested.elu", src, reg)
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(access.Request{Roles: []string{"admin"}, Action: "read", Resource: "blog.post", Context: condition.EvalContext{"resource": map[string]string{"type": "special"}}}, reg)
	if d.Effect != policy.EffectAllow {
		t.Fatalf("expected allow, got %s errors=%v", d.Effect, d.Errors)
	}
}

func TestE2ERouteSubjectIDConditions(t *testing.T) {
	src := `pack "x" version 1
type = "route_policy"
routes "site":
  route "own_settings":
    method = "POST"
    path = "/settings"
    effect = "allow"
    require_role = "user"
    when:
      all:
        - field = "subject.id"
          op = "eq"
          value = "u1"
`
	reg := extension.NewRegistry()
	f := mustParseAndValidate(t, "route-subject.elu", src, reg)
	p, err := route.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(route.Request{SubjectID: "u1", Method: "POST", Path: "/settings", Roles: []string{"user"}}, reg); d.Effect != policy.EffectAllow {
		t.Fatalf("expected allow for subject u1, got %s", d.Effect)
	}
	if d := p.Evaluate(route.Request{SubjectID: "u2", Method: "POST", Path: "/settings", Roles: []string{"user"}}, reg); d.Effect != policy.EffectDeny {
		t.Fatalf("expected deny for subject u2, got %s", d.Effect)
	}
}

func TestE2EDecodersStillAcceptValidGuardrailAndFilter(t *testing.T) {
	guardSrc := `pack "x" version 1
type = "guardrail_pack"
guardrail "g":
  severity = "critical"
  never:
    - "expose secrets"
  on_violation:
    action = "block"
`
	filterSrc := `pack "x" version 1
type = "filter_pack"
filter "f":
  applies_to:
    - "output.send"
  detect:
    - "api_key"
  action:
    on_detect = "redact"
    replacement = "[REDACTED]"
`
	for _, tc := range []struct{ name, src string }{{"guard", guardSrc}, {"filter", filterSrc}} {
		f := mustParseAndValidate(t, tc.name+".elu", tc.src, extension.NewRegistry())
		if tc.name == "guard" {
			if _, err := guardrail.Decode(f); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := filter.Decode(f); err != nil {
				t.Fatal(err)
			}
		}
	}
}
