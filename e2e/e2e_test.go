package e2e_test

import (
	"testing"

	elu "github.com/therxwold/elu"
	"github.com/therxwold/elu/access"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/repo"
	"github.com/therxwold/elu/route"
)

func mustParseAndValidate(t *testing.T, name, src string, reg *extension.Registry) *elu.File {
	t.Helper()
	f, diags := elu.CheckStringWithRegistry(name, src, reg, true)
	if diags.HasErrors() {
		t.Fatalf("%s should validate, got diagnostics:\n%s", name, diags.Error())
	}
	return f
}

func TestE2EWebsiteAccessPolicy(t *testing.T) {
	src := `pack "app.security.access" version 1
type = "access_policy"

access "website":
  default = "deny"

  roles:
    - "guest"
    - "author"
    - "admin"

  role "guest":
    allow:
      read:
        - "page.public"
        - "blog.post.published"

  role "author":
    rule "edit_own_draft":
      effect = "allow"
      action = "update"
      resource = "blog.post"
      when:
        all:
          - field = "resource.owner_id"
            op = "eq"
            ref = "subject.id"
          - field = "resource.status"
            op = "eq"
            value = "draft"

    rule "published_requires_approval":
      effect = "approval"
      action = "update"
      resource = "blog.post"
      when:
        all:
          - field = "resource.owner_id"
            op = "eq"
            ref = "subject.id"
          - field = "resource.status"
            op = "eq"
            value = "published"

  role "admin":
    allow:
      read:
        - "*"
    never:
      delete:
        - "owner.account"
`
	reg := extension.NewRegistry()
	f := mustParseAndValidate(t, "access.elu", src, reg)
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		req  access.Request
		want policy.Effect
	}{
		{"guest public read", access.Request{Roles: []string{"guest"}, Action: "read", Resource: "page.public"}, policy.EffectAllow},
		{"author own draft", access.Request{SubjectID: "u1", Roles: []string{"author"}, Action: "update", Resource: "blog.post", Context: condition.EvalContext{"resource": map[string]any{"owner_id": "u1", "status": "draft"}}}, policy.EffectAllow},
		{"author own published", access.Request{SubjectID: "u1", Roles: []string{"author"}, Action: "update", Resource: "blog.post", Context: condition.EvalContext{"resource": map[string]any{"owner_id": "u1", "status": "published"}}}, policy.EffectApproval},
		{"author other draft", access.Request{SubjectID: "u1", Roles: []string{"author"}, Action: "update", Resource: "blog.post", Context: condition.EvalContext{"resource": map[string]any{"owner_id": "u2", "status": "draft"}}}, policy.EffectDeny},
		{"admin cannot delete owner", access.Request{Roles: []string{"admin"}, Action: "delete", Resource: "owner.account"}, policy.EffectNever},
	}
	for _, tc := range cases {
		d := p.Evaluate(tc.req, reg)
		if d.Effect != tc.want {
			t.Fatalf("%s: expected %s got %s matched=%v errors=%v", tc.name, tc.want, d.Effect, d.MatchedRules, d.Errors)
		}
	}
}

func TestE2ERoutePolicyRejectsAmbiguityAndEvaluatesAuth(t *testing.T) {
	bad := `pack "app.security.routes" version 1
type = "route_policy"

routes "website":
  public:
    - method = "GET"
      path = "/admin/**"

  protected:
    - method = "GET"
      path = "/admin/settings"
      require_role = "admin"
`
	if f, err := parser.ParseString("bad-routes.elu", bad); err != nil {
		t.Fatal(err)
	} else if _, err := route.Decode(f); err == nil {
		t.Fatal("expected ambiguous public/protected route policy to fail")
	}

	good := `pack "app.security.routes" version 1
type = "route_policy"

routes "website":
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
    audit = true
`
	reg := extension.NewRegistry()
	f := mustParseAndValidate(t, "routes.elu", good, reg)
	p, err := route.Decode(f)
	if err != nil {
		t.Fatal(err)
	}

	if d := p.Evaluate(route.Request{Method: "GET", Path: "/dashboard"}, reg); d.Effect != policy.EffectDeny {
		t.Fatalf("dashboard without role should deny, got %s", d.Effect)
	}
	if d := p.Evaluate(route.Request{SubjectID: "u1", Method: "GET", Path: "/dashboard", Roles: []string{"user"}}, reg); d.Effect != policy.EffectAllow {
		t.Fatalf("dashboard with role should allow, got %s", d.Effect)
	}
	if d := p.Evaluate(route.Request{SubjectID: "u1", Method: "POST", Path: "/admin/settings", Roles: []string{"admin"}, MFA: true}, reg); d.Effect != policy.EffectApproval || !d.Audit {
		t.Fatalf("admin settings should approval+audit, got %s audit=%v errors=%v", d.Effect, d.Audit, d.Errors)
	}
}

func TestE2ERepoPolicyFailClosed(t *testing.T) {
	src := `pack "repo.security.policy" version 1
type = "repo_policy"

repo "backend":
  default:
    read = "allow"
    edit = "deny"

  allow:
    edit:
      - "docs/**/*.md"

  approval:
    edit:
      - "internal/auth/**"

  never:
    read:
      - ".env*"
    context:
      - ".env*"

  rule "small_patch":
    effect = "allow"
    action = "edit"
    resource = "frontend/**/*.tsx"
    when:
      all:
        - field = "patch.added_lines"
          op = "lte"
          value = 200
`
	reg := extension.NewRegistry()
	f := mustParseAndValidate(t, "repo.elu", src, reg)
	p, err := repo.Decode(f)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		req  repo.Request
		want policy.Effect
	}{
		{"docs edit", repo.Request{Action: "edit", Resource: "docs/intro.md"}, policy.EffectAllow},
		{"auth edit", repo.Request{Action: "edit", Resource: "internal/auth/session.go"}, policy.EffectApproval},
		{"env read", repo.Request{Action: "read", Resource: ".env"}, policy.EffectNever},
		{"small frontend patch", repo.Request{Action: "edit", Resource: "frontend/App.tsx", Context: condition.EvalContext{"patch.added_lines": 20}}, policy.EffectAllow},
		{"large frontend patch", repo.Request{Action: "edit", Resource: "frontend/App.tsx", Context: condition.EvalContext{"patch.added_lines": 500}}, policy.EffectDeny},
	}
	for _, tc := range cases {
		d := p.Evaluate(tc.req, reg)
		if d.Effect != tc.want {
			t.Fatalf("%s: expected %s got %s matched=%v errors=%v", tc.name, tc.want, d.Effect, d.MatchedRules, d.Errors)
		}
	}
}

func TestE2ECustomOperatorPanicFailsClosed(t *testing.T) {
	src := `pack "app.security.access" version 1
type = "access_policy"

access "site":
  default = "deny"

  role "admin":
    rule "custom":
      effect = "allow"
      action = "read"
      resource = "secret"
      when:
        all:
          - field = "request.ip"
            op = "boom"
            value = "127.0.0.1"
`
	reg := extension.NewRegistry()
	reg.RegisterOperator("boom", func(left any, right any) (bool, error) { panic("boom") })
	f := mustParseAndValidate(t, "panic.elu", src, reg)
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(access.Request{Roles: []string{"admin"}, Action: "read", Resource: "secret", Context: condition.EvalContext{"request.ip": "127.0.0.1"}}, reg)
	if d.Effect != policy.EffectNever || len(d.Errors) == 0 {
		t.Fatalf("expected custom operator panic to fail closed to never, got %s errors=%v", d.Effect, d.Errors)
	}
}
