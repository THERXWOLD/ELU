package repo_test

import (
	"testing"

	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/repo"
)

const repoPolicySrc = `pack "therxwold.repo.policy" version 1
type = "repo_policy"

repo "THERXWOLD":
  default:
    read = "allow"
    edit = "deny"
    context = "deny"

  allow:
    edit:
      - "docs/**/*.md"
      - "frontend/src/**/*.tsx"

  propose:
    edit:
      - "backend/**/*.go"

  approval:
    edit:
      - "backend/internal/auth/**"

  never:
    read:
      - ".env*"
    edit:
      - ".env*"

  rule "small_frontend_patch":
    effect = "allow"
    action = "edit"
    resource = "frontend/src/**/*.tsx"

    when:
      all:
        - field = "patch.added_lines"
          op = "lt"
          value = 200
`

func decodeRepo(t *testing.T) *repo.Policy {
	t.Helper()
	f, err := parser.ParseString("repo.elu", repoPolicySrc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := repo.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRepoPolicyEvaluation(t *testing.T) {
	p := decodeRepo(t)
	reg := extension.NewRegistry()
	cases := []struct {
		action, path string
		ctx          condition.EvalContext
		want         policy.Effect
	}{
		{"read", "README.md", nil, policy.EffectAllow},
		{"edit", "docs/a.md", nil, policy.EffectAllow},
		{"edit", "backend/main.go", nil, policy.EffectPropose},
		{"edit", "backend/internal/auth/session.go", nil, policy.EffectApproval},
		{"edit", ".env", nil, policy.EffectNever},
		{"read", ".env", nil, policy.EffectNever},
		{"edit", "frontend/src/App.tsx", condition.EvalContext{"patch.added_lines": int64(100)}, policy.EffectAllow},
		{"edit", "frontend/src/App.tsx", condition.EvalContext{"patch.added_lines": int64(250)}, policy.EffectAllow},
	}
	for _, tc := range cases {
		d := p.Evaluate(repo.Request{Action: tc.action, Resource: tc.path, Context: tc.ctx}, reg)
		if d.Effect != tc.want {
			t.Fatalf("%s %s expected %s got %s matched=%v errors=%v", tc.action, tc.path, tc.want, d.Effect, d.MatchedRules, d.Errors)
		}
	}
}

func TestRepoRejectsInvalidConditionAndEffect(t *testing.T) {
	src := `pack "repo.x" version 1
type = "repo_policy"

repo "x":
  rule "bad":
    effect = "alow"
    action = "edit"
    resource = "**"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Decode(f); err == nil {
		t.Fatal("expected bad effect error")
	}

	src = `pack "repo.x" version 1
type = "repo_policy"

repo "x":
  rule "bad":
    effect = "allow"
    action = "edit"
    resource = "**"

    when:
      all:
        - "bad"
`
	f, err = parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Decode(f); err == nil {
		t.Fatal("expected invalid condition error")
	}
}

func TestRepoCustomOperatorValidatedWithRegistry(t *testing.T) {
	src := `pack "repo.x" version 1
type = "repo_policy"

repo "x":
  rule "custom":
    effect = "allow"
    action = "edit"
    resource = "**"

    when:
      all:
        - field = "patch.risk"
          op = "risk_below"
          value = "medium"
`
	f, err := parser.ParseString("custom.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := repo.Decode(f)
	if err != nil {
		t.Fatalf("decode should not reject custom operator before registry validation: %v", err)
	}
	if err := repo.ValidatePolicy(p, extension.NewRegistry()); err == nil {
		t.Fatal("expected validation error without custom operator")
	}
	reg := extension.NewRegistry()
	reg.RegisterOperator("risk_below", func(left, right any) bool { return left == "low" && right == "medium" })
	if err := repo.ValidatePolicy(p, reg); err != nil {
		t.Fatalf("expected validation with registered operator: %v", err)
	}
	d := p.Evaluate(repo.Request{Action: "edit", Resource: "main.go", Context: condition.EvalContext{"patch.risk": "low"}}, reg)
	if d.Effect != policy.EffectAllow {
		t.Fatalf("expected allow, got %s errors=%v", d.Effect, d.Errors)
	}
}

func TestRepoRejectsDuplicateActionSection(t *testing.T) {
	src := `pack "repo.x" version 1
type = "repo_policy"

repo "x":
  allow:
    edit:
      - "docs/**/*.md"
    edit:
      - "frontend/**/*.tsx"
`
	f, err := parser.ParseString("dup.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Decode(f); err == nil {
		t.Fatal("expected duplicate action section to fail")
	}
}

func TestRepoConditionErrorFailsClosedNever(t *testing.T) {
	src := `pack "repo.x" version 1
type = "repo_policy"

repo "x":
  default:
    read = "allow"
  rule "custom":
    effect = "allow"
    action = "read"
    resource = "**"
    when:
      all:
        - field = "file.path"
          op = "missing_custom_operator"
          value = "README.md"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := repo.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(repo.Request{Action: "read", Resource: "README.md"}, extension.NewRegistry())
	if d.Effect != policy.EffectNever || len(d.Errors) == 0 {
		t.Fatalf("expected never with error, got %s errors=%v", d.Effect, d.Errors)
	}
}

func TestRepoEvaluateDoesNotOverwriteNestedResourceContext(t *testing.T) {
	src := `pack "repo.x" version 1
type = "repo_policy"

repo "x":
  default:
    edit = "deny"

  rule "owner_only":
    effect = "allow"
    action = "edit"
    resource = "docs/**/*.md"

    when:
      all:
        - field = "resource.owner"
          op = "eq"
          value = "me"

        - field = "file.path"
          op = "matches"
          value = "docs/**/*.md"
`
	f, err := parser.ParseString("repo.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := repo.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(repo.Request{
		Action:   "edit",
		Resource: "docs/a.md",
		Context: condition.EvalContext{
			"resource": map[string]any{"owner": "me"},
		},
	}, extension.NewRegistry())
	if d.Effect != policy.EffectAllow {
		t.Fatalf("expected allow without overwriting nested resource context, got %s matched=%v errors=%v", d.Effect, d.MatchedRules, d.Errors)
	}
}

func TestRepoRejectsWildcardActionPatternsExceptStar(t *testing.T) {
	src := `pack "x.repo" version 1
type = "repo_policy"

repo "x":
  allow:
    "read*":
      - "**"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Decode(f); err == nil {
		t.Fatal("expected wildcard action pattern to fail")
	}
}

func TestRepoActionMatchingIsExactOrStarOnly(t *testing.T) {
	src := `pack "x.repo" version 1
type = "repo_policy"

repo "x":
  default:
    readx = "deny"
  allow:
    read:
      - "**"
`
	f, err := parser.ParseString("ok.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := repo.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(repo.Request{Action: "readx", Resource: "README.md"}, extension.NewRegistry())
	if d.Effect != policy.EffectDeny {
		t.Fatalf("expected readx not to match read, got %s", d.Effect)
	}
}

func TestRepoRejectsQuotedWeirdAction(t *testing.T) {
	src := `pack "repo.policy" version 1
type = "repo_policy"

repo "app":
  allow:
    "read write":
      - "*"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Decode(f); err == nil {
		t.Fatal("expected action with whitespace to fail")
	}
}
