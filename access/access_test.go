package access_test

import (
	"testing"

	"github.com/therxwold/elu/access"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/policy"
)

const accessPolicySrc = `pack "app.security.access" version 1
type = "access_policy"

access "website":
  default = "deny"

  role "guest":
    allow:
      read:
        - "page.public"
        - "blog.post.published"

  role "author":
    allow:
      create:
        - "blog.post"

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

    rule "published_posts_need_approval":
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
      delete:
        - "owner.account"

  never:
    delete:
      - "owner.account"
`

func decodePolicy(t *testing.T) *access.Policy {
	t.Helper()
	f, err := parser.ParseString("access.elu", accessPolicySrc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccessPolicyEvaluation(t *testing.T) {
	p := decodePolicy(t)
	reg := extension.NewRegistry()

	allowDraft := p.Evaluate(access.Request{
		SubjectID: "user_1",
		Roles:     []string{"author"},
		Action:    "update",
		Resource:  "blog.post",
		Context: condition.EvalContext{
			"resource.owner_id": "user_1",
			"resource.status":   "draft",
		},
	}, reg)
	if allowDraft.Effect != policy.EffectAllow {
		t.Fatalf("expected allow, got %s matched=%v", allowDraft.Effect, allowDraft.MatchedRules)
	}

	approvePublished := p.Evaluate(access.Request{
		SubjectID: "user_1",
		Roles:     []string{"author"},
		Action:    "update",
		Resource:  "blog.post",
		Context: condition.EvalContext{
			"resource.owner_id": "user_1",
			"resource.status":   "published",
		},
	}, reg)
	if approvePublished.Effect != policy.EffectApproval {
		t.Fatalf("expected approval, got %s matched=%v", approvePublished.Effect, approvePublished.MatchedRules)
	}

	denyOtherOwner := p.Evaluate(access.Request{
		SubjectID: "user_1",
		Roles:     []string{"author"},
		Action:    "update",
		Resource:  "blog.post",
		Context: condition.EvalContext{
			"resource.owner_id": "user_2",
			"resource.status":   "draft",
		},
	}, reg)
	if denyOtherOwner.Effect != policy.EffectDeny {
		t.Fatalf("expected deny, got %s matched=%v", denyOtherOwner.Effect, denyOtherOwner.MatchedRules)
	}

	neverOwner := p.Evaluate(access.Request{
		SubjectID: "admin_1",
		Roles:     []string{"admin"},
		Action:    "delete",
		Resource:  "owner.account",
	}, reg)
	if neverOwner.Effect != policy.EffectNever {
		t.Fatalf("expected never to override allow, got %s matched=%v", neverOwner.Effect, neverOwner.MatchedRules)
	}
}

func TestInvalidConditionDoesNotBecomeUnconditionalAllow(t *testing.T) {
	src := `pack "app.security.access" version 1
type = "access_policy"

access "site":
  default = "deny"

  role "author":
    rule "bad_when":
      effect = "allow"
      action = "update"
      resource = "blog.post"

      when:
        all:
          - "not an object"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = access.Decode(f)
	if err == nil {
		t.Fatal("expected decode error for invalid condition")
	}
}

func TestExplicitRuleMissingFieldsAreErrors(t *testing.T) {
	tests := []string{
		`rule "missing_action":
      effect = "allow"
      resource = "blog.post"`,
		`rule "missing_resource":
      effect = "allow"
      action = "read"`,
		`rule "bad_effect":
      effect = "alow"
      action = "read"
      resource = "blog.post"`,
	}
	for _, rule := range tests {
		src := "pack \"app.security.access\" version 1\ntype = \"access_policy\"\n\naccess \"site\":\n  role \"admin\":\n    " + rule
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := access.Decode(f); err == nil {
			t.Fatalf("expected decode error for rule:\n%s", rule)
		}
	}
}

func TestDoublestarResourceMatching(t *testing.T) {
	src := `pack "app.security.access" version 1
type = "access_policy"

access "site":
  default = "deny"

  role "dev":
    allow:
      edit:
        - "backend/**/*.go"
        - "docs/**/*.md"
`
	f, err := parser.ParseString("glob.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"backend/main.go", "backend/internal/auth/session.go", "docs/a.md", "docs/x/y.md"} {
		decision := p.Evaluate(access.Request{Roles: []string{"dev"}, Action: "edit", Resource: resource}, extension.NewRegistry())
		if decision.Effect != policy.EffectAllow {
			t.Fatalf("expected allow for %s, got %s", resource, decision.Effect)
		}
	}
}

func TestConditionEvaluationErrorFailsClosed(t *testing.T) {
	src := `pack "app.security.access" version 1
type = "access_policy"

access "site":
  default = "allow"

  role "admin":
    rule "unknown_operator":
      effect = "deny"
      action = "read"
      resource = "secret"

      when:
        all:
          - field = "subject.id"
            op = "custom_missing_operator"
            value = "admin"
`
	f, err := parser.ParseString("failclosed.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	decision := p.Evaluate(access.Request{SubjectID: "admin", Roles: []string{"admin"}, Action: "read", Resource: "secret"}, extension.NewRegistry())
	if decision.Effect != policy.EffectNever {
		t.Fatalf("expected fail-closed never, got %s errors=%v", decision.Effect, decision.Errors)
	}
	if len(decision.Errors) == 0 {
		t.Fatal("expected condition error to be reported")
	}
}

func TestAccessPolicyRejectsUnexpectedTopLevelAndDuplicateRoles(t *testing.T) {
	tests := []string{
		`pack "app.security.access" version 1
type = "access_policy"

access "site":
  default = "deny"

access "other":
  default = "deny"
`,
		`pack "app.security.access" version 1
type = "access_policy"

skill "not_access":
  name = "oops"

access "site":
  default = "deny"
`,
		`pack "app.security.access" version 1
type = "access_policy"

access "site":
  role "admin":
    allow:
      read:
        - "*"

  role "admin":
    allow:
      update:
        - "*"
`,
	}
	for _, src := range tests {
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := access.Decode(f); err == nil {
			t.Fatalf("expected access decode error for:\n%s", src)
		}
	}
}

func TestExplicitRuleRejectsDuplicateFieldsAndUnknownChildren(t *testing.T) {
	tests := []string{
		`rule "dup_effect":
      effect = "allow"
      effect = "deny"
      action = "read"
      resource = "x"`,
		`rule "unknown_block":
      effect = "allow"
      action = "read"
      resource = "x"
      nested "bad":
        value = "x"`,
		`rule "dup_when":
      effect = "allow"
      action = "read"
      resource = "x"
      when:
        all:
          - field = "subject.id"
            op = "eq"
            value = "u"
      when:
        all:
          - field = "subject.id"
            op = "eq"
            value = "u"`,
	}
	for _, rule := range tests {
		src := "pack \"app.security.access\" version 1\ntype = \"access_policy\"\n\naccess \"site\":\n  role \"admin\":\n    " + rule
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := access.Decode(f); err == nil {
			t.Fatalf("expected decode error for rule:\n%s", rule)
		}
	}
}

func TestAccessRolesSectionIsEnforced(t *testing.T) {
	src := `pack "app.security.access" version 1
type = "access_policy"

access "site":
  roles:
    - "guest"

  role "admin":
    allow:
      read:
        - "*"
`
	f, err := parser.ParseString("roles.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Decode(f); err == nil {
		t.Fatal("expected undeclared role to fail")
	}
}

func TestAccessRejectsDuplicateActionSection(t *testing.T) {
	src := `pack "app.security.access" version 1
type = "access_policy"

access "site":
  role "admin":
    allow:
      read:
        - "page.one"
      read:
        - "page.two"
`
	f, err := parser.ParseString("dup.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Decode(f); err == nil {
		t.Fatal("expected duplicate action section to fail")
	}
}

func TestAccessRejectsDuplicateEffectSections(t *testing.T) {
	tests := []string{
		`access "site":
  allow:
    read:
      - "x"
  allow:
    update:
      - "x"`,
		`access "site":
  role "admin":
    allow:
      read:
        - "x"
    allow:
      update:
        - "x"`,
	}
	for _, body := range tests {
		src := "pack \"app.security.access\" version 1\ntype = \"access_policy\"\n\n" + body
		f, err := parser.ParseString("dup.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := access.Decode(f); err == nil {
			t.Fatalf("expected duplicate effect section error for:\n%s", body)
		}
	}
}

func TestAccessEvaluateInjectsRequestFieldsIntoConditions(t *testing.T) {
	src := `pack "app.security.access" version 1
type = "access_policy"

access "site":
  default = "deny"

  role "admin":
    rule "request_context":
      effect = "allow"
      action = "read"
      resource = "blog.post"

      when:
        all:
          - field = "request.action"
            op = "eq"
            value = "read"

          - field = "request.resource"
            op = "eq"
            value = "blog.post"

          - field = "resource.type"
            op = "eq"
            value = "blog.post"
`
	f, err := parser.ParseString("ctx.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(access.Request{Roles: []string{"admin"}, Action: "read", Resource: "blog.post"}, extension.NewRegistry())
	if d.Effect != policy.EffectAllow {
		t.Fatalf("expected allow using injected request fields, got %s matched=%v errors=%v", d.Effect, d.MatchedRules, d.Errors)
	}
}

func TestAccessRejectsWildcardActionPatternsExceptStar(t *testing.T) {
	src := `pack "x.access" version 1
type = "access_policy"

access "site":
  role "admin":
    allow:
      "read*":
        - "*"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Decode(f); err == nil {
		t.Fatal("expected wildcard action pattern to fail")
	}
}

func TestAccessActionMatchingIsExactOrStarOnly(t *testing.T) {
	src := `pack "x.access" version 1
type = "access_policy"

access "site":
  role "admin":
    allow:
      read:
        - "*"
`
	f, err := parser.ParseString("ok.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(access.Request{Roles: []string{"admin"}, Action: "readx", Resource: "page"}, extension.NewRegistry())
	if d.Effect != policy.EffectDeny {
		t.Fatalf("expected readx not to match read, got %s", d.Effect)
	}
}

func TestAccessRejectsQuotedWeirdAction(t *testing.T) {
	src := `pack "app.access" version 1
type = "access_policy"

access "site":
  role "admin":
    allow:
      "read write":
        - "*"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Decode(f); err == nil {
		t.Fatal("expected action with whitespace to fail")
	}
}

func TestAccessDoesNotOverrideNestedResourceType(t *testing.T) {
	p := &access.Policy{Default: policy.EffectDeny, Rules: []access.Rule{{
		Name:      "r",
		Role:      "admin",
		Effect:    policy.EffectAllow,
		Action:    "read",
		Resource:  "blog.post",
		Condition: &condition.Condition{Field: "resource.type", Op: "eq", Value: "special"},
	}}}
	d := p.Evaluate(access.Request{
		Roles:    []string{"admin"},
		Action:   "read",
		Resource: "blog.post",
		Context: condition.EvalContext{
			"resource": map[string]any{"type": "special"},
		},
	}, extension.NewRegistry())
	if d.Effect != policy.EffectAllow {
		t.Fatalf("expected allow, got %s errors=%v", d.Effect, d.Errors)
	}
}
