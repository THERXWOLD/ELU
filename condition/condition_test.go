package condition_test

import (
	"testing"

	"github.com/therxwold/elu/access"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/policy"
)

func TestConditionMissingAndCustomOperator(t *testing.T) {
	cond := condition.Condition{All: []condition.Condition{{Field: "resource.owner_id", Op: "missing"}}}
	ok, err := condition.Evaluate(cond, condition.EvalContext{"subject.id": "user_1"}, extension.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("expected missing field condition to be true")
	}

	cond = condition.Condition{Field: "request.ip", Op: "within_cidr", Value: "10.0.0.0/8"}
	_, err = condition.Evaluate(cond, condition.EvalContext{"request.ip": "10.1.2.3"}, extension.NewRegistry())
	if err == nil {
		t.Fatalf("expected unknown operator error")
	}

	reg := extension.NewRegistry()
	err = reg.RegisterOperator("within_cidr", func(left any, right any) bool {
		return left == "10.1.2.3" && right == "10.0.0.0/8"
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, err = condition.Evaluate(cond, condition.EvalContext{"request.ip": "10.1.2.3"}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("expected custom operator to pass")
	}
}

func TestNestedContextLookup(t *testing.T) {
	cond := condition.Condition{Field: "resource.owner_id", Op: "eq", Ref: "subject.id"}
	ctx := condition.EvalContext{
		"subject":  map[string]any{"id": "user_1"},
		"resource": map[string]any{"owner_id": "user_1"},
	}
	ok, err := condition.Evaluate(cond, ctx, extension.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected nested lookup condition to pass")
	}
}

func TestConditionValueListAndNot(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "author":
    rule "draft_or_review_not_banned":
      effect = "allow"
      action = "update"
      resource = "blog.post"

      when:
        all:
          - field = "resource.status"
            op = "in"
            value:
              - "draft"
              - "review"
          - not:
              field = "subject.roles"
              op = "contains"
              value = "banned"
`
	f, err := parser.ParseString("condition.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	decision := p.Evaluate(access.Request{
		SubjectID: "u1",
		Roles:     []string{"author"},
		Action:    "update",
		Resource:  "blog.post",
		Context: condition.EvalContext{
			"resource.status": "draft",
		},
	}, extension.NewRegistry())
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected allow, got %s", decision.Effect)
	}
	decision = p.Evaluate(access.Request{
		SubjectID: "u1",
		Roles:     []string{"author", "banned"},
		Action:    "update",
		Resource:  "blog.post",
		Context: condition.EvalContext{
			"resource.status": "draft",
		},
	}, extension.NewRegistry())
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected deny for banned role, got %s", decision.Effect)
	}
}

func TestMalformedConditionShapesAreErrors(t *testing.T) {
	tests := []string{
		`when:
  all:
    - field = "x"
      value = "y"`,
		`when:
  all:
    - field = "x"
      op = "eq"`,
		`when:
  all:
    - field = "x"
      op = "eq"
      value = "y"
      ref = "z"`,
		`when:
  all:
    - field = "x"
      op = "exists"
      value = "y"`,
	}
	for _, when := range tests {
		src := "pack \"x\" version 1\ntype = \"access_policy\"\n\naccess \"site\":\n  role \"r\":\n    rule \"bad\":\n      effect = \"allow\"\n      action = \"read\"\n      resource = \"x\"\n\n      " + when
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		_, err = access.Decode(f)
		if err == nil {
			t.Fatalf("expected condition decode error for:\n%s", when)
		}
	}
}

func TestDuplicateConditionKeysAreErrors(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "r":
    rule "bad":
      effect = "allow"
      action = "read"
      resource = "x"

      when:
        all:
          - field = "subject.id"
            field = "subject.other"
            op = "eq"
            value = "u"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Decode(f); err == nil {
		t.Fatal("expected duplicate condition key error")
	}
}

func TestDuplicateConditionValueKeysAreErrors(t *testing.T) {
	tests := []string{
		`when:
  all:
    - field = "resource.meta"
      op = "eq"
      value:
        a = "first"
        a = "second"`,
		`when:
  all:
    - field = "resource.meta"
      op = "in"
      value:
        - a = "first"
          a = "second"`,
	}
	for _, when := range tests {
		src := "pack \"x\" version 1\ntype = \"access_policy\"\n\naccess \"site\":\n  role \"r\":\n    rule \"bad\":\n      effect = \"allow\"\n      action = \"read\"\n      resource = \"x\"\n\n      " + when
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := access.Decode(f); err == nil {
			t.Fatalf("expected duplicate value key error for:\n%s", when)
		}
	}
}

func TestConditionRejectsDuplicateAllAnyGroups(t *testing.T) {
	tests := []string{
		`when:
  all:
    - field = "resource.status"
      op = "eq"
      value = "draft"
  all:
    - field = "subject.roles"
      op = "contains"
      value = "admin"
`,
		`when:
  any:
    - field = "resource.status"
      op = "eq"
      value = "draft"
  any:
    - field = "subject.roles"
      op = "contains"
      value = "admin"
`,
	}
	for _, when := range tests {
		src := "pack \"x\" version 1\ntype = \"access_policy\"\n\naccess \"site\":\n  role \"r\":\n    rule \"bad\":\n      effect = \"allow\"\n      action = \"read\"\n      resource = \"x\"\n\n      " + when
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := access.Decode(f); err == nil {
			t.Fatalf("expected duplicate condition group to fail for:\n%s", when)
		}
	}
}

func TestConditionRejectsMixedGroupAndLeafShape(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "r":
    rule "bad":
      effect = "allow"
      action = "read"
      resource = "x"

      when:
        all:
          - field = "subject.roles"
            op = "contains"
            value = "admin"
        field = "resource.status"
        op = "eq"
        value = "draft"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Decode(f); err == nil {
		t.Fatal("expected mixed condition group/leaf shape to fail")
	}
}

func TestNilCustomOperatorDoesNotPanic(t *testing.T) {
	reg := extension.NewRegistry()
	err := reg.RegisterOperator("nilop", nil)
	if err == nil {
		t.Fatal("expected error for nil operator registration")
	}
	_, err = condition.Evaluate(condition.Condition{Field: "x", Op: "nilop", Value: "y"}, condition.EvalContext{"x": "z"}, reg)
	if err == nil {
		t.Fatal("expected nil custom operator to be rejected and reported as unknown")
	}
}

func TestConditionRejectsMixedLogicalGroups(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "r":
    rule "bad":
      effect = "allow"
      action = "read"
      resource = "x"

      when:
        all:
          - field = "subject.roles"
            op = "contains"
            value = "admin"
        any:
          - field = "resource.type"
            op = "eq"
            value = "blog.post"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Decode(f); err == nil {
		t.Fatal("expected mixed all/any condition groups to fail")
	}
}

func TestContainsSupportsMapKeys(t *testing.T) {
	cond := condition.Condition{Field: "claims", Op: "contains", Value: "admin"}
	ok, err := condition.Evaluate(cond, condition.EvalContext{"claims": map[string]any{"admin": true}}, extension.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected contains to match map key")
	}
}

func TestCustomOperatorPanicReturnsError(t *testing.T) {
	reg := extension.NewRegistry()
	err := reg.RegisterOperator("boom", func(left any, right any) bool {
		panic("boom")
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = condition.Evaluate(condition.Condition{Field: "x", Op: "boom", Value: "y"}, condition.EvalContext{"x": "z"}, reg)
	if err == nil {
		t.Fatal("expected custom operator panic to be returned as error")
	}
}

func TestManualMalformedConditionIsError(t *testing.T) {
	_, err := condition.Evaluate(condition.Condition{Op: "eq", Value: "x"}, condition.EvalContext{}, extension.NewRegistry())
	if err == nil {
		t.Fatal("expected manually constructed condition without field to fail")
	}
}

func TestNestedLookupSupportsTypedStringMap(t *testing.T) {
	cond := condition.Condition{Field: "resource.owner", Op: "eq", Value: "me"}
	ok, err := condition.Evaluate(cond, condition.EvalContext{"resource": map[string]string{"owner": "me"}}, extension.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected nested typed map lookup to pass")
	}
}

func TestContainsSupportsTypedMapKeys(t *testing.T) {
	cond := condition.Condition{Field: "claims", Op: "contains", Value: "admin"}
	ok, err := condition.Evaluate(cond, condition.EvalContext{"claims": map[string]bool{"admin": true}}, extension.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected contains to match typed map key")
	}
}

func TestConditionShorthandImplicitAll(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "author":
    rule "own_draft":
      effect = "allow"
      action = "update"
      resource = "blog.post"

      when:
        - resource.owner_id eq $subject.id
        - resource.status eq "draft"
`
	f, err := parser.ParseString("shorthand.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	decision := p.Evaluate(access.Request{
		SubjectID: "u1",
		Roles:     []string{"author"},
		Action:    "update",
		Resource:  "blog.post",
		Context: condition.EvalContext{
			"resource.owner_id": "u1",
			"resource.status":   "draft",
		},
	}, extension.NewRegistry())
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected allow, got %s with errors %v", decision.Effect, decision.Errors)
	}
	decision = p.Evaluate(access.Request{
		SubjectID: "u2",
		Roles:     []string{"author"},
		Action:    "update",
		Resource:  "blog.post",
		Context: condition.EvalContext{
			"resource.owner_id": "u1",
			"resource.status":   "draft",
		},
	}, extension.NewRegistry())
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected deny when owner does not match, got %s", decision.Effect)
	}
}

func TestConditionShorthandAnyNotAndInlineList(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "agent":
    rule "medium_or_high_not_secret":
      effect = "allow"
      action = "call"
      resource = "tool"

      when:
        all:
          - task.risk in ["medium", "high"]
          - not args.path ends_with ".pem"
          - file.was_read exists
`
	f, err := parser.ParseString("shorthand.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	decision := p.Evaluate(access.Request{
		SubjectID: "eluuna",
		Roles:     []string{"agent"},
		Action:    "call",
		Resource:  "tool",
		Context: condition.EvalContext{
			"task.risk":     "high",
			"args.path":     "src/main.go",
			"file.was_read": true,
		},
	}, extension.NewRegistry())
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected allow, got %s with errors %v", decision.Effect, decision.Errors)
	}
	decision = p.Evaluate(access.Request{
		SubjectID: "eluuna",
		Roles:     []string{"agent"},
		Action:    "call",
		Resource:  "tool",
		Context: condition.EvalContext{
			"task.risk":     "high",
			"args.path":     "cert.pem",
			"file.was_read": true,
		},
	}, extension.NewRegistry())
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected deny for secret path, got %s", decision.Effect)
	}
}

func TestConditionShorthandAnyGroup(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "agent":
    rule "secret_path":
      effect = "deny"
      action = "read"
      resource = "file"

      when:
        any:
          - args.path contains ".env"
          - args.path ends_with ".pem"
`
	f, err := parser.ParseString("shorthand-any.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := access.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	decision := p.Evaluate(access.Request{
		SubjectID: "eluuna",
		Roles:     []string{"agent"},
		Action:    "read",
		Resource:  "file",
		Context: condition.EvalContext{
			"args.path": "cert.pem",
		},
	}, extension.NewRegistry())
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected explicit deny to match, got %s", decision.Effect)
	}
}

func TestParseConditionExpressionRejectsBadReference(t *testing.T) {
	_, err := condition.ParseExpression("resource.owner_id eq $bad/ref")
	if err == nil {
		t.Fatal("expected bad reference to fail")
	}
}

func TestConditionShorthandCannotMixImplicitAndExplicitGroups(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "r":
    rule "bad":
      effect = "allow"
      action = "read"
      resource = "x"

      when:
        - file.exists eq true
        any:
          - subject.id eq "u1"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Decode(f); err == nil {
		t.Fatal("expected mixing implicit list and any group to fail")
	}
}
