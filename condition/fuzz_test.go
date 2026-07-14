package condition_test

import (
	"testing"

	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
)

func FuzzEvaluateCondition(f *testing.F) {
	f.Add("subject.roles", "contains", "admin")
	f.Add("resource.status", "eq", "draft")
	f.Add("file.path", "matches", "docs/**/*.md")
	reg := extension.NewRegistry()
	ctx := condition.EvalContext{
		"subject":   map[string]any{"roles": []string{"admin"}, "id": "u1"},
		"resource":  map[string]any{"status": "draft", "owner_id": "u1"},
		"file.path": "docs/readme.md",
	}
	f.Fuzz(func(t *testing.T, field, op, val string) {
		cond := condition.Condition{Field: field, Op: op, Value: val}
		_, _ = condition.Evaluate(cond, ctx, reg)
	})
}

func FuzzParseExpression(f *testing.F) {
	seeds := []string{
		"file.exists eq false",
		"resource.status eq 'deleted'",
		"not subject.roles contains admin",
		"file.path matches docs/**/*.md",
		"resource.owner_id eq $subject.id",
		"file.size gt 1024",
		"not file.hidden exists",
		"",
		"   ",
		"only_one_token",
		"field op value extra",
		"not not nested",
		`"quoted field" eq "value"`,
		"field in [a, b, c]",
		"field contains 'hello world'",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, expr string) {
		_, _ = condition.ParseExpression(expr)
	})
}
