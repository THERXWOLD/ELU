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
