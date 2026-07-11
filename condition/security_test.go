package condition_test

import (
	"testing"

	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
)

func TestEvaluateStrictRejectsMissingField(t *testing.T) {
	cond := condition.Condition{Field: "resource.classification", Op: "eq", Value: "secret"}

	ok, err := condition.Evaluate(cond, nil, extension.NewRegistry())
	if err != nil || ok {
		t.Fatalf("legacy evaluation should return false without error; ok=%v err=%v", ok, err)
	}

	if _, err := condition.EvaluateStrict(cond, nil, extension.NewRegistry()); err == nil {
		t.Fatal("strict evaluation must reject a missing field")
	}
}

func TestEvaluateStrictRejectsMissingReference(t *testing.T) {
	cond := condition.Condition{Field: "resource.owner_id", Op: "eq", Ref: "subject.id"}
	ctx := condition.EvalContext{"resource.owner_id": "u1"}

	if _, err := condition.EvaluateStrict(cond, ctx, extension.NewRegistry()); err == nil {
		t.Fatal("strict evaluation must reject a missing reference")
	}
}

func TestEvaluateStrictRejectsTypeMismatch(t *testing.T) {
	tests := []condition.Condition{
		{Field: "resource.status", Op: "starts_with", Value: "draft"},
		{Field: "resource.count", Op: "gt", Value: int64(2)},
		{Field: "resource.status", Op: "eq", Value: "draft"},
		{Field: "resource.tags", Op: "contains", Value: "safe"},
	}
	contexts := []condition.EvalContext{
		{"resource.status": 7},
		{"resource.count": "three"},
		{"resource.status": true},
		{"resource.tags": 42},
	}

	for i, cond := range tests {
		if _, err := condition.EvaluateStrict(cond, contexts[i], extension.NewRegistry()); err == nil {
			t.Fatalf("case %d: expected type mismatch error", i)
		}
	}
}

func TestEvaluateStrictKeepsExistsAndMissingSemantics(t *testing.T) {
	ctx := condition.EvalContext{"subject.id": "u1"}

	ok, err := condition.EvaluateStrict(condition.Condition{Field: "subject.id", Op: "exists"}, ctx, nil)
	if err != nil || !ok {
		t.Fatalf("exists failed: ok=%v err=%v", ok, err)
	}

	ok, err = condition.EvaluateStrict(condition.Condition{Field: "subject.email", Op: "missing"}, ctx, nil)
	if err != nil || !ok {
		t.Fatalf("missing failed: ok=%v err=%v", ok, err)
	}
}
