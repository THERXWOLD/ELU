package access_test

import (
	"testing"

	"github.com/therxwold/elu/access"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/policy"
)

func TestAccessMissingConditionDataFailsClosed(t *testing.T) {
	cond := condition.Condition{Field: "resource.owner_id", Op: "eq", Ref: "subject.id"}
	p := &access.Policy{
		Default: policy.EffectAllow,
		Rules: []access.Rule{{
			Name:      "own-document",
			Effect:    policy.EffectAllow,
			Action:    "read",
			Resource:  "document",
			Condition: &cond,
		}},
	}

	d := p.Evaluate(access.Request{
		SubjectID: "u1",
		Action:    "read",
		Resource:  "document",
	}, extension.NewRegistry())
	if d.Effect != policy.EffectNever || len(d.Errors) == 0 {
		t.Fatalf("expected never with error, got %s errors=%v", d.Effect, d.Errors)
	}
}
