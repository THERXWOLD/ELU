package repo_test

import (
	"testing"

	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/repo"
)

func TestRepoMissingConditionDataFailsClosed(t *testing.T) {
	cond := condition.Condition{Field: "change.approved", Op: "eq", Value: true}
	p := &repo.Policy{
		Default: map[string]policy.Effect{"write": policy.EffectAllow},
		Rules: []repo.Rule{{
			Name:      "approved-write",
			Effect:    policy.EffectAllow,
			Action:    "write",
			Resource:  "src/**",
			Condition: &cond,
		}},
	}

	d := p.Evaluate(repo.Request{Action: "write", Resource: "src/main.go"}, extension.NewRegistry())
	if d.Effect != policy.EffectNever || len(d.Errors) == 0 {
		t.Fatalf("expected never with error, got %s errors=%v", d.Effect, d.Errors)
	}
}
