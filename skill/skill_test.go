package skill_test

import (
	"testing"

	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/skill"
)

func TestDecodeSkillPack(t *testing.T) {
	src := `pack "eluuna.skill.implement_small_feature" version 1
type = "skill_pack"

skill "implement_small_feature":
  title = "Implement Small Feature"
  category = "engineering"
  risk = "high"

  uses:
    tools:
      - "repo.search"
      - "repo.read"
    policies:
      - "therxwold.repo.policy"

  allowed_targets:
    - "docs"
    - "frontend"
  propose_only_targets:
    - "backend"
  forbidden_targets:
    - "secrets"
  steps:
    - "understand request"
    - "read relevant files"
  done_when:
    - "patch is minimal"
`
	f, err := parser.ParseString("skill.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := skill.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Skill.ID != "implement_small_feature" || p.Skill.Risk != "high" || len(p.Skill.Uses.Tools) != 2 {
		t.Fatalf("unexpected skill decode: %+v", p.Skill)
	}
}

func TestSkillRejectsOverlapAndBadRisk(t *testing.T) {
	tests := []string{
		`pack "x" version 1
type = "skill_pack"

skill "bad":
  category = "engineering"
  risk = "godmode"
  steps:
    - "do"
`,
		`pack "x" version 1
type = "skill_pack"

skill "bad":
  category = "engineering"
  risk = "high"
  allowed_targets:
    - "backend"
  forbidden_targets:
    - "backend"
  steps:
    - "do"
  done_when:
    - "done"
`,
	}
	for _, src := range tests {
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := skill.Decode(f); err == nil {
			t.Fatalf("expected decode error for:\n%s", src)
		}
	}
}

func TestSkillRejectsAllTargetOverlaps(t *testing.T) {
	tests := []string{
		`allowed_targets:
    - "backend"
  propose_only_targets:
    - "backend"`,
		`allowed_targets:
    - "backend"
  approval_targets:
    - "backend"`,
		`propose_only_targets:
    - "backend"
  approval_targets:
    - "backend"`,
		`approval_targets:
    - "backend"
  forbidden_targets:
    - "backend"`,
	}
	for _, targets := range tests {
		src := `pack "x" version 1
type = "skill_pack"

skill "bad":
  category = "engineering"
  risk = "high"
  ` + targets + `
  steps:
    - "do"
  done_when:
    - "done"
`
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := skill.Decode(f); err == nil {
			t.Fatalf("expected target overlap error for:\n%s", targets)
		}
	}
}
