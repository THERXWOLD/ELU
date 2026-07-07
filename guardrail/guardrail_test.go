package guardrail_test

import (
	"testing"

	"github.com/therxwold/elu/guardrail"
	"github.com/therxwold/elu/parser"
)

func TestDecodeGuardrailPack(t *testing.T) {
	src := `pack "eluuna.guardrails.core" version 1
type = "guardrail_pack"
priority = "critical"

guardrail "no_secret_exposure":
  severity = "critical"
  applies_to:
    - "repo.read"
    - "context.build"
  never:
    - "print secrets"
    - "store secrets in memory"
  on_violation:
    action = "block"
    report = "Secret exposure attempt blocked."

guardrail "no_self_permission_edits":
  severity = "critical"
  never_edit:
    - "policies/guardrails.elu"
  requires_approval:
    edit:
      - "policies/repo.elu"
`
	f, err := parser.ParseString("guard.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := guardrail.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Guardrails) != 2 || p.Priority != "critical" {
		t.Fatalf("unexpected guardrail pack: %+v", p)
	}
}

func TestGuardrailRejectsInvalidSeverity(t *testing.T) {
	src := `pack "x" version 1
type = "guardrail_pack"

guardrail "bad":
  severity = "godmode"
  never:
    - "bad"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guardrail.Decode(f); err == nil {
		t.Fatal("expected invalid severity error")
	}
}

func TestGuardrailRejectsUnknownOnViolationKeysAndValues(t *testing.T) {
	tests := []string{
		`on_violation:
    unknown = "x"`,
		`on_violation:
    action = "totally_fake_action"`,
	}
	for _, body := range tests {
		src := `pack "eluuna.guardrails.core" version 1
type = "guardrail_pack"

guardrail "no_secret_exposure":
  severity = "critical"

  never:
    - "print secrets"

  ` + body + `
`
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guardrail.Decode(f); err == nil {
			t.Fatalf("expected invalid guardrail on_violation to fail:\n%s", src)
		}
	}
}

func TestGuardrailOnViolationRequiresAction(t *testing.T) {
	src := `pack "x.guard" version 1
type = "guardrail_pack"

guardrail "secret":
  severity = "high"
  never:
    - "expose secrets"
  on_violation:
    report = "Secret blocked."
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guardrail.Decode(f); err == nil {
		t.Fatal("expected on_violation without action to fail")
	}
}

func TestCriticalGuardrailRequiresEnforcingAction(t *testing.T) {
	src := `pack "x.guard" version 1
type = "guardrail_pack"

guardrail "secret":
  severity = "critical"
  never:
    - "expose secrets"
  on_violation:
    action = "report"
    report = "Secret blocked."
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guardrail.Decode(f); err == nil {
		t.Fatal("expected critical guardrail report-only action to fail")
	}
}
