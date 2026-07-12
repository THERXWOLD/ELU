package validate_test

import (
	"fmt"
	"testing"

	"github.com/therxwold/elu/diag"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/validate"
)

func TestStrictUnknownPackType(t *testing.T) {
	src := `pack "custom.stream.events" version 1
type = "stream_event_policy"

stream_events "main":
  event "new_follower":
    cooldown = "10s"
`
	f, err := parser.ParseString("stream.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	diags := validate.File(f, extension.NewRegistry(), false)
	if diags.HasErrors() {
		t.Fatalf("permissive mode should not error: %v", diags)
	}
	if len(diags) == 0 || diags[0].Severity != diag.Warning {
		t.Fatalf("expected warning in permissive mode, got %v", diags)
	}

	diags = validate.File(f, extension.NewRegistry(), true)
	if !diags.HasErrors() {
		t.Fatalf("strict mode should error")
	}

	reg := extension.NewRegistry()
	err = reg.RegisterValidator("stream_event_policy", func(pack any) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	diags = validate.File(f, reg, true)
	if diags.HasErrors() {
		t.Fatalf("registered custom pack with validator should pass strict mode: %v", diags)
	}
}

func TestBuiltInPackTypesValidate(t *testing.T) {
	samples := map[string]string{
		"access_policy": `pack "x.access" version 1
type = "access_policy"

access "site":
  default = "deny"
  role "guest":
    allow:
      read:
        - "page.public"
`,
		"route_policy": `pack "x.routes" version 1
type = "route_policy"

routes "site":
  default = "deny"
  public:
    - method = "GET"
      path = "/"
`,
		"repo_policy": `pack "x.repo" version 1
type = "repo_policy"

repo "x":
  default:
    read = "allow"
    edit = "deny"
`,
		"skill_pack": `pack "x.skill" version 1
type = "skill_pack"

skill "x":
  category = "engineering"
  risk = "medium"
  steps:
    - "do thing"
`,
		"guardrail_pack": `pack "x.guard" version 1
type = "guardrail_pack"

guardrail "x":
  severity = "high"
  never:
    - "do bad thing"
`,
		"filter_pack": `pack "x.filter" version 1
type = "filter_pack"

filter "x":
  applies_to:
    - "output.send"
  detect:
    - "secret"
  action:
    on_detect = "block"
`,
	}
	for name, src := range samples {
		f, err := parser.ParseString(name+".elu", src)
		if err != nil {
			t.Fatalf("%s parse: %v", name, err)
		}
		diags := validate.File(f, extension.NewRegistry(), true)
		if diags.HasErrors() {
			t.Fatalf("%s should validate, got %v", name, diags)
		}
	}
}

func TestCustomValidatorIsCalled(t *testing.T) {
	src := `pack "custom.stream" version 1
type = "stream_event_policy"

stream_events "main":
  event "x":
    cooldown = "10s"
`
	f, err := parser.ParseString("stream.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	reg := extension.NewRegistry()
	err = reg.RegisterValidator("stream_event_policy", func(pack any) error {
		return fmt.Errorf("custom validation failed")
	})
	if err != nil {
		t.Fatal(err)
	}
	diags := validate.File(f, reg, true)
	if !diags.HasErrors() {
		t.Fatalf("expected custom validator error")
	}
}

func TestStrictRegisteredCustomPackRequiresValidator(t *testing.T) {
	src := `pack "custom.stream.events" version 1
type = "stream_event_policy"

stream_events "main":
  event "new_follower":
    cooldown = "10s"
`
	f, err := parser.ParseString("custom.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	reg := extension.NewRegistry()
	err = reg.RegisterPackType("stream_event_policy")
	if err != nil {
		t.Fatal(err)
	}
	if diags := validate.File(f, reg, true); !diags.HasErrors() {
		t.Fatal("expected strict mode to reject registered custom pack without validator")
	}
	err = reg.RegisterValidator("stream_event_policy", func(pack any) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if diags := validate.File(f, reg, true); diags.HasErrors() {
		t.Fatalf("expected strict mode to accept custom pack with validator, got %v", diags)
	}
}

func TestNilCustomValidatorDoesNotPanic(t *testing.T) {
	src := `pack "custom.stream.events" version 1
type = "stream_event_policy"

stream_events "main":
  event "new_follower":
    cooldown = "10s"
`
	f, err := parser.ParseString("custom.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	reg := extension.NewRegistry()
	err = reg.RegisterValidator("stream_event_policy", nil)
	if err == nil {
		t.Fatal("expected error for nil validator registration")
	}
	if diags := validate.File(f, reg, true); !diags.HasErrors() {
		t.Fatal("expected strict mode to reject custom pack registered with nil validator")
	}
}

func TestCustomValidatorPanicBecomesDiagnostic(t *testing.T) {
	src := `pack "custom.stream" version 1
type = "stream_event_policy"

stream_events "main":
  event "x":
    cooldown = "10s"
`
	f, err := parser.ParseString("stream.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	reg := extension.NewRegistry()
	err = reg.RegisterValidator("stream_event_policy", func(pack any) error {
		panic("boom")
	})
	if err != nil {
		t.Fatal(err)
	}
	diags := validate.File(f, reg, true)
	if !diags.HasErrors() {
		t.Fatal("expected validator panic to become diagnostic")
	}
}

func TestRegisterEmptyPackTypeIgnored(t *testing.T) {
	reg := extension.NewRegistry()
	err := reg.RegisterPackType("")
	if err == nil {
		t.Fatal("expected error for empty pack type registration")
	}
	if reg.HasPackType("") {
		t.Fatal("empty pack type should not be in registry")
	}
}
