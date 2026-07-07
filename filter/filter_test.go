package filter_test

import (
	"testing"

	"github.com/therxwold/elu/filter"
	"github.com/therxwold/elu/parser"
)

func TestDecodeFilterPack(t *testing.T) {
	src := `pack "eluuna.filters.core" version 1
type = "filter_pack"

filter "secret_detector":
  applies_to:
    - "file.read"
    - "output.send"
  detect:
    - "api_key"
    - "private_key"
  action:
    on_detect = "redact"
    replacement = "[REDACTED_SECRET]"

filter "protected_paths":
  applies_to:
    - "repo.patch"
  block_paths:
    - ".env*"
    - "**/*.key"
  action:
    on_match = "deny"
`
	f, err := parser.ParseString("filters.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := filter.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Filters) != 2 || p.Filters[0].Action["on_detect"] != "redact" {
		t.Fatalf("unexpected filter pack: %+v", p)
	}
}

func TestFilterRejectsMissingAction(t *testing.T) {
	src := `pack "x" version 1
type = "filter_pack"

filter "bad":
  applies_to:
    - "output.send"
  detect:
    - "email"
`
	f, err := parser.ParseString("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := filter.Decode(f); err == nil {
		t.Fatal("expected missing action error")
	}
}

func TestFilterRejectsUnknownActionKeysAndValues(t *testing.T) {
	tests := []string{
		`action:
    totally_fake_key = "block"`,
		`action:
    on_detect = "totally_fake_action"`,
		`escalate:
    unknown = "x"`,
		`escalate:
    action = "totally_fake_action"`,
	}
	for _, body := range tests {
		src := `pack "eluuna.filters.core" version 1
type = "filter_pack"

filter "secret_detector":
  applies_to:
    - "output.send"

  detect:
    - "api_key"

  ` + body + `
`
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := filter.Decode(f); err == nil {
			t.Fatalf("expected invalid filter action map to fail:\n%s", src)
		}
	}
}

func TestFilterRejectsMismatchedOrIncompleteActions(t *testing.T) {
	tests := []string{
		`filter "detect_without_action":
  applies_to:
    - "output.send"
  detect:
    - "api_key"
  action:
    replacement = "[REDACTED]"`,
		`filter "block_paths_wrong_action":
  applies_to:
    - "repo.patch"
  block_paths:
    - ".env*"
  action:
    on_detect = "redact"`,
		`filter "detect_change_wrong_action":
  applies_to:
    - "repo.patch"
  detect_change:
    - "removes authentication check"
  action:
    on_detect = "report"`,
		`filter "incomplete_escalate":
  applies_to:
    - "output.send"
  detect:
    - "api_key"
  action:
    on_detect = "redact"
  escalate:
    when = "secret appears in output"`,
	}
	for _, body := range tests {
		src := "pack \"x.filter\" version 1\ntype = \"filter_pack\"\n\n" + body + "\n"
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := filter.Decode(f); err == nil {
			t.Fatalf("expected filter validation to fail:\n%s", src)
		}
	}
}

func TestFilterRejectsDetectorSpecificInvalidActionValues(t *testing.T) {
	tests := []string{
		`filter "paths_redact":
  applies_to:
    - "repo.patch"
  block_paths:
    - ".env*"
  action:
    on_match = "redact"`,
		`filter "change_redact":
  applies_to:
    - "repo.patch"
  detect_change:
    - "removes auth check"
  action:
    on_change_detect = "redact"`,
		`filter "replacement_without_redaction":
  applies_to:
    - "repo.patch"
  block_paths:
    - ".env*"
  action:
    on_match = "deny"
    replacement = "[REDACTED]"`,
	}
	for _, body := range tests {
		src := "pack \"x.filter\" version 1\ntype = \"filter_pack\"\n\n" + body + "\n"
		f, err := parser.ParseString("bad.elu", src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := filter.Decode(f); err == nil {
			t.Fatalf("expected filter validation to fail:\n%s", src)
		}
	}
}
