package elu_test

import (
	"testing"

	"github.com/therxwold/elu"
)

func TestRootFacade(t *testing.T) {
	src := `pack "app.security.access" version 1
type = "access_policy"

access "website":
  default = "deny"
`
	f, diags := elu.CheckString("inline.elu", src, true)
	if diags.HasErrors() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if f == nil || f.Type != "access_policy" {
		t.Fatalf("unexpected file: %#v", f)
	}
}

func TestRootFacadeSharedEffectAndCustomRegistry(t *testing.T) {
	var _ elu.Effect = elu.EffectAllow

	src := `pack "custom.stream" version 1
type = "stream_event_policy"

stream_events "main":
  event "x":
    cooldown = "10s"
`
	reg := elu.NewRegistry()
	reg.RegisterValidator("stream_event_policy", func(pack any) error { return nil })
	f, diags := elu.CheckStringWithRegistry("custom.elu", src, reg, true)
	if diags.HasErrors() {
		t.Fatalf("unexpected custom registry diagnostics: %v", diags)
	}
	if f == nil || f.Type != "stream_event_policy" {
		t.Fatalf("unexpected file: %#v", f)
	}
}
