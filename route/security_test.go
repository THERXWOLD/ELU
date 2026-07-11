package route_test

import (
	"testing"

	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/route"
)

func TestProtectedRouteDoesNotFallThroughToAllowDefault(t *testing.T) {
	p := &route.Policy{
		Default: policy.EffectAllow,
		Routes: []route.Route{{
			Name:        "admin",
			Effect:      policy.EffectAllow,
			Method:      "GET",
			Path:        "/admin",
			RequireRole: "admin",
		}},
	}

	d := p.Evaluate(route.Request{Method: "GET", Path: "/admin"}, extension.NewRegistry())
	if d.Effect != policy.EffectDeny {
		t.Fatalf("expected deny, got %s matched=%v errors=%v", d.Effect, d.MatchedRoutes, d.Errors)
	}
}

func TestProtectedRouteMFADoesNotFallThroughToAllowDefault(t *testing.T) {
	p := &route.Policy{
		Default: policy.EffectAllow,
		Routes: []route.Route{{
			Name:        "admin",
			Effect:      policy.EffectAllow,
			Method:      "POST",
			Path:        "/admin/settings",
			RequireRole: "admin",
			Require2FA:  true,
			Audit:       true,
		}},
	}

	d := p.Evaluate(route.Request{
		Method: "POST",
		Path:   "/admin/settings",
		Roles:  []string{"admin"},
	}, extension.NewRegistry())
	if d.Effect != policy.EffectDeny || !d.Audit {
		t.Fatalf("expected audited deny, got %s audit=%v", d.Effect, d.Audit)
	}
}

func TestProtectedRouteConditionFailureDenies(t *testing.T) {
	cond := condition.Condition{Field: "tenant.id", Op: "eq", Value: "allowed"}
	p := &route.Policy{
		Default: policy.EffectAllow,
		Routes: []route.Route{{
			Name:        "tenant-admin",
			Effect:      policy.EffectAllow,
			Method:      "GET",
			Path:        "/admin",
			RequireRole: "admin",
			Condition:   &cond,
		}},
	}

	d := p.Evaluate(route.Request{
		Method:  "GET",
		Path:    "/admin",
		Roles:   []string{"admin"},
		Context: condition.EvalContext{"tenant.id": "other"},
	}, extension.NewRegistry())
	if d.Effect != policy.EffectDeny {
		t.Fatalf("expected deny, got %s", d.Effect)
	}
}

func TestRouteMissingConditionDataFailsClosed(t *testing.T) {
	cond := condition.Condition{Field: "tenant.id", Op: "eq", Value: "allowed"}
	p := &route.Policy{
		Default: policy.EffectAllow,
		Routes: []route.Route{{
			Name:        "tenant-admin",
			Effect:      policy.EffectAllow,
			Method:      "GET",
			Path:        "/admin",
			RequireRole: "admin",
			Condition:   &cond,
		}},
	}

	d := p.Evaluate(route.Request{
		Method: "GET",
		Path:   "/admin",
		Roles:  []string{"admin"},
	}, extension.NewRegistry())
	if d.Effect != policy.EffectNever || len(d.Errors) == 0 {
		t.Fatalf("expected never with an error, got %s errors=%v", d.Effect, d.Errors)
	}
}
