// ELU Policy DSL — the tiny, embeddable policy language that started as a wild idea.
//
// Credits:
//
//	Technical Design: Naru K
//	Implementation:  AIRI
//	Special thanks to ChatGPT-chan for keeping us out of rabbit holes and fixing
//	the bugs we swore weren't ours.
package elu

import (
	"github.com/therxwold/elu/access"
	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/diag"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/filter"
	"github.com/therxwold/elu/format"
	"github.com/therxwold/elu/guardrail"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/repo"
	"github.com/therxwold/elu/route"
	"github.com/therxwold/elu/skill"
	"github.com/therxwold/elu/validate"
)

// Facade exports — the most common types from subpackages, re-exported so you
// don't have to remember six different import paths. You're welcome.

// File is a parsed ELU document. Type alias for ast.File.
type File = ast.File

// Node is a generic AST element. Type alias for ast.Node.
type Node = ast.Node

// Diagnostic points at something suspicious in your policy. Type alias for diag.Diagnostic.
type Diagnostic = diag.Diagnostic

// Diagnostics is a list of Diagnostic that also implements error. Type alias for diag.Diagnostics.
type Diagnostics = diag.Diagnostics

// Registry manages condition extensions. Type alias for extension.Registry.
type Registry = extension.Registry

// Condition evaluates yes/no questions about a request. Type alias for condition.Condition.
type Condition = condition.Condition

// EvalContext carries everything a Condition needs to make up its mind. Type alias for condition.EvalContext.
type EvalContext = condition.EvalContext

// AccessPolicy is a decoded access control policy. Type alias for access.Policy.
type AccessPolicy = access.Policy

// AccessRequest is what you ask when checking access. Type alias for access.Request.
type AccessRequest = access.Request

// AccessDecision is what you get back — allow, deny, etc. Type alias for access.Decision.
type AccessDecision = access.Decision

// Effect is the decision a policy reaches. Type alias for policy.Effect.
type Effect = policy.Effect

// SkillPack is a decoded skill package. Type alias for skill.Pack.
type SkillPack = skill.Pack

// RepoPolicy is a decoded repository policy. Type alias for repo.Policy.
type RepoPolicy = repo.Policy

// RepoRequest is what you ask when checking repo rules. Type alias for repo.Request.
type RepoRequest = repo.Request

// RepoDecision is what the repo policy decided. Type alias for repo.Decision.
type RepoDecision = repo.Decision

// RoutePolicy is a decoded routing policy. Type alias for route.Policy.
type RoutePolicy = route.Policy

// RouteRequest is what you ask when routing. Type alias for route.Request.
type RouteRequest = route.Request

// RouteDecision is where the request should go. Type alias for route.Decision.
type RouteDecision = route.Decision

// GuardrailPack is a decoded guardrail package. Type alias for guardrail.Pack.
type GuardrailPack = guardrail.Pack

// FilterPack is a decoded filter package. Type alias for filter.Pack.
type FilterPack = filter.Pack

const (
	// Error severity — hard failure.
	Error = diag.Error
	// Warning severity — advisory, look at this when you have time.
	Warning = diag.Warning

	// EffectAllow — let it through, no questions asked.
	EffectAllow = policy.EffectAllow
	// EffectPropose — suggest it, but someone needs to approve.
	EffectPropose = policy.EffectPropose
	// EffectApproval — requires explicit approval before proceeding.
	EffectApproval = policy.EffectApproval
	// EffectDeny — shut it down, this isn't happening.
	EffectDeny = policy.EffectDeny
	// EffectNever — not now, not ever. Stronger than deny.
	EffectNever = policy.EffectNever
)

// NewRegistry creates a fresh extension registry. No extensions, just potential.
func NewRegistry() *extension.Registry { return extension.NewRegistry() }

// ParseFile reads an ELU file from disk and parses it into an AST.
func ParseFile(path string) (*ast.File, error) { return parser.ParseFile(path) }

// ParseString parses ELU source text (from a string) into an AST.
// Path is used for error messages — it doesn't have to be a real file.
func ParseString(path, src string) (*ast.File, error) { return parser.ParseString(path, src) }

// DecodeAccessPolicy decodes a parsed ELU file into an AccessPolicy.
func DecodeAccessPolicy(f *ast.File) (*access.Policy, error) { return access.Decode(f) }

// DecodeSkillPack decodes a parsed ELU file into a SkillPack.
func DecodeSkillPack(f *ast.File) (*skill.Pack, error) { return skill.Decode(f) }

// DecodeRepoPolicy decodes a parsed ELU file into a RepoPolicy.
func DecodeRepoPolicy(f *ast.File) (*repo.Policy, error) { return repo.Decode(f) }

// DecodeRoutePolicy decodes a parsed ELU file into a RoutePolicy.
func DecodeRoutePolicy(f *ast.File) (*route.Policy, error) { return route.Decode(f) }

// DecodeGuardrailPack decodes a parsed ELU file into a GuardrailPack.
func DecodeGuardrailPack(f *ast.File) (*guardrail.Pack, error) {
	return guardrail.Decode(f)
}

// DecodeFilterPack decodes a parsed ELU file into a FilterPack.
func DecodeFilterPack(f *ast.File) (*filter.Pack, error) { return filter.Decode(f) }

// ValidateFile runs validation on a parsed ELU file with the given registry.
// Strict mode enables additional checks that production environments want.
func ValidateFile(f *ast.File, reg *extension.Registry, strict bool) diag.Diagnostics {
	return validate.File(f, reg, strict)
}

// ValidateProductionFile validates a parsed ELU file with strict production rules.
// Shortcut for ValidateFile with strict=true, because production Doesn't Play.
func ValidateProductionFile(f *ast.File, reg *extension.Registry) diag.Diagnostics {
	return validate.ProductionFile(f, reg)
}

// FormatString formats ELU source text and returns the pretty version.
func FormatString(path, src string) (string, error) { return format.String(path, src) }

// FormatFile formats a parsed ELU AST back into readable text.
func FormatFile(f *ast.File) string { return format.File(f) }

// EvaluateCondition evaluates a condition against a context and registry.
// Returns true if the condition passes, false otherwise.
func EvaluateCondition(cond condition.Condition, ctx condition.EvalContext, reg *extension.Registry) (bool, error) {
	return condition.Evaluate(cond, ctx, reg)
}

// CheckString parses and validates ELU source in one shot. Convenience wrapper
// that uses a fresh registry and the given strictness. Returns the parsed file
// and any diagnostics.
func CheckString(path, src string, strict bool) (*ast.File, diag.Diagnostics) {
	return CheckStringWithRegistry(path, src, extension.NewRegistry(), strict)
}

// CheckStringWithRegistry parses and validates ELU source with a specific registry.
// It's CheckString's more sophisticated sibling — use this when you've got
// custom extensions registered and want them considered during validation.
func CheckStringWithRegistry(path, src string, reg *extension.Registry, strict bool) (*ast.File, diag.Diagnostics) {
	f, err := parser.ParseString(path, src)
	if err != nil {
		if ds, ok := err.(diag.Diagnostics); ok {
			return nil, ds
		}
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Message: err.Error()}}
	}
	return f, validate.File(f, reg, strict)
}
