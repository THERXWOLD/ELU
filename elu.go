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

// Facade exports the most common MVP API from subpackages.

type File = ast.File
type Node = ast.Node
type Diagnostic = diag.Diagnostic
type Diagnostics = diag.Diagnostics
type Registry = extension.Registry
type Condition = condition.Condition
type EvalContext = condition.EvalContext
type AccessPolicy = access.Policy
type AccessRequest = access.Request
type AccessDecision = access.Decision
type Effect = policy.Effect

type SkillPack = skill.Pack
type RepoPolicy = repo.Policy
type RepoRequest = repo.Request
type RepoDecision = repo.Decision
type RoutePolicy = route.Policy
type RouteRequest = route.Request
type RouteDecision = route.Decision
type GuardrailPack = guardrail.Pack
type FilterPack = filter.Pack

const (
	Error   = diag.Error
	Warning = diag.Warning

	EffectAllow    = policy.EffectAllow
	EffectPropose  = policy.EffectPropose
	EffectApproval = policy.EffectApproval
	EffectDeny     = policy.EffectDeny
	EffectNever    = policy.EffectNever
)

func NewRegistry() *extension.Registry                       { return extension.NewRegistry() }
func ParseFile(path string) (*ast.File, error)               { return parser.ParseFile(path) }
func ParseString(path, src string) (*ast.File, error)        { return parser.ParseString(path, src) }
func DecodeAccessPolicy(f *ast.File) (*access.Policy, error) { return access.Decode(f) }
func DecodeSkillPack(f *ast.File) (*skill.Pack, error)       { return skill.Decode(f) }
func DecodeRepoPolicy(f *ast.File) (*repo.Policy, error)     { return repo.Decode(f) }
func DecodeRoutePolicy(f *ast.File) (*route.Policy, error)   { return route.Decode(f) }
func DecodeGuardrailPack(f *ast.File) (*guardrail.Pack, error) {
	return guardrail.Decode(f)
}
func DecodeFilterPack(f *ast.File) (*filter.Pack, error) { return filter.Decode(f) }
func ValidateFile(f *ast.File, reg *extension.Registry, strict bool) diag.Diagnostics {
	return validate.File(f, reg, strict)
}

func ValidateProductionFile(f *ast.File, reg *extension.Registry) diag.Diagnostics {
	return validate.ProductionFile(f, reg)
}

func FormatString(path, src string) (string, error) { return format.String(path, src) }
func FormatFile(f *ast.File) string                 { return format.File(f) }
func EvaluateCondition(cond condition.Condition, ctx condition.EvalContext, reg *extension.Registry) (bool, error) {
	return condition.Evaluate(cond, ctx, reg)
}

func CheckString(path, src string, strict bool) (*ast.File, diag.Diagnostics) {
	return CheckStringWithRegistry(path, src, extension.NewRegistry(), strict)
}

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
