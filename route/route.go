// Package route decodes and evaluates route_policy files.
// Route policies control HTTP endpoint access with support for conditions,
// roles, MFA requirements, and audit flags.
package route

import (
	"fmt"
	"strings"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/diag"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/internal/glob"
	"github.com/therxwold/elu/internal/util"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/value"
)

// Policy is a decoded route_policy with all its routes.
type Policy struct {
	PackID  string
	Version int
	Name    string
	Default policy.Effect
	Routes  []Route
}

// Route defines access rules for an HTTP endpoint.
type Route struct {
	Name        string
	Effect      policy.Effect
	Method      string
	Path        string
	RequireRole string
	Require2FA  bool
	Audit       bool
	Condition   *condition.Condition
}

// Request carries the information needed to evaluate a route policy.
type Request struct {
	SubjectID string
	Method    string
	Path      string
	Roles     []string
	MFA       bool
	Context   condition.EvalContext
}

// Decision is the route policy evaluation result.
type Decision struct {
	Effect        policy.Effect
	MatchedRoutes []string
	Errors        []string
	Audit         bool
}

// Decode parses an AST into a validated route_policy.
// Returns all errors at once via diag.Diagnostics.
func Decode(f *ast.File) (*Policy, error) {
	if f == nil {
		return nil, diag.Diagnostics{{Severity: diag.Error, Message: "Decode requires non-nil ast.File"}}
	}
	if f.Type != "route_policy" {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Message: fmt.Sprintf("expected route_policy, got %q", f.Type)}}
	}
	var block *ast.Node
	for _, n := range f.Nodes {
		if n.Kind == ast.NodeBlock && n.Key == "routes" {
			if block != nil {
				return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Message: "route_policy allows exactly one routes block"}}
			}
			block = n
			continue
		}
		return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Line: n.Line, Message: fmt.Sprintf("unexpected top-level %s %q in route_policy", n.Kind, n.Key)}}
	}
	if block == nil {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Message: "route_policy requires routes block"}}
	}
	p := &Policy{PackID: f.PackID, Version: f.Version, Name: block.Name, Default: policy.EffectDeny}
	var diags diag.Diagnostics
	seenTop := map[string]bool{}
	seenRoutes := map[string]bool{}
	for _, child := range block.Children {
		switch child.Kind {
		case ast.NodeAssign:
			if child.Key != "default" {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("unknown routes assignment %q", child.Key)})
				continue
			}
			if seenTop[child.Key] {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("duplicate routes assignment %q", child.Key)})
				continue
			}
			seenTop[child.Key] = true
			p.Default = policy.Effect(child.Value.StringValue())
			if !policy.IsEffect(string(p.Default)) {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("invalid route default effect %q", p.Default)})
			}
		case ast.NodeSection:
			if seenTop[child.Key] {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("duplicate routes section %q", child.Key)})
				continue
			}
			seenTop[child.Key] = true
			switch child.Key {
			case "public":
				rs, err := decodeRouteList(child, policy.EffectAllow, false)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				for _, r := range rs {
					if seenRoutes[r.Name] {
						diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("duplicate route %q", r.Name)})
						continue
					}
					seenRoutes[r.Name] = true
					p.Routes = append(p.Routes, r)
				}
			case "protected":
				rs, err := decodeRouteList(child, policy.EffectAllow, true)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				for _, r := range rs {
					if seenRoutes[r.Name] {
						diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("duplicate route %q", r.Name)})
						continue
					}
					seenRoutes[r.Name] = true
					p.Routes = append(p.Routes, r)
				}
			default:
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("unknown routes section %q", child.Key)})
			}
		case ast.NodeBlock:
			if child.Key != "route" {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("unknown routes block %q", child.Key)})
				continue
			}
			r, err := decodeRouteBlock(child, child.Name, policy.Effect(""))
			if err != nil {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
				continue
			}
			if seenRoutes[r.Name] {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("duplicate route %q", r.Name)})
				continue
			}
			seenRoutes[r.Name] = true
			p.Routes = append(p.Routes, r)
		default:
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: "invalid child in routes block"})
		}
	}
	if err := validateRouteConflicts(p.Routes); err != nil {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Message: err.Error()})
	}
	if diags.HasErrors() {
		return nil, diags
	}
	return p, nil
}

// decodeRouteList decodes a list of inline route objects from a section.
func decodeRouteList(sec *ast.Node, defaultEffect policy.Effect, protected bool) ([]Route, error) {
	var routes []Route
	if len(sec.Children) == 0 {
		return nil, fmt.Errorf("section %q at line %d must not be empty", sec.Key, sec.Line)
	}
	for i, item := range sec.Children {
		if item.Kind != ast.NodeListItem || item.Value.Kind != "" {
			return nil, fmt.Errorf("section %q at line %d expects object list items", sec.Key, item.Line)
		}
		name := fmt.Sprintf("%s.%d", sec.Key, i)
		r, err := decodeRouteFields(item.Children, name, defaultEffect)
		if err != nil {
			return nil, err
		}
		if protected && r.RequireRole == "" {
			return nil, fmt.Errorf("protected route %q requires require_role", r.Name)
		}
		if !protected && r.RequireRole != "" {
			return nil, fmt.Errorf("public route %q cannot use require_role", r.Name)
		}
		if !protected && r.Require2FA {
			return nil, fmt.Errorf("public route %q cannot use require_2fa", r.Name)
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// decodeRouteBlock decodes a named route block.
func decodeRouteBlock(n *ast.Node, name string, defaultEffect policy.Effect) (Route, error) {
	if name == "" {
		return Route{}, fmt.Errorf("route block at line %d requires a name", n.Line)
	}
	return decodeRouteFields(n.Children, name, defaultEffect)
}

// decodeRouteFields extracts route fields from its child nodes.
func decodeRouteFields(children []*ast.Node, name string, defaultEffect policy.Effect) (Route, error) {
	r := Route{Name: name, Effect: defaultEffect}
	seen := map[string]bool{}
	for _, child := range children {
		switch child.Kind {
		case ast.NodeAssign:
			if seen[child.Key] {
				return r, fmt.Errorf("route %q has duplicate field %q at line %d", name, child.Key, child.Line)
			}
			seen[child.Key] = true
			switch child.Key {
			case "method":
				r.Method = strings.ToUpper(child.Value.StringValue())
			case "path":
				r.Path = child.Value.StringValue()
			case "require_role":
				r.RequireRole = child.Value.StringValue()
			case "require_2fa":
				b, ok := boolValue(child.Value)
				if !ok {
					return r, fmt.Errorf("route %q require_2fa must be boolean at line %d", name, child.Line)
				}
				r.Require2FA = b
			case "audit":
				b, ok := boolValue(child.Value)
				if !ok {
					return r, fmt.Errorf("route %q audit must be boolean at line %d", name, child.Line)
				}
				r.Audit = b
			case "effect":
				r.Effect = policy.Effect(child.Value.StringValue())
				if !policy.IsEffect(string(r.Effect)) {
					return r, fmt.Errorf("route %q has invalid effect %q", name, r.Effect)
				}
			default:
				return r, fmt.Errorf("route %q has unknown field %q at line %d", name, child.Key, child.Line)
			}
		case ast.NodeSection:
			if child.Key != "when" {
				return r, fmt.Errorf("route %q has unknown section %q at line %d", name, child.Key, child.Line)
			}
			if seen["when"] {
				return r, fmt.Errorf("route %q has duplicate when section at line %d", name, child.Line)
			}
			seen["when"] = true
			cond, err := condition.ParseSection(child)
			if err != nil {
				return r, fmt.Errorf("route %q has invalid when condition: %w", name, err)
			}
			r.Condition = &cond
		default:
			return r, fmt.Errorf("route %q has invalid child at line %d", name, child.Line)
		}
	}
	if r.Method == "" {
		return r, fmt.Errorf("route %q is missing method", name)
	}
	if r.Path == "" {
		return r, fmt.Errorf("route %q is missing path", name)
	}
	if !isHTTPMethod(r.Method) {
		return r, fmt.Errorf("route %q has invalid HTTP method %q", name, r.Method)
	}
	if !isValidRoutePath(r.Path) {
		return r, fmt.Errorf("route %q has invalid path %q", name, r.Path)
	}
	if r.Require2FA && r.RequireRole == "" {
		return r, fmt.Errorf("route %q require_2fa requires require_role", name)
	}
	if defaultEffect == "" && !seen["effect"] {
		return r, fmt.Errorf("route %q is missing required field effect", name)
	}
	return r, nil
}

// ValidatePolicy checks that a route_policy has valid routes and operator references.
// Returns all errors at once via diag.Diagnostics.
func ValidatePolicy(p *Policy, reg *extension.Registry) error {
	if p == nil {
		return diag.Diagnostics{{Severity: diag.Error, Message: "ValidatePolicy requires non-nil Policy"}}
	}
	var diags diag.Diagnostics
	if !policy.IsEffect(string(p.Default)) {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("invalid default effect %q", p.Default)})
	}
	if len(p.Routes) == 0 {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: "route_policy requires at least one route"})
	}
	for _, r := range p.Routes {
		if r.Method == "" {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("route %q has empty method", r.Name)})
			continue
		}
		if r.Path == "" {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("route %q has empty path", r.Name)})
			continue
		}
		if !isValidRoutePath(r.Path) {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("route %q has invalid path %q", r.Name, r.Path)})
			continue
		}
		if r.Require2FA && r.RequireRole == "" {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("route %q require_2fa requires require_role", r.Name)})
		}
		if !policy.IsEffect(string(r.Effect)) {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("route %q has invalid effect %q", r.Name, r.Effect)})
		}
		if r.Condition != nil {
			if err := condition.ValidateOperators(*r.Condition, reg); err != nil {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("route %q has invalid condition: %v", r.Name, err)})
			}
		}
	}
	if err := validateRouteConflicts(p.Routes); err != nil {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: err.Error()})
	}
	if diags.HasErrors() {
		return diags
	}
	return nil
}

// Evaluate runs a request through the route policy and returns a decision.
func (p *Policy) Evaluate(req Request, reg *extension.Registry) Decision {
	if p == nil {
		return Decision{Effect: policy.EffectDeny, Errors: []string{"Evaluate requires non-nil Policy"}}
	}
	decision := policy.Effect("")
	matched := []string{}
	audit := false
	ctx := condition.EvalContext{}
	for k, v := range req.Context {
		ctx[k] = v
	}
	ctx["request.method"] = strings.ToUpper(req.Method)
	ctx["request.path"] = req.Path
	ctx["subject.id"] = req.SubjectID
	ctx["subject.roles"] = req.Roles
	ctx["auth.mfa"] = req.MFA
	for _, r := range p.Routes {
		if strings.ToUpper(req.Method) != r.Method {
			continue
		}
		if !glob.Match(r.Path, req.Path) {
			continue
		}
		// Once method and path match, authorization failures must not fall
		// through to a more permissive policy default.
		if r.RequireRole != "" && !util.HasRole(req.Roles, r.RequireRole) {
			matched = append(matched, r.Name)
			audit = audit || r.Audit
			decision = strongerEffect(decision, policy.EffectDeny)
			continue
		}
		if r.Require2FA && !req.MFA {
			matched = append(matched, r.Name)
			audit = audit || r.Audit
			decision = strongerEffect(decision, policy.EffectDeny)
			continue
		}
		if r.Condition != nil {
			ok, err := condition.EvaluateStrict(*r.Condition, ctx, reg)
			if err != nil {
				return Decision{Effect: policy.EffectNever, Errors: []string{fmt.Sprintf("route %q condition error: %v", r.Name, err)}}
			}
			if !ok {
				// A condition attached to an authenticated route is an additional
				// authorization requirement, not a reason to use the default.
				if r.RequireRole != "" {
					matched = append(matched, r.Name)
					audit = audit || r.Audit
					decision = strongerEffect(decision, policy.EffectDeny)
				}
				continue
			}
		}
		matched = append(matched, r.Name)
		audit = audit || r.Audit
		decision = strongerEffect(decision, r.Effect)
	}
	if decision == "" {
		decision = p.Default
	}
	return Decision{Effect: decision, MatchedRoutes: matched, Audit: audit}
}

// strongerEffect returns candidate when it outranks current.
func strongerEffect(current, candidate policy.Effect) policy.Effect {
	if current == "" || policy.Stronger(candidate, current) {
		return candidate
	}
	return current
}

// isHTTPMethod checks if a string is a valid HTTP method.
func isHTTPMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

// isValidRoutePath checks if a route path is valid (starts with / or is *).
func isValidRoutePath(path string) bool {
	if path == "" || strings.TrimSpace(path) != path {
		return false
	}
	return path == "*" || strings.HasPrefix(path, "/")
}

// validateRouteConflicts detects overlapping route definitions that could
// cause ambiguity during evaluation.
func validateRouteConflicts(routes []Route) error {
	for i := 0; i < len(routes); i++ {
		for j := i + 1; j < len(routes); j++ {
			a, b := routes[i], routes[j]
			if a.Method != b.Method {
				continue
			}
			if routesOverlap(a.Path, b.Path) {
				return fmt.Errorf("route %q conflicts with route %q for %s %s", a.Name, b.Name, a.Method, a.Path)
			}
		}
	}
	return nil
}

// routesOverlap checks if two route patterns could match the same path.
func routesOverlap(a, b string) bool {
	a = normalizePath(a)
	b = normalizePath(b)
	if a == b {
		return true
	}
	return segmentsOverlap(a, b)
}

// normalizePath removes duplicate slashes and trims trailing slashes.
func normalizePath(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return strings.TrimSuffix(p, "/")
}

// segmentsOverlap checks if two normalized route patterns can match the same
// concrete path by comparing their segments pairwise.
func segmentsOverlap(a, b string) bool {
	sa := splitRoutePath(a)
	sb := splitRoutePath(b)
	for len(sa) < len(sb) {
		if !hasDoubleStar(sa) {
			return false
		}
		sa = append(sa, "**")
	}
	for len(sb) < len(sa) {
		if !hasDoubleStar(sb) {
			return false
		}
		sb = append(sb, "**")
	}
	for i := 0; i < len(sa); i++ {
		if !segmentCanMatch(sa[i], sb[i]) {
			return false
		}
	}
	return true
}

// splitRoutePath splits a path into segments, trimming leading/trailing slashes.
func splitRoutePath(s string) []string {
	s = strings.Trim(s, "/")
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

// hasDoubleStar checks if any segment is **.
func hasDoubleStar(segs []string) bool {
	for _, seg := range segs {
		if seg == "**" {
			return true
		}
	}
	return false
}

// segmentCanMatch checks if two path segments could match each other.
func segmentCanMatch(a, b string) bool {
	if a == b || a == "**" || b == "**" {
		return true
	}
	if a == "*" || b == "*" {
		return true
	}
	ha := hasRouteMetachar(a)
	hb := hasRouteMetachar(b)
	if !ha && !hb {
		return a == b
	}
	if ha != hb {
		if ha {
			return glob.Match(a, b)
		}
		return glob.Match(b, a)
	}
	return segmentPatternsOverlap(a, b)
}

// splitLiteralBounds returns the literal string before the first metachar
// and after the last metachar in a glob pattern.
func splitLiteralBounds(s string) (string, string) {
	i := strings.IndexAny(s, "*?")
	if i < 0 {
		return s, s
	}
	j := strings.LastIndexAny(s, "*?")
	return s[:i], s[j+1:]
}

// segmentPatternsOverlap checks if two glob patterns could match the same
// string by comparing their literal prefix and suffix portions.
func segmentPatternsOverlap(a, b string) bool {
	if glob.Match(a, b) || glob.Match(b, a) {
		return true
	}
	preA, sufA := splitLiteralBounds(a)
	preB, sufB := splitLiteralBounds(b)
	if !strings.HasPrefix(preA, preB) && !strings.HasPrefix(preB, preA) {
		return false
	}
	if !strings.HasSuffix(sufA, sufB) && !strings.HasSuffix(sufB, sufA) {
		return false
	}
	return true
}

// hasRouteMetachar checks if a string contains glob metacharacters.
func hasRouteMetachar(s string) bool {
	return strings.ContainsAny(s, "*?")
}

// boolValue tries to extract a boolean from a Value, accepting both
// actual Bool kind and string "true"/"false".
func boolValue(v value.Value) (bool, bool) {
	if v.Kind == value.Bool {
		return v.B, true
	}
	if v.Kind == value.String {
		if v.S == "true" {
			return true, true
		}
		if v.S == "false" {
			return false, true
		}
	}
	return false, false
}
