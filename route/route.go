// Package route decodes and evaluates route_policy files.
// Route policies control HTTP endpoint access with support for conditions,
// roles, MFA requirements, and audit flags.
package route

import (
	"fmt"
	"strings"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/internal/glob"
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
func Decode(f *ast.File) (*Policy, error) {
	if f == nil {
		return nil, fmt.Errorf("Decode requires non-nil ast.File")
	}
	if f.Type != "route_policy" {
		return nil, fmt.Errorf("expected route_policy, got %q", f.Type)
	}
	var block *ast.Node
	for _, n := range f.Nodes {
		if n.Kind == ast.NodeBlock && n.Key == "routes" {
			if block != nil {
				return nil, fmt.Errorf("route_policy allows exactly one routes block")
			}
			block = n
			continue
		}
		return nil, fmt.Errorf("unexpected top-level %s %q at line %d in route_policy", n.Kind, n.Key, n.Line)
	}
	if block == nil {
		return nil, fmt.Errorf("route_policy requires routes block")
	}
	p := &Policy{PackID: f.PackID, Version: f.Version, Name: block.Name, Default: policy.EffectDeny}
	seenTop := map[string]bool{}
	seenRoutes := map[string]bool{}
	for _, child := range block.Children {
		switch child.Kind {
		case ast.NodeAssign:
			if child.Key != "default" {
				return nil, fmt.Errorf("unknown routes assignment %q at line %d", child.Key, child.Line)
			}
			if seenTop[child.Key] {
				return nil, fmt.Errorf("duplicate routes assignment %q at line %d", child.Key, child.Line)
			}
			seenTop[child.Key] = true
			p.Default = policy.Effect(child.Value.StringValue())
			if !policy.IsEffect(string(p.Default)) {
				return nil, fmt.Errorf("invalid route default effect %q", p.Default)
			}
		case ast.NodeSection:
			if seenTop[child.Key] {
				return nil, fmt.Errorf("duplicate routes section %q at line %d", child.Key, child.Line)
			}
			seenTop[child.Key] = true
			switch child.Key {
			case "public":
				rs, err := decodeRouteList(child, policy.EffectAllow, false)
				if err != nil {
					return nil, err
				}
				for _, r := range rs {
					if seenRoutes[r.Name] {
						return nil, fmt.Errorf("duplicate route %q", r.Name)
					}
					seenRoutes[r.Name] = true
					p.Routes = append(p.Routes, r)
				}
			case "protected":
				rs, err := decodeRouteList(child, policy.EffectAllow, true)
				if err != nil {
					return nil, err
				}
				for _, r := range rs {
					if seenRoutes[r.Name] {
						return nil, fmt.Errorf("duplicate route %q", r.Name)
					}
					seenRoutes[r.Name] = true
					p.Routes = append(p.Routes, r)
				}
			default:
				return nil, fmt.Errorf("unknown routes section %q at line %d", child.Key, child.Line)
			}
		case ast.NodeBlock:
			if child.Key != "route" {
				return nil, fmt.Errorf("unknown routes block %q at line %d", child.Key, child.Line)
			}
			r, err := decodeRouteBlock(child, child.Name, policy.Effect(""))
			if err != nil {
				return nil, err
			}
			if seenRoutes[r.Name] {
				return nil, fmt.Errorf("duplicate route %q", r.Name)
			}
			seenRoutes[r.Name] = true
			p.Routes = append(p.Routes, r)
		default:
			return nil, fmt.Errorf("invalid child in routes block at line %d", child.Line)
		}
	}
	if err := validateRouteConflicts(p.Routes); err != nil {
		return nil, err
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
func ValidatePolicy(p *Policy, reg *extension.Registry) error {
	if p == nil {
		return fmt.Errorf("ValidatePolicy requires non-nil Policy")
	}
	if !policy.IsEffect(string(p.Default)) {
		return fmt.Errorf("invalid default effect %q", p.Default)
	}
	if len(p.Routes) == 0 {
		return fmt.Errorf("route_policy requires at least one route")
	}
	for _, r := range p.Routes {
		if r.Method == "" {
			return fmt.Errorf("route %q has empty method", r.Name)
		}
		if r.Path == "" {
			return fmt.Errorf("route %q has empty path", r.Name)
		}
		if !isValidRoutePath(r.Path) {
			return fmt.Errorf("route %q has invalid path %q", r.Name, r.Path)
		}
		if r.Require2FA && r.RequireRole == "" {
			return fmt.Errorf("route %q require_2fa requires require_role", r.Name)
		}
		if !policy.IsEffect(string(r.Effect)) {
			return fmt.Errorf("route %q has invalid effect %q", r.Name, r.Effect)
		}
		if r.Condition != nil {
			if err := condition.ValidateOperators(*r.Condition, reg); err != nil {
				return fmt.Errorf("route %q has invalid condition: %w", r.Name, err)
			}
		}
	}
	return validateRouteConflicts(p.Routes)
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
		if r.RequireRole != "" && !hasRole(req.Roles, r.RequireRole) {
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

// hasRole checks if a role is in a list of roles.
func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
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
	if a == b {
		return true
	}
	if glob.Match(a, b) || glob.Match(b, a) {
		return true
	}
	return segmentsOverlap(a, b)
}

// segmentsOverlap checks if two route patterns can match the same concrete
// path by comparing their segments pairwise. This catches overlaps that
// simple glob matching misses when both patterns contain metacharacters.
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
	if !hasRouteMetachar(a) {
		return glob.Match(b, a)
	}
	if !hasRouteMetachar(b) {
		return glob.Match(a, b)
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
