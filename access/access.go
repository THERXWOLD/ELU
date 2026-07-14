// Package access decodes and evaluates access_policy files.
// Access policies define who can do what to which resources.
package access

import (
	"fmt"
	"regexp"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/internal/glob"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/value"
)

// Rule is a single access control rule. It matches a role, action, and resource,
// optionally gated by a condition, and produces an effect (allow/deny/etc).
type Rule struct {
	Name      string
	// Role is the role this rule applies to. If empty, the rule applies to all roles.
	Role      string
	Effect    policy.Effect
	Action    string
	Resource  string
	Condition *condition.Condition
}

// Policy is a decoded access_policy with all its roles and rules.
type Policy struct {
	PackID        string
	Version       int
	Name          string
	Default       policy.Effect
	DeclaredRoles []string
	NeverRules    []Rule
	Rules         []Rule
}

// Request carries the information needed to evaluate an access policy.
type Request struct {
	SubjectID string
	Roles     []string
	Action    string
	Resource  string
	Context   condition.EvalContext
}

// Decision is what comes out of Evaluate — an Effect plus metadata.
type Decision struct {
	Effect       policy.Effect
	MatchedRules []string
	Errors       []string
}

// actionTokenRE validates action tokens: alphanumeric with some punctuation.
var actionTokenRE *regexp.Regexp

// init initializes the regexes used by the parser.
func init() {
	var err error
	actionTokenRE, err = regexp.Compile(`^[A-Za-z_][A-Za-z0-9_.:-]*$`)
	if err != nil {
		panic("elu.access: failed to compile action token regex: " + err.Error())
	}
}

// Decode parses an AST into a validated access_policy.
func Decode(f *ast.File) (*Policy, error) {
	if f == nil {
		return nil, fmt.Errorf("Decode requires non-nil ast.File")
	}
	if f.Type != "access_policy" {
		return nil, fmt.Errorf("expected access_policy, got %q", f.Type)
	}
	var block *ast.Node
	for _, n := range f.Nodes {
		if n.Kind == ast.NodeBlock && n.Key == "access" {
			if block != nil {
				return nil, fmt.Errorf("access_policy allows exactly one access block")
			}
			block = n
			continue
		}
		if n.Kind == ast.NodeAssign {
			continue
		}
		return nil, fmt.Errorf("unexpected top-level %s %q at line %d in access_policy", n.Kind, n.Key, n.Line)
	}
	if block == nil {
		return nil, fmt.Errorf("access_policy requires access block")
	}
	p := &Policy{PackID: f.PackID, Version: f.Version, Name: block.Name, Default: policy.EffectDeny}
	if v, ok := ast.FindAssign(block.Children, "default"); ok {
		p.Default = policy.Effect(v.StringValue())
		if !policy.IsEffect(string(p.Default)) {
			return nil, fmt.Errorf("invalid default effect %q at line %d", p.Default, v.Line)
		}
	}
	seenRuleNames := map[string]bool{}
	seenRoles := map[string]bool{}
	seenAssigns := map[string]bool{}
	seenSections := map[string]bool{}
	for _, child := range block.Children {
		switch child.Kind {
		case ast.NodeAssign:
			if child.Key != "default" {
				return nil, fmt.Errorf("unknown access assignment %q at line %d", child.Key, child.Line)
			}
			if seenAssigns[child.Key] {
				return nil, fmt.Errorf("duplicate access assignment %q at line %d", child.Key, child.Line)
			}
			seenAssigns[child.Key] = true
		case ast.NodeBlock:
			switch child.Key {
			case "role":
				if child.Name == "" {
					return nil, fmt.Errorf("role block at line %d requires a name", child.Line)
				}
				if seenRoles[child.Name] {
					return nil, fmt.Errorf("duplicate role %q", child.Name)
				}
				seenRoles[child.Name] = true
				rules, neverRules, err := decodeRoleRules(child)
				if err != nil {
					return nil, err
				}
				for _, r := range rules {
					if r.Name != "" {
						key := r.Role + ":" + r.Name
						if seenRuleNames[key] {
							return nil, fmt.Errorf("duplicate rule %q for role %q", r.Name, r.Role)
						}
						seenRuleNames[key] = true
					}
					p.Rules = append(p.Rules, r)
				}
				p.NeverRules = append(p.NeverRules, neverRules...)
			case "rule":
				r, err := decodeExplicitRule(child, "")
				if err != nil {
					return nil, err
				}
				if seenRuleNames[":"+r.Name] {
					return nil, fmt.Errorf("duplicate top-level rule %q", r.Name)
				}
				seenRuleNames[":"+r.Name] = true
				p.Rules = append(p.Rules, r)
			default:
				return nil, fmt.Errorf("unknown access block %q at line %d", child.Key, child.Line)
			}
		case ast.NodeSection:
			if policy.IsEffect(child.Key) {
				if seenSections[child.Key] {
					return nil, fmt.Errorf("duplicate access section %q at line %d", child.Key, child.Line)
				}
				seenSections[child.Key] = true
				rules, err := decodeEffectSection("", policy.Effect(child.Key), child)
				if err != nil {
					return nil, err
				}
				if policy.Effect(child.Key) == policy.EffectNever {
					p.NeverRules = append(p.NeverRules, rules...)
				} else {
					p.Rules = append(p.Rules, rules...)
				}
			} else if child.Key == "roles" {
				if seenSections[child.Key] {
					return nil, fmt.Errorf("duplicate access section %q at line %d", child.Key, child.Line)
				}
				seenSections[child.Key] = true
				roles, err := stringListSection(child)
				if err != nil {
					return nil, err
				}
				p.DeclaredRoles = roles
			} else if child.Key == "" {
				return nil, fmt.Errorf("empty section key at line %d", child.Line)
			} else {
				return nil, fmt.Errorf("unknown access section %q at line %d", child.Key, child.Line)
			}
		case ast.NodeListItem:
			return nil, fmt.Errorf("unexpected list item in access block at line %d", child.Line)
		}
	}
	if len(p.DeclaredRoles) > 0 {
		declared := map[string]bool{}
		for _, r := range p.DeclaredRoles {
			declared[r] = true
		}
		for role := range seenRoles {
			if !declared[role] {
				return nil, fmt.Errorf("role %q is not declared in roles section", role)
			}
		}
	}
	return p, nil
}

// decodeRoleRules extracts rules from a role block.
// Returns regular rules and never rules separately.
func decodeRoleRules(role *ast.Node) (rules, neverRules []Rule, err error) {
	seen := map[string]bool{}
	seenSections := map[string]bool{}
	for _, child := range role.Children {
		switch child.Kind {
		case ast.NodeSection:
			if !policy.IsEffect(child.Key) {
				return nil, nil, fmt.Errorf("unknown section %q in role %q at line %d", child.Key, role.Name, child.Line)
			}
			if seenSections[child.Key] {
				return nil, nil, fmt.Errorf("duplicate section %q in role %q at line %d", child.Key, role.Name, child.Line)
			}
			seenSections[child.Key] = true
			rs, err := decodeEffectSection(role.Name, policy.Effect(child.Key), child)
			if err != nil {
				return nil, nil, err
			}
			if policy.Effect(child.Key) == policy.EffectNever {
				neverRules = append(neverRules, rs...)
			} else {
				rules = append(rules, rs...)
			}
		case ast.NodeBlock:
			if child.Key != "rule" {
				return nil, nil, fmt.Errorf("unknown block %q in role %q at line %d", child.Key, role.Name, child.Line)
			}
			r, err := decodeExplicitRule(child, role.Name)
			if err != nil {
				return nil, nil, err
			}
			if seen[r.Name] {
				return nil, nil, fmt.Errorf("duplicate rule %q for role %q", r.Name, role.Name)
			}
			seen[r.Name] = true
			if r.Effect == policy.EffectNever {
				neverRules = append(neverRules, r)
			} else {
				rules = append(rules, r)
			}
		default:
			return nil, nil, fmt.Errorf("invalid item in role %q at line %d", role.Name, child.Line)
		}
	}
	return rules, neverRules, nil
}

// decodeEffectSection decodes a shorthand effect section (allow/deny/etc)
// containing action → resource mappings.
func decodeEffectSection(role string, effect policy.Effect, sec *ast.Node) ([]Rule, error) {
	var rules []Rule
	if len(sec.Children) == 0 {
		return nil, fmt.Errorf("effect section %q at line %d must not be empty", sec.Key, sec.Line)
	}
	seenActions := map[string]bool{}
	for _, actionSec := range sec.Children {
		if actionSec.Kind != ast.NodeSection {
			return nil, fmt.Errorf("effect section %q expects action sections at line %d", sec.Key, actionSec.Line)
		}
		action := actionSec.Key
		if !isValidActionToken(action) {
			return nil, fmt.Errorf("invalid action %q in effect section %q at line %d", action, sec.Key, actionSec.Line)
		}
		if seenActions[action] {
			return nil, fmt.Errorf("effect section %q has duplicate action section %q at line %d", sec.Key, action, actionSec.Line)
		}
		seenActions[action] = true
		if action == "" {
			return nil, fmt.Errorf("empty action in effect section %q at line %d", sec.Key, actionSec.Line)
		}
		if len(actionSec.Children) == 0 {
			return nil, fmt.Errorf("action section %q at line %d must list resources", action, actionSec.Line)
		}
		for _, item := range actionSec.Children {
			if item.Kind != ast.NodeListItem || item.Value.Kind != value.String || len(item.Children) != 0 {
				return nil, fmt.Errorf("action %q at line %d expects string list items", action, item.Line)
			}
			res := item.Value.S
			if res == "" {
				return nil, fmt.Errorf("empty resource in action %q at line %d", action, item.Line)
			}
			rules = append(rules, Rule{
				Role:     role,
				Effect:   effect,
				Action:   action,
				Resource: res,
				Name:     fmt.Sprintf("%s:%s.%s.%s", role, string(effect), action, res),
			})
		}
	}
	return rules, nil
}

// decodeExplicitRule decodes a named rule block with effect, action, resource, and optional when.
func decodeExplicitRule(n *ast.Node, role string) (Rule, error) {
	r := Rule{Name: n.Name, Role: role, Effect: policy.EffectDeny}
	if r.Name == "" {
		return r, fmt.Errorf("rule at line %d requires a name", n.Line)
	}
	// Looking for effect named rule field, if not found, return error
	if v, ok := ast.FindAssign(n.Children, "effect"); ok {
		r.Effect = policy.Effect(v.StringValue())
		if !policy.IsEffect(string(r.Effect)) {
			return r, fmt.Errorf("rule %q has invalid effect %q at line %d", r.Name, r.Effect, v.Line)
		}
	} else {
		return r, fmt.Errorf("rule %q is missing required field effect", r.Name)
	}
	// Looking for action named rule field, if not found, return error
	if v, ok := ast.FindAssign(n.Children, "action"); ok {
		r.Action = v.StringValue()
		if r.Action == "" {
			return r, fmt.Errorf("rule %q has empty action at line %d", r.Name, v.Line)
		}
		if !isValidActionToken(r.Action) {
			return r, fmt.Errorf("rule %q has invalid action %q at line %d", r.Name, r.Action, v.Line)
		}
	} else {
		return r, fmt.Errorf("rule %q is missing required field action", r.Name)
	}
	// Looking for resource named rule field, if not found, return error
	if v, ok := ast.FindAssign(n.Children, "resource"); ok {
		r.Resource = v.StringValue()
		if r.Resource == "" {
			return r, fmt.Errorf("rule %q has empty resource at line %d", r.Name, v.Line)
		}
	} else {
		return r, fmt.Errorf("rule %q is missing required field resource", r.Name)
	}
	seenFields := map[string]bool{}
	seenWhen := false
	for _, child := range n.Children {
		switch child.Kind {
		case ast.NodeAssign:
			switch child.Key {
			case "effect", "action", "resource":
				if seenFields[child.Key] {
					return r, fmt.Errorf("rule %q has duplicate field %q at line %d", r.Name, child.Key, child.Line)
				}
				seenFields[child.Key] = true
			default:
				return r, fmt.Errorf("rule %q has unknown field %q at line %d", r.Name, child.Key, child.Line)
			}
		case ast.NodeSection:
			if child.Key != "when" {
				return r, fmt.Errorf("rule %q has unknown section %q at line %d", r.Name, child.Key, child.Line)
			}
			if seenWhen {
				return r, fmt.Errorf("rule %q has duplicate when section at line %d", r.Name, child.Line)
			}
			seenWhen = true
		default:
			return r, fmt.Errorf("rule %q has invalid child at line %d", r.Name, child.Line)
		}
	}
	if when := ast.FindSection(n.Children, "when"); when != nil {
		cond, err := condition.ParseSection(when)
		if err != nil {
			return r, fmt.Errorf("rule %q has invalid when condition: %w", r.Name, err)
		}
		r.Condition = &cond
	}
	return r, nil
}

// stringListSection extracts a list of strings from a section node.
func stringListSection(sec *ast.Node) ([]string, error) {
	if len(sec.Children) == 0 {
		return nil, fmt.Errorf("section %q at line %d must not be empty", sec.Key, sec.Line)
	}
	var out []string
	seen := map[string]bool{}
	for _, item := range sec.Children {
		if item.Kind != ast.NodeListItem || item.Value.Kind != value.String || len(item.Children) != 0 {
			return nil, fmt.Errorf("section %q at line %d expects string list items", sec.Key, item.Line)
		}
		if item.Value.S == "" {
			return nil, fmt.Errorf("section %q has empty string item at line %d", sec.Key, item.Line)
		}
		if seen[item.Value.S] {
			return nil, fmt.Errorf("section %q has duplicate item %q", sec.Key, item.Value.S)
		}
		seen[item.Value.S] = true
		out = append(out, item.Value.S)
	}
	return out, nil
}

// validateRule checks a single rule for valid fields and operator references.
func validateRule(r Rule, reg *extension.Registry) error {
	if !policy.IsEffect(string(r.Effect)) {
		return fmt.Errorf("rule %q has invalid effect %q", r.Name, r.Effect)
	}
	if r.Action == "" {
		return fmt.Errorf("rule %q has empty action", r.Name)
	}
	if r.Resource == "" {
		return fmt.Errorf("rule %q has empty resource", r.Name)
	}
	if r.Condition != nil {
		if err := condition.ValidateOperators(*r.Condition, reg); err != nil {
			return fmt.Errorf("rule %q has invalid condition: %w", r.Name, err)
		}
	}
	return nil
}

// ValidatePolicy checks that an access policy has valid rules and operator references.
func ValidatePolicy(p *Policy, reg *extension.Registry) error {
	if p == nil {
		return fmt.Errorf("ValidatePolicy requires non-nil Policy")
	}
	if !policy.IsEffect(string(p.Default)) {
		return fmt.Errorf("invalid default effect %q", p.Default)
	}
	for _, r := range p.NeverRules {
		if err := validateRule(r, reg); err != nil {
			return err
		}
	}
	for _, r := range p.Rules {
		if err := validateRule(r, reg); err != nil {
			return err
		}
	}
	return nil
}

// Evaluate runs a request through the policy and returns a decision.
// Never rules are evaluated first as a mandatory pre-pass. If any never rule
// matches the request (role, action, resource, and optional condition all
// satisfied), the decision is EffectNever — regardless of what any other rule
// says. Condition errors on never rules also produce EffectNever (fail-closed).
//
// After the never pre-pass, regular rules are iterated in order, applying the
// strongest matching effect. Condition errors on regular rules are aggregated:
// all rules are evaluated and all errors are reported, but any error still
// produces EffectNever (fail-closed).
func (p *Policy) Evaluate(req Request, reg *extension.Registry) Decision {
	if p == nil {
		return Decision{Effect: policy.EffectNever, Errors: []string{"Evaluate requires non-nil Policy"}}
	}
	decision := policy.Effect("")
	matched := []string{}
	ctx := condition.EvalContext{}
	for k, v := range req.Context {
		ctx[k] = v
	}
	ctx["subject.id"] = req.SubjectID
	ctx["subject.roles"] = req.Roles
	ctx["request.action"] = req.Action
	ctx["request.resource"] = req.Resource
	if _, ok := ctx["resource"]; !ok {
		ctx["resource"] = req.Resource
		ctx["resource.type"] = req.Resource
	}
	for _, r := range p.NeverRules {
		// Skip rules that don't apply to the requesting role.
		if r.Role != "" && !hasRole(req.Roles, r.Role) {
			continue
		}
		if !matchAction(r.Action, req.Action) {
			continue
		}
		if !matchResource(r.Resource, req.Resource) {
			continue
		}
		if r.Condition != nil {
			ok, err := condition.EvaluateStrict(*r.Condition, ctx, reg)
			if err != nil {
				return Decision{Effect: policy.EffectNever, Errors: []string{fmt.Sprintf("never rule %q condition error: %v", r.Name, err)}}
			}
			if !ok {
				continue
			}
		}
		return Decision{Effect: policy.EffectNever, MatchedRules: []string{r.Name}}
	}
	var errs []string
	for _, r := range p.Rules {
		// Skip rules that don't apply to the requesting role.
		if r.Role != "" && !hasRole(req.Roles, r.Role) {
			continue
		}
		if !matchAction(r.Action, req.Action) {
			continue
		}
		if !matchResource(r.Resource, req.Resource) {
			continue
		}
		if r.Condition != nil {
			ok, err := condition.EvaluateStrict(*r.Condition, ctx, reg)
			if err != nil {
				errs = append(errs, fmt.Sprintf("rule %q condition error: %v", r.Name, err))
				continue
			}
			if !ok {
				continue
			}
		}
		matched = append(matched, r.Name)
		if decision == "" || policy.Stronger(r.Effect, decision) {
			decision = r.Effect
		}
	}
	if len(errs) > 0 {
		decision = policy.EffectNever
	}
	if decision == "" {
		decision = p.Default
	}
	return Decision{Effect: decision, MatchedRules: matched, Errors: errs}
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

// matchAction checks if a pattern matches an action.
// * matches everything, otherwise exact match.
func matchAction(pattern, val string) bool {
	return pattern == "*" || pattern == val
}

// matchResource checks if a resource pattern matches a value.
// Supports * and glob patterns.
func matchResource(pattern, val string) bool {
	if pattern == "*" || pattern == val {
		return true
	}
	return glob.Match(pattern, val)
}

// isValidActionToken checks if a string is a valid action token or wildcard.
func isValidActionToken(action string) bool {
	return action == "*" || actionTokenRE.MatchString(action)
}
