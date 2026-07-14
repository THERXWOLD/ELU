// Package repo decodes and evaluates repo_policy files.
// Repo policies control repository-level access: who can read, edit, execute, etc.
package repo

import (
	"fmt"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/internal/util"
	"github.com/therxwold/elu/policy"
	"github.com/therxwold/elu/value"
)

// Rule is a single repo access rule.
type Rule struct {
	Name      string
	Effect    policy.Effect
	Action    string
	Resource  string
	Condition *condition.Condition
}

// Policy is a decoded repo_policy with default effects per action and rules.
type Policy struct {
	PackID  string
	Version int
	Name    string
	Default map[string]policy.Effect
	Rules   []Rule
}

// Request carries the information needed to evaluate a repo policy.
type Request struct {
	Action   string
	Resource string
	Context  condition.EvalContext
}

// Decision is the repo policy evaluation result.
type Decision struct {
	Effect       policy.Effect
	MatchedRules []string
	Errors       []string
}

// actionTokenRE validates action tokens.
var actionTokenRE *regexp.Regexp

// init initializes the regexes used by the parser.
func init() {
	var err error
	actionTokenRE, err = regexp.Compile(`^[A-Za-z_][A-Za-z0-9_.:-]*$`)
	if err != nil {
		panic("elu.repo: failed to compile action token regex: " + err.Error())
	}
}

// Decode parses an AST into a validated repo_policy.
func Decode(f *ast.File) (*Policy, error) {
	if f == nil {
		return nil, fmt.Errorf("Decode requires non-nil ast.File")
	}
	if f.Type != "repo_policy" {
		return nil, fmt.Errorf("expected repo_policy, got %q", f.Type)
	}
	var block *ast.Node
	for _, n := range f.Nodes {
		if n.Kind == ast.NodeBlock && n.Key == "repo" {
			if block != nil {
				return nil, fmt.Errorf("repo_policy allows exactly one repo block")
			}
			block = n
			continue
		}
		return nil, fmt.Errorf("unexpected top-level %s %q at line %d in repo_policy", n.Kind, n.Key, n.Line)
	}
	if block == nil {
		return nil, fmt.Errorf("repo_policy requires repo block")
	}
	p := &Policy{PackID: f.PackID, Version: f.Version, Name: block.Name, Default: map[string]policy.Effect{}}
	seenRules := map[string]bool{}
	seenSections := map[string]bool{}
	for _, child := range block.Children {
		switch child.Kind {
		case ast.NodeSection:
			if seenSections[child.Key] {
				return nil, fmt.Errorf("repo %q has duplicate section %q at line %d", block.Name, child.Key, child.Line)
			}
			seenSections[child.Key] = true
			switch {
			case child.Key == "default":
				defs, err := decodeDefault(child)
				if err != nil {
					return nil, err
				}
				p.Default = defs
			case policy.IsEffect(child.Key):
				rules, err := decodeEffectSection(policy.Effect(child.Key), child)
				if err != nil {
					return nil, err
				}
				p.Rules = append(p.Rules, rules...)
			default:
				if child.Key == "" {
					return nil, fmt.Errorf("empty section key at line %d", child.Line)
				}
				return nil, fmt.Errorf("unknown repo section %q at line %d", child.Key, child.Line)
			}
		case ast.NodeBlock:
			if child.Key != "rule" {
				return nil, fmt.Errorf("unknown repo block %q at line %d", child.Key, child.Line)
			}
			r, err := decodeExplicitRule(child)
			if err != nil {
				return nil, err
			}
			if seenRules[r.Name] {
				return nil, fmt.Errorf("duplicate repo rule %q", r.Name)
			}
			seenRules[r.Name] = true
			p.Rules = append(p.Rules, r)
		default:
			return nil, fmt.Errorf("invalid child in repo block at line %d", child.Line)
		}
	}
	return p, nil
}

// decodeDefault extracts the default effect mapping (action → effect) from a section.
func decodeDefault(sec *ast.Node) (map[string]policy.Effect, error) {
	out := map[string]policy.Effect{}
	for _, child := range sec.Children {
		if child.Kind != ast.NodeAssign {
			return nil, fmt.Errorf("default section at line %d expects assignments", child.Line)
		}
		e := policy.Effect(child.Value.StringValue())
		if !policy.IsEffect(string(e)) {
			return nil, fmt.Errorf("invalid default effect %q at line %d", e, child.Line)
		}
		if _, ok := out[child.Key]; ok {
			return nil, fmt.Errorf("duplicate default action %q at line %d", child.Key, child.Line)
		}
		out[child.Key] = e
	}
	return out, nil
}

// decodeEffectSection decodes a shorthand effect section into rules.
func decodeEffectSection(effect policy.Effect, sec *ast.Node) ([]Rule, error) {
	if len(sec.Children) == 0 {
		return nil, fmt.Errorf("effect section %q at line %d must not be empty", sec.Key, sec.Line)
	}
	var rules []Rule
	seenActions := map[string]bool{}
	for _, actionSec := range sec.Children {
		if actionSec.Kind != ast.NodeSection {
			return nil, fmt.Errorf("effect section %q expects action sections at line %d", sec.Key, actionSec.Line)
		}
		if seenActions[actionSec.Key] {
			return nil, fmt.Errorf("effect section %q has duplicate action section %q at line %d", sec.Key, actionSec.Key, actionSec.Line)
		}
		seenActions[actionSec.Key] = true
		if actionSec.Key == "" {
			return nil, fmt.Errorf("empty action in effect section %q", sec.Key)
		}
		if !util.IsValidActionToken(actionSec.Key) {
			return nil, fmt.Errorf("invalid action %q in effect section %q at line %d", actionSec.Key, sec.Key, actionSec.Line)
		}
		if len(actionSec.Children) == 0 {
			return nil, fmt.Errorf("action section %q at line %d must list resources", actionSec.Key, actionSec.Line)
		}
		for _, item := range actionSec.Children {
			if item.Kind != ast.NodeListItem || item.Value.Kind != value.String || len(item.Children) != 0 {
				return nil, fmt.Errorf("action %q at line %d expects string list items", actionSec.Key, item.Line)
			}
			if item.Value.S == "" {
				return nil, fmt.Errorf("action %q has empty resource at line %d", actionSec.Key, item.Line)
			}
			rules = append(rules, Rule{Name: string(effect) + "." + actionSec.Key + "." + item.Value.S, Effect: effect, Action: actionSec.Key, Resource: item.Value.S})
		}
	}
	return rules, nil
}

// decodeExplicitRule decodes a named rule block.
func decodeExplicitRule(n *ast.Node) (Rule, error) {
	r := Rule{Name: n.Name, Effect: policy.EffectDeny}
	if r.Name == "" {
		return r, fmt.Errorf("repo rule at line %d requires a name", n.Line)
	}
	seen := map[string]bool{}
	seenWhen := false
	for _, child := range n.Children {
		switch child.Kind {
		case ast.NodeAssign:
			if seen[child.Key] {
				return r, fmt.Errorf("rule %q has duplicate field %q at line %d", r.Name, child.Key, child.Line)
			}
			seen[child.Key] = true
			switch child.Key {
			case "effect":
				r.Effect = policy.Effect(child.Value.StringValue())
				if !policy.IsEffect(string(r.Effect)) {
					return r, fmt.Errorf("rule %q has invalid effect %q", r.Name, r.Effect)
				}
			case "action":
				r.Action = child.Value.StringValue()
			case "resource":
				r.Resource = child.Value.StringValue()
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
			cond, err := condition.ParseSection(child)
			if err != nil {
				return r, fmt.Errorf("rule %q has invalid when condition: %w", r.Name, err)
			}
			r.Condition = &cond
		default:
			return r, fmt.Errorf("rule %q has invalid child at line %d", r.Name, child.Line)
		}
	}
	if !seen["effect"] {
		return r, fmt.Errorf("rule %q is missing required field effect", r.Name)
	}
	if !seen["action"] || r.Action == "" {
		return r, fmt.Errorf("rule %q is missing required field action", r.Name)
	}
	if !util.IsValidActionToken(r.Action) {
		return r, fmt.Errorf("rule %q has invalid action %q", r.Name, r.Action)
	}
	if !seen["resource"] || r.Resource == "" {
		return r, fmt.Errorf("rule %q is missing required field resource", r.Name)
	}
	return r, nil
}

// ValidatePolicy checks that a repo policy has valid defaults, rules, and operators.
func ValidatePolicy(p *Policy, reg *extension.Registry) error {
	if p == nil {
		return fmt.Errorf("ValidatePolicy requires non-nil Policy")
	}
	for action, effect := range p.Default {
		if action == "" {
			return fmt.Errorf("default action must not be empty")
		}
		if !policy.IsEffect(string(effect)) {
			return fmt.Errorf("invalid default effect %q", effect)
		}
	}
	for _, r := range p.Rules {
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
	}
	return nil
}

// Evaluate runs a request through the repo policy and returns a decision.
func (p *Policy) Evaluate(req Request, reg *extension.Registry) Decision {
	if p == nil {
		return Decision{Effect: policy.EffectDeny, Errors: []string{"Evaluate requires non-nil Policy"}}
	}
	decision := policy.Effect("")
	matched := []string{}
	ctx := condition.EvalContext{}
	for k, v := range req.Context {
		ctx[k] = v
	}
	ctx["request.action"] = req.Action
	ctx["request.resource"] = req.Resource
	ctx["file.path"] = req.Resource
	if _, ok := ctx["resource"]; !ok {
		ctx["resource"] = req.Resource
	}
	for _, r := range p.Rules {
		if !util.MatchAction(r.Action, req.Action) {
			continue
		}
		if !util.MatchResource(r.Resource, req.Resource) {
			continue
		}
		if r.Condition != nil {
			ok, err := condition.EvaluateStrict(*r.Condition, ctx, reg)
			if err != nil {
				return Decision{Effect: policy.EffectNever, Errors: []string{fmt.Sprintf("rule %q condition error: %v", r.Name, err)}}
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
	if decision == "" {
		decision = p.defaultFor(req.Action)
	}
	return Decision{Effect: decision, MatchedRules: matched}
}

// defaultFor looks up the default effect for an action, falling back to "*" then deny.
func (p *Policy) defaultFor(action string) policy.Effect {
	if p.Default != nil {
		if e, ok := p.Default[action]; ok {
			return e
		}
		if e, ok := p.Default["*"]; ok {
			return e
		}
	}
	return policy.EffectDeny
}
