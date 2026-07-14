// Package guardrail decodes and validates guardrail_pack ELU files.
// Guardrails are hard safety rules: never do X, never edit Y, require approval for Z.
package guardrail

import (
	"fmt"
	"regexp"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/internal/util"
	"github.com/therxwold/elu/policy"
)

// Pack is a decoded guardrail_pack.
type Pack struct {
	PackID     string
	Version    int
	Priority   string
	Guardrails []Guardrail
}

// Guardrail is a single safety rule with severity, scope, and violation handling.
type Guardrail struct {
	Name             string
	Severity         string
	AppliesTo        []string
	Never            []string
	NeverEdit        []string
	RequiresApproval map[string][]string
	OnViolation      map[string]string
}

var actionTokenRE *regexp.Regexp

// init initializes the regexes used by the parser.
func init() {
	var err error
	actionTokenRE, err = regexp.Compile(`^[A-Za-z_][A-Za-z0-9_.:-]*$`)
	if err != nil {
		panic("elu.guardrail: failed to compile action token regex: " + err.Error())
	}
}

// Decode parses an AST into a validated guardrail_pack.
func Decode(f *ast.File) (*Pack, error) {
	if f.Type != "guardrail_pack" {
		return nil, fmt.Errorf("expected guardrail_pack, got %q", f.Type)
	}
	p := &Pack{PackID: f.PackID, Version: f.Version}
	seenNames := map[string]bool{}
	seenTopAssign := map[string]bool{}
	for _, n := range f.Nodes {
		switch n.Kind {
		case ast.NodeAssign:
			if seenTopAssign[n.Key] {
				return nil, fmt.Errorf("duplicate top-level field %q at line %d", n.Key, n.Line)
			}
			seenTopAssign[n.Key] = true
			if n.Key != "priority" {
				return nil, fmt.Errorf("unknown top-level field %q at line %d in guardrail_pack", n.Key, n.Line)
			}
			p.Priority = n.Value.StringValue()
		case ast.NodeBlock:
			if n.Key != "guardrail" {
				return nil, fmt.Errorf("unexpected top-level block %q at line %d in guardrail_pack", n.Key, n.Line)
			}
			if n.Name == "" {
				return nil, fmt.Errorf("guardrail block at line %d requires a name", n.Line)
			}
			if seenNames[n.Name] {
				return nil, fmt.Errorf("duplicate guardrail %q", n.Name)
			}
			seenNames[n.Name] = true
			g, err := decodeGuardrail(n)
			if err != nil {
				return nil, err
			}
			p.Guardrails = append(p.Guardrails, g)
		default:
			return nil, fmt.Errorf("unexpected top-level %s %q at line %d in guardrail_pack", n.Kind, n.Key, n.Line)
		}
	}
	if err := Validate(p); err != nil {
		return nil, err
	}
	return p, nil
}

// decodeGuardrail extracts a single Guardrail from its AST block node.
func decodeGuardrail(n *ast.Node) (Guardrail, error) {
	g := Guardrail{Name: n.Name, RequiresApproval: map[string][]string{}, OnViolation: map[string]string{}}
	seen := map[string]bool{}
	for _, child := range n.Children {
		switch child.Kind {
		case ast.NodeAssign:
			if seen[child.Key] {
				return g, fmt.Errorf("guardrail %q has duplicate field %q at line %d", g.Name, child.Key, child.Line)
			}
			seen[child.Key] = true
			if child.Key != "severity" {
				return g, fmt.Errorf("guardrail %q has unknown field %q at line %d", g.Name, child.Key, child.Line)
			}
			g.Severity = child.Value.StringValue()
		case ast.NodeSection:
			if seen[child.Key] {
				return g, fmt.Errorf("guardrail %q has duplicate section %q at line %d", g.Name, child.Key, child.Line)
			}
			seen[child.Key] = true
			switch child.Key {
			case "applies_to":
				xs, err := util.StringList(child)
				if err != nil {
					return g, err
				}
				g.AppliesTo = xs
			case "never":
				xs, err := util.StringList(child)
				if err != nil {
					return g, err
				}
				g.Never = xs
			case "never_edit":
				xs, err := util.StringList(child)
				if err != nil {
					return g, err
				}
				g.NeverEdit = xs
			case "requires_approval":
				m, err := actionMap(child)
				if err != nil {
					return g, err
				}
				g.RequiresApproval = m
			case "on_violation":
				m, err := assignMap(child)
				if err != nil {
					return g, err
				}
				g.OnViolation = m
			default:
				return g, fmt.Errorf("guardrail %q has unknown section %q at line %d", g.Name, child.Key, child.Line)
			}
		default:
			return g, fmt.Errorf("guardrail %q has invalid child at line %d", g.Name, child.Line)
		}
	}
	return g, nil
}

// Validate checks that a guardrail_pack has valid structure and coherent rules.
func Validate(p *Pack) error {
	if p.Priority != "" && !policy.IsSeverity(p.Priority) {
		return fmt.Errorf("invalid guardrail pack priority %q", p.Priority)
	}
	if len(p.Guardrails) == 0 {
		return fmt.Errorf("guardrail_pack requires at least one guardrail")
	}
	for _, g := range p.Guardrails {
		if g.Name == "" {
			return fmt.Errorf("guardrail name must not be empty")
		}
		if g.Severity == "" {
			return fmt.Errorf("guardrail %q is missing required field severity", g.Name)
		}
		if !policy.IsSeverity(g.Severity) {
			return fmt.Errorf("guardrail %q has invalid severity %q", g.Name, g.Severity)
		}
		if len(g.Never) == 0 && len(g.NeverEdit) == 0 && len(g.RequiresApproval) == 0 {
			return fmt.Errorf("guardrail %q must define never, never_edit, or requires_approval", g.Name)
		}
		if err := validateOnViolation(g.Name, g.Severity, g.OnViolation); err != nil {
			return err
		}
	}
	return nil
}

// validateOnViolation checks that on_violation has valid action and report settings.
// Critical-severity guardrails require enforcing actions (block, deny, etc.).
func validateOnViolation(name, severity string, m map[string]string) error {
	if len(m) == 0 {
		return nil
	}
	action := ""
	for k, v := range m {
		switch k {
		case "action":
			if !isViolationAction(v) {
				return fmt.Errorf("guardrail %q has invalid on_violation action %q", name, v)
			}
			action = v
		case "report":
			if v == "" {
				return fmt.Errorf("guardrail %q on_violation report must not be empty", name)
			}
		default:
			return fmt.Errorf("guardrail %q has unknown on_violation key %q", name, k)
		}
	}
	if action == "" {
		return fmt.Errorf("guardrail %q on_violation requires action", name)
	}
	if severity == "critical" && !isEnforcingViolationAction(action) {
		return fmt.Errorf("critical guardrail %q requires enforcing on_violation action, got %q", name, action)
	}
	return nil
}

// isEnforcingViolationAction checks if an action is strong enough for critical severity.
func isEnforcingViolationAction(action string) bool {
	switch action {
	case "block", "deny", "never", "require_approval", "redact", "mask":
		return true
	default:
		return false
	}
}

// isViolationAction checks if a string is a valid on_violation action keyword.
func isViolationAction(action string) bool {
	switch action {
	case "block", "redact", "mask", "log", "audit", "require_approval", "deny", "never", "report":
		return true
	default:
		return false
	}
}

// actionMap extracts a map of action → string list from a section node.
func actionMap(sec *ast.Node) (map[string][]string, error) {
	out := map[string][]string{}
	for _, child := range sec.Children {
		if child.Kind != ast.NodeSection {
			return nil, fmt.Errorf("section %q expects action sections at line %d", sec.Key, child.Line)
		}
		if _, ok := out[child.Key]; ok {
			return nil, fmt.Errorf("duplicate action section %q at line %d", child.Key, child.Line)
		}
		xs, err := util.StringList(child)
		if err != nil {
			return nil, err
		}
		out[child.Key] = xs
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("section %q at line %d must not be empty", sec.Key, sec.Line)
	}
	return out, nil
}

// assignMap extracts a key=value map from a section node.
func assignMap(sec *ast.Node) (map[string]string, error) {
	out := map[string]string{}
	for _, child := range sec.Children {
		if child.Kind != ast.NodeAssign {
			return nil, fmt.Errorf("section %q expects assignments at line %d", sec.Key, child.Line)
		}
		if _, ok := out[child.Key]; ok {
			return nil, fmt.Errorf("duplicate assignment %q at line %d", child.Key, child.Line)
		}
		out[child.Key] = child.Value.StringValue()
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("section %q at line %d must not be empty", sec.Key, sec.Line)
	}
	return out, nil
}

// isValidActionToken checks if a string is a valid action token or wildcard.
func isValidActionToken(action string) bool {
	return action == "*" || actionTokenRE.MatchString(action)
}
