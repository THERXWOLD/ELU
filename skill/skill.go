// Package skill decodes and validates skill_pack ELU files.
// Skills are agent capability manifests — what tools they use, what they can do,
// and what they're forbidden from touching.
package skill

import (
	"fmt"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/diag"
	"github.com/therxwold/elu/internal/util"
	"github.com/therxwold/elu/policy"
)

// Pack is a decoded skill_pack. Exactly one skill per pack.
type Pack struct {
	PackID  string
	Version int
	Skill   Skill
}

// Skill describes an agent's capability: what triggers it, what tools it uses,
// which targets are allowed/proposed/forbidden, and the steps to execute.
type Skill struct {
	ID                 string
	Title              string
	Category           string
	Risk               string
	Autonomy           string
	Uses               Uses
	Triggers           []string
	Accepts            []string
	AllowedTargets     []string
	ProposeOnlyTargets []string
	ApprovalTargets    []string
	ForbiddenTargets   []string
	Steps              []string
	DoneWhen           []string
	Never              []string
}

// Uses declares which tools and policies a skill depends on.
type Uses struct {
	Tools    []string
	Policies []string
}

// Decode parses an AST into a validated skill_pack.
// Returns all errors at once via diag.Diagnostics.
func Decode(f *ast.File) (*Pack, error) {
	if f.Type != "skill_pack" {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Message: fmt.Sprintf("expected skill_pack, got %q", f.Type)}}
	}
	var block *ast.Node
	for _, n := range f.Nodes {
		if n.Kind == ast.NodeBlock && n.Key == "skill" {
			if block != nil {
				return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Message: "skill_pack allows exactly one skill block"}}
			}
			block = n
			continue
		}
		return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Line: n.Line, Message: fmt.Sprintf("unexpected top-level %s %q in skill_pack", n.Kind, n.Key)}}
	}
	if block == nil {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Message: "skill_pack requires skill block"}}
	}
	if block.Name == "" {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Line: block.Line, Message: "skill block requires a name"}}
	}
	p := &Pack{PackID: f.PackID, Version: f.Version, Skill: Skill{ID: block.Name}}
	var diags diag.Diagnostics
	seen := map[string]bool{}
	for _, child := range block.Children {
		switch child.Kind {
		case ast.NodeAssign:
			if seen[child.Key] {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("skill %q has duplicate field %q", block.Name, child.Key)})
				continue
			}
			seen[child.Key] = true
			switch child.Key {
			case "title":
				p.Skill.Title = child.Value.StringValue()
			case "category":
				p.Skill.Category = child.Value.StringValue()
			case "risk":
				p.Skill.Risk = child.Value.StringValue()
			case "autonomy":
				p.Skill.Autonomy = child.Value.StringValue()
			default:
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("skill %q has unknown field %q", block.Name, child.Key)})
			}
		case ast.NodeSection:
			if seen[child.Key] {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("skill %q has duplicate section %q", block.Name, child.Key)})
				continue
			}
			seen[child.Key] = true
			switch child.Key {
			case "uses":
				uses, err := decodeUses(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.Uses = uses
			case "triggers":
				xs, err := util.StringList(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.Triggers = xs
			case "accepts":
				xs, err := util.StringList(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.Accepts = xs
			case "allowed_targets":
				xs, err := util.StringList(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.AllowedTargets = xs
			case "propose_only_targets":
				xs, err := util.StringList(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.ProposeOnlyTargets = xs
			case "approval_targets":
				xs, err := util.StringList(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.ApprovalTargets = xs
			case "forbidden_targets":
				xs, err := util.StringList(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.ForbiddenTargets = xs
			case "steps":
				xs, err := util.StringList(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.Steps = xs
			case "done_when":
				xs, err := util.StringList(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.DoneWhen = xs
			case "never":
				xs, err := util.StringList(child)
				if err != nil {
					diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: err.Error()})
					continue
				}
				p.Skill.Never = xs
			default:
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("skill %q has unknown section %q", block.Name, child.Key)})
			}
		default:
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: child.Line, Message: fmt.Sprintf("skill %q has invalid child", block.Name)})
		}
	}
	if err := Validate(p); err != nil {
		if d, ok := err.(diag.Diagnostics); ok {
			diags = append(diags, d...)
		} else {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Message: err.Error()})
		}
	}
	if diags.HasErrors() {
		return nil, diags
	}
	return p, nil
}

// Validate checks that a skill_pack has the required fields and valid target groups.
// Returns all errors at once via diag.Diagnostics.
func Validate(p *Pack) error {
	var diags diag.Diagnostics
	if p.Skill.ID == "" {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: "skill id must not be empty"})
	}
	if p.Skill.Category == "" {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("skill %q is missing required field category", p.Skill.ID)})
	}
	if p.Skill.Risk == "" {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("skill %q is missing required field risk", p.Skill.ID)})
	}
	if !policy.IsSeverity(p.Skill.Risk) {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("skill %q has invalid risk %q", p.Skill.ID, p.Skill.Risk)})
	}
	if len(p.Skill.Steps) == 0 {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("skill %q requires at least one step", p.Skill.ID)})
	}
	if len(p.Skill.DoneWhen) == 0 && (p.Skill.Risk == "high" || p.Skill.Risk == "critical") {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("skill %q with risk %q requires done_when", p.Skill.ID, p.Skill.Risk)})
	}
	targetGroups := []struct {
		name string
		xs   []string
	}{
		{"allowed_targets", p.Skill.AllowedTargets},
		{"propose_only_targets", p.Skill.ProposeOnlyTargets},
		{"approval_targets", p.Skill.ApprovalTargets},
		{"forbidden_targets", p.Skill.ForbiddenTargets},
	}
	for i := 0; i < len(targetGroups); i++ {
		for j := i + 1; j < len(targetGroups); j++ {
			if x := overlap(targetGroups[i].xs, targetGroups[j].xs); x != "" {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("skill %q target %q appears in both %s and %s", p.Skill.ID, x, targetGroups[i].name, targetGroups[j].name)})
			}
		}
	}
	if diags.HasErrors() {
		return diags
	}
	return nil
}

// decodeUses extracts the uses section (tools + policies).
func decodeUses(sec *ast.Node) (Uses, error) {
	var u Uses
	seen := map[string]bool{}
	for _, child := range sec.Children {
		if child.Kind != ast.NodeSection {
			return u, fmt.Errorf("uses section at line %d expects nested sections", child.Line)
		}
		if seen[child.Key] {
			return u, fmt.Errorf("duplicate uses section %q at line %d", child.Key, child.Line)
		}
		seen[child.Key] = true
		switch child.Key {
		case "tools":
			xs, err := util.StringList(child)
			if err != nil {
				return u, err
			}
			u.Tools = xs
		case "policies":
			xs, err := util.StringList(child)
			if err != nil {
				return u, err
			}
			u.Policies = xs
		default:
			return u, fmt.Errorf("unknown uses section %q at line %d", child.Key, child.Line)
		}
	}
	return u, nil
}

// overlap checks if two string slices share any element.
// Returns the first overlapping element, or empty string.
func overlap(a, b []string) string {
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if m[x] {
			return x
		}
	}
	return ""
}
