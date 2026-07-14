// Package skill decodes and validates skill_pack ELU files.
// Skills are agent capability manifests — what tools they use, what they can do,
// and what they're forbidden from touching.
package skill

import (
	"fmt"

	"github.com/therxwold/elu/ast"
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
func Decode(f *ast.File) (*Pack, error) {
	if f.Type != "skill_pack" {
		return nil, fmt.Errorf("expected skill_pack, got %q", f.Type)
	}
	var block *ast.Node
	for _, n := range f.Nodes {
		if n.Kind == ast.NodeBlock && n.Key == "skill" {
			if block != nil {
				return nil, fmt.Errorf("skill_pack allows exactly one skill block")
			}
			block = n
			continue
		}
		return nil, fmt.Errorf("unexpected top-level %s %q at line %d in skill_pack", n.Kind, n.Key, n.Line)
	}
	if block == nil {
		return nil, fmt.Errorf("skill_pack requires skill block")
	}
	if block.Name == "" {
		return nil, fmt.Errorf("skill block at line %d requires a name", block.Line)
	}
	p := &Pack{PackID: f.PackID, Version: f.Version, Skill: Skill{ID: block.Name}}
	seen := map[string]bool{}
	for _, child := range block.Children {
		switch child.Kind {
		case ast.NodeAssign:
			if seen[child.Key] {
				return nil, fmt.Errorf("skill %q has duplicate field %q at line %d", block.Name, child.Key, child.Line)
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
				return nil, fmt.Errorf("skill %q has unknown field %q at line %d", block.Name, child.Key, child.Line)
			}
		case ast.NodeSection:
			if seen[child.Key] {
				return nil, fmt.Errorf("skill %q has duplicate section %q at line %d", block.Name, child.Key, child.Line)
			}
			seen[child.Key] = true
			switch child.Key {
			case "uses":
				uses, err := decodeUses(child)
				if err != nil {
					return nil, err
				}
				p.Skill.Uses = uses
			case "triggers":
				xs, err := util.StringList(child)
				if err != nil {
					return nil, err
				}
				p.Skill.Triggers = xs
			case "accepts":
				xs, err := util.StringList(child)
				if err != nil {
					return nil, err
				}
				p.Skill.Accepts = xs
			case "allowed_targets":
				xs, err := util.StringList(child)
				if err != nil {
					return nil, err
				}
				p.Skill.AllowedTargets = xs
			case "propose_only_targets":
				xs, err := util.StringList(child)
				if err != nil {
					return nil, err
				}
				p.Skill.ProposeOnlyTargets = xs
			case "approval_targets":
				xs, err := util.StringList(child)
				if err != nil {
					return nil, err
				}
				p.Skill.ApprovalTargets = xs
			case "forbidden_targets":
				xs, err := util.StringList(child)
				if err != nil {
					return nil, err
				}
				p.Skill.ForbiddenTargets = xs
			case "steps":
				xs, err := util.StringList(child)
				if err != nil {
					return nil, err
				}
				p.Skill.Steps = xs
			case "done_when":
				xs, err := util.StringList(child)
				if err != nil {
					return nil, err
				}
				p.Skill.DoneWhen = xs
			case "never":
				xs, err := util.StringList(child)
				if err != nil {
					return nil, err
				}
				p.Skill.Never = xs
			default:
				return nil, fmt.Errorf("skill %q has unknown section %q at line %d", block.Name, child.Key, child.Line)
			}
		default:
			return nil, fmt.Errorf("skill %q has invalid child at line %d", block.Name, child.Line)
		}
	}
	if err := Validate(p); err != nil {
		return nil, err
	}
	return p, nil
}

// Validate checks that a skill_pack has the required fields and valid target groups.
func Validate(p *Pack) error {
	if p.Skill.ID == "" {
		return fmt.Errorf("skill id must not be empty")
	}
	if p.Skill.Category == "" {
		return fmt.Errorf("skill %q is missing required field category", p.Skill.ID)
	}
	if p.Skill.Risk == "" {
		return fmt.Errorf("skill %q is missing required field risk", p.Skill.ID)
	}
	if !policy.IsSeverity(p.Skill.Risk) {
		return fmt.Errorf("skill %q has invalid risk %q", p.Skill.ID, p.Skill.Risk)
	}
	if len(p.Skill.Steps) == 0 {
		return fmt.Errorf("skill %q requires at least one step", p.Skill.ID)
	}
	if len(p.Skill.DoneWhen) == 0 && (p.Skill.Risk == "high" || p.Skill.Risk == "critical") {
		return fmt.Errorf("skill %q with risk %q requires done_when", p.Skill.ID, p.Skill.Risk)
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
				return fmt.Errorf("skill %q target %q appears in both %s and %s", p.Skill.ID, x, targetGroups[i].name, targetGroups[j].name)
			}
		}
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
