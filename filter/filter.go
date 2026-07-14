// Package filter decodes and validates filter_pack ELU files.
// Filter packs define detection, redaction, and blocking rules.
package filter

import (
	"fmt"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/diag"
	"github.com/therxwold/elu/internal/util"
)

// Pack is a decoded filter_pack. It holds one or more filter definitions.
type Pack struct {
	PackID  string
	Version int
	Filters []Filter
}

// Filter defines a single detection/redaction/blocking rule.
// AppliesTo limits which resources the filter applies to; Detect/DetectChange/
// BlockPaths define what to look for; Action/Escalate define what to do.
type Filter struct {
	Name         string
	AppliesTo    []string
	Detect       []string
	DetectChange []string
	BlockPaths   []string
	Action       map[string]string
	Escalate     map[string]string
}

// Decode parses an AST into a validated filter_pack.
// Returns all errors at once via diag.Diagnostics.
func Decode(f *ast.File) (*Pack, error) {
	if f.Type != "filter_pack" {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: f.Path, Message: fmt.Sprintf("expected filter_pack, got %q", f.Type)}}
	}
	p := &Pack{PackID: f.PackID, Version: f.Version}
	var diags diag.Diagnostics
	seen := map[string]bool{}
	for _, n := range f.Nodes {
		if n.Kind != ast.NodeBlock || n.Key != "filter" {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: n.Line, Message: fmt.Sprintf("unexpected top-level %s %q in filter_pack", n.Kind, n.Key)})
			continue
		}
		if n.Name == "" {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: n.Line, Message: "filter block requires a name"})
			continue
		}
		if seen[n.Name] {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: n.Line, Message: fmt.Sprintf("duplicate filter %q", n.Name)})
			continue
		}
		seen[n.Name] = true
		filt, err := decodeFilter(n)
		if err != nil {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Line: n.Line, Message: err.Error()})
			continue
		}
		p.Filters = append(p.Filters, filt)
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

// decodeFilter extracts a single Filter from its AST block node.
func decodeFilter(n *ast.Node) (Filter, error) {
	f := Filter{Name: n.Name, Action: map[string]string{}, Escalate: map[string]string{}}
	seen := map[string]bool{}
	for _, child := range n.Children {
		if child.Kind != ast.NodeSection {
			return f, fmt.Errorf("filter %q expects sections; invalid child at line %d", f.Name, child.Line)
		}
		if seen[child.Key] {
			return f, fmt.Errorf("filter %q has duplicate section %q at line %d", f.Name, child.Key, child.Line)
		}
		seen[child.Key] = true
		switch child.Key {
		case "applies_to":
			xs, err := util.StringList(child)
			if err != nil {
				return f, err
			}
			f.AppliesTo = xs
		case "detect":
			xs, err := util.StringList(child)
			if err != nil {
				return f, err
			}
			f.Detect = xs
		case "detect_change":
			xs, err := util.StringList(child)
			if err != nil {
				return f, err
			}
			f.DetectChange = xs
		case "block_paths":
			xs, err := util.StringList(child)
			if err != nil {
				return f, err
			}
			f.BlockPaths = xs
		case "action":
			m, err := assignMap(child)
			if err != nil {
				return f, err
			}
			f.Action = m
		case "escalate":
			m, err := assignMap(child)
			if err != nil {
				return f, err
			}
			f.Escalate = m
		default:
			return f, fmt.Errorf("filter %q has unknown section %q at line %d", f.Name, child.Key, child.Line)
		}
	}
	return f, nil
}

// Validate checks that a filter_pack has valid structure and coherent actions.
// Returns all errors at once via diag.Diagnostics.
func Validate(p *Pack) error {
	var diags diag.Diagnostics
	if len(p.Filters) == 0 {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: "filter_pack requires at least one filter"})
	}
	for _, f := range p.Filters {
		if f.Name == "" {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: "filter name must not be empty"})
			continue
		}
		if len(f.AppliesTo) == 0 {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("filter %q requires applies_to", f.Name)})
		}
		if len(f.Detect) == 0 && len(f.DetectChange) == 0 && len(f.BlockPaths) == 0 {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("filter %q requires detect, detect_change, or block_paths", f.Name)})
		}
		if len(f.Action) == 0 {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: fmt.Sprintf("filter %q requires action", f.Name)})
		}
		if err := validateActionMap(f.Name, f.Action); err != nil {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: err.Error()})
		}
		if err := validateDetectorActions(f); err != nil {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: err.Error()})
		}
		if err := validateEscalateMap(f.Name, f.Escalate); err != nil {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, Message: err.Error()})
		}
	}
	if diags.HasErrors() {
		return diags
	}
	return nil
}

// validateDetectorActions ensures action keys match the detector types present.
// e.g., on_detect only makes sense if detect is defined.
func validateDetectorActions(f Filter) error {
	hasDetect := len(f.Detect) > 0
	hasBlockPaths := len(f.BlockPaths) > 0
	hasDetectChange := len(f.DetectChange) > 0
	if hasDetect {
		if _, ok := f.Action["on_detect"]; !ok {
			if _, ok := f.Action["on_output_detect"]; !ok {
				return fmt.Errorf("filter %q with detect requires on_detect or on_output_detect action", f.Name)
			}
		}
	}
	if hasBlockPaths {
		if _, ok := f.Action["on_match"]; !ok {
			return fmt.Errorf("filter %q with block_paths requires on_match action", f.Name)
		}
	}
	if hasDetectChange {
		if _, ok := f.Action["on_change_detect"]; !ok {
			return fmt.Errorf("filter %q with detect_change requires on_change_detect action", f.Name)
		}
	}
	if !hasDetect {
		if _, ok := f.Action["on_detect"]; ok {
			return fmt.Errorf("filter %q uses on_detect without detect", f.Name)
		}
		if _, ok := f.Action["on_output_detect"]; ok {
			return fmt.Errorf("filter %q uses on_output_detect without detect", f.Name)
		}
	}
	if !hasBlockPaths {
		if _, ok := f.Action["on_match"]; ok {
			return fmt.Errorf("filter %q uses on_match without block_paths", f.Name)
		}
	}
	if !hasDetectChange {
		if _, ok := f.Action["on_change_detect"]; ok {
			return fmt.Errorf("filter %q uses on_change_detect without detect_change", f.Name)
		}
	}
	return nil
}

// validateActionMap checks action keys and values for validity.
func validateActionMap(name string, m map[string]string) error {
	hasRedaction := false
	for k, v := range m {
		switch k {
		case "on_detect", "on_output_detect", "on_match", "on_change_detect":
			if !isFilterAction(v) {
				return fmt.Errorf("filter %q has invalid action value %q for %q", name, v, k)
			}
			if !isActionAllowedForKey(k, v) {
				return fmt.Errorf("filter %q cannot use action %q for %q", name, v, k)
			}
			if v == "redact" || v == "mask" {
				hasRedaction = true
			}
		case "replacement":
			if v == "" {
				return fmt.Errorf("filter %q replacement must not be empty", name)
			}
		default:
			return fmt.Errorf("filter %q has unknown action key %q", name, k)
		}
	}
	if _, ok := m["replacement"]; ok && !hasRedaction {
		return fmt.Errorf("filter %q replacement is only valid with redact or mask actions", name)
	}
	return nil
}

// isActionAllowedForKey checks if a specific action value is valid for a key.
func isActionAllowedForKey(key, action string) bool {
	switch key {
	case "on_detect", "on_output_detect":
		switch action {
		case "redact", "mask", "block", "report", "audit":
			return true
		}
	case "on_match":
		switch action {
		case "deny", "block", "require_approval", "audit", "report":
			return true
		}
	case "on_change_detect":
		switch action {
		case "require_approval", "block", "deny", "audit", "report":
			return true
		}
	}
	return false
}

// validateEscalateMap checks the escalate section's structure.
func validateEscalateMap(name string, m map[string]string) error {
	if len(m) == 0 {
		return nil
	}
	hasWhen := false
	hasAction := false
	for k, v := range m {
		switch k {
		case "when":
			hasWhen = true
			if v == "" {
				return fmt.Errorf("filter %q escalate.when must not be empty", name)
			}
		case "action":
			hasAction = true
			if !isFilterAction(v) {
				return fmt.Errorf("filter %q has invalid escalate action %q", name, v)
			}
		default:
			return fmt.Errorf("filter %q has unknown escalate key %q", name, k)
		}
	}
	if !hasWhen || !hasAction {
		return fmt.Errorf("filter %q escalate requires both when and action", name)
	}
	return nil
}

// isFilterAction checks if a string is a valid filter action keyword.
func isFilterAction(action string) bool {
	switch action {
	case "block", "redact", "mask", "log", "audit", "require_approval", "deny", "report":
		return true
	default:
		return false
	}
}

// assignMap extracts a key=value map from a section node.
// Each child must be an assignment.
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
