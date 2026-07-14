// Package validate is the validation entrypoint for ELU documents.
// It dispatches to the right decoder/validator based on pack type.
package validate

import (
	"fmt"
	"github.com/therxwold/elu/access"
	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/diag"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/filter"
	"github.com/therxwold/elu/guardrail"
	"github.com/therxwold/elu/repo"
	"github.com/therxwold/elu/route"
	"github.com/therxwold/elu/skill"
)

// ProductionFile applies strict production defaults: unknown pack types
// are errors, and custom types without validators are rejected.
func ProductionFile(f *ast.File, reg *extension.Registry) diag.Diagnostics {
	return File(f, reg, true)
}

// File validates an ELU document. In strict mode, unknown pack types are errors
// and custom types must have registered validators. In non-strict mode, unknown
// types get warnings instead.
func File(f *ast.File, reg *extension.Registry, strict bool) diag.Diagnostics {
	if f == nil {
		return diag.Diagnostics{{Severity: diag.Error, File: "", Message: "nil ast.File"}}
	}
	if reg == nil {
		reg = extension.NewRegistry()
	}
	var diags diag.Diagnostics
	if f.PackID == "" {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Message: "missing pack id"})
	}
	if f.Version <= 0 {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Message: "version must be positive"})
	}
	if f.Type == "" {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Message: "missing type"})
		return diags
	}
	if !reg.HasPackType(f.Type) {
		sev := diag.Warning
		if strict {
			sev = diag.Error
		}
		diags = append(diags, diag.Diagnostic{Severity: sev, File: f.Path, Message: "unknown pack type " + f.Type})
		return diags
	}
	implemented := extension.IsImplementedPackType(f.Type)
	diags = append(diags, validateImplemented(f, reg)...)
	if fn, ok := reg.Validator(f.Type); ok {
		if err := runCustomValidator(fn, f); err != nil {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Message: err.Error()})
		}
	} else if strict && !implemented {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: f.Path, Message: "pack type " + f.Type + " is registered but has no strict validator"})
	}
	return diags
}

// validateImplemented dispatches to the appropriate pack decoder/validator
// based on the file's type field.
func validateImplemented(f *ast.File, reg *extension.Registry) diag.Diagnostics {
	switch f.Type {
	case "access_policy":
		p, err := access.Decode(f)
		if err != nil {
			return wrapDiagnostics(err, f.Path)
		}
		return wrapDiagnostics(access.ValidatePolicy(p, reg), f.Path)
	case "skill_pack":
		_, err := skill.Decode(f)
		return wrapDiagnostics(err, f.Path)
	case "repo_policy":
		p, err := repo.Decode(f)
		if err != nil {
			return wrapDiagnostics(err, f.Path)
		}
		return wrapDiagnostics(repo.ValidatePolicy(p, reg), f.Path)
	case "route_policy":
		p, err := route.Decode(f)
		if err != nil {
			return wrapDiagnostics(err, f.Path)
		}
		return wrapDiagnostics(route.ValidatePolicy(p, reg), f.Path)
	case "guardrail_pack":
		_, err := guardrail.Decode(f)
		return wrapDiagnostics(err, f.Path)
	case "filter_pack":
		_, err := filter.Decode(f)
		return wrapDiagnostics(err, f.Path)
	case "behavior_pack", "flow_pack", "memory_pack", "voice_pack", "workflow_policy", "feature_policy", "audit_policy", "dataset_pack", "eval_pack":
		return nil
	default:
		return nil
	}
}

// runCustomValidator wraps a custom validator call with panic recovery.
func runCustomValidator(fn extension.ValidatorFunc, f *ast.File) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("custom validator for %q panicked: %v", f.Type, r)
		}
	}()
	return fn(f)
}

// wrapDiagnostics converts an error to diag.Diagnostics.
// If the error is already diag.Diagnostics, it's returned as-is.
// If nil, returns nil.
func wrapDiagnostics(err error, filePath string) diag.Diagnostics {
	if err == nil {
		return nil
	}
	if d, ok := err.(diag.Diagnostics); ok {
		return d
	}
	return diag.Diagnostics{{Severity: diag.Error, File: filePath, Message: err.Error()}}
}
