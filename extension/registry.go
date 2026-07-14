// Extension registry — the plugin backbone for custom operators, pack types,
// and validators. Register stuff here so the core doesn't need to know about it.
package extension

import (
	"fmt"
	"reflect"
	"sync"
)

// OperatorSpec describes a custom operator with optional argument validation.
// Zero-value LeftType/RightType mean "any type accepted" for that operand.
type OperatorSpec struct {
	Fn        OperatorFunc
	LeftType  reflect.Kind
	RightType reflect.Kind
}

// OperatorFunc evaluates a condition operator at runtime.
// Takes left and right operands, returns whether the condition holds and any error.
// Panics are caught by the caller, so don't worry about crashing the host.
type OperatorFunc func(left any, right any) (bool, error)

// ValidatorFunc validates a pack after it's been parsed.
// The built-in validate package passes *ast.File for custom validators.
type ValidatorFunc func(pack any) error

// ImplementedPackTypes are the pack types that ship with built-in semantic
// validation. If it's not here, you need to register your own validator.
var ImplementedPackTypes = []string{
	"skill_pack",
	"repo_policy",
	"access_policy",
	"route_policy",
	"guardrail_pack",
	"filter_pack",
}

// futurePackTypes are recognized but don't have semantic validation yet.
// They're placeholders for the roadmap so the registry doesn't reject them.
var futurePackTypes = []string{
	"behavior_pack",
	"flow_pack",
	"memory_pack",
	"voice_pack",
	"workflow_policy",
	"feature_policy",
	"audit_policy",
	"dataset_pack",
	"eval_pack",
}

// IsImplementedPackType checks if a pack type has built-in validation.
func IsImplementedPackType(typ string) bool {
	for _, t := range ImplementedPackTypes {
		if t == typ {
			return true
		}
	}
	return false
}

// noCopy is a marker type to prevent copying of Registry instances.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// Registry is a thread-safe container for operators, pack types, and validators.
// Use NewRegistry to get one with the built-in types preloaded.
type Registry struct {
	_             noCopy
	mu            sync.RWMutex
	operators     map[string]OperatorFunc
	operatorSpecs map[string]OperatorSpec
	packTypes     map[string]bool
	validators    map[string]ValidatorFunc
}

// NewRegistry creates a registry preloaded with all built-in and future pack types.
func NewRegistry() *Registry {
	r := &Registry{
		operators:     map[string]OperatorFunc{},
		operatorSpecs: map[string]OperatorSpec{},
		packTypes:     map[string]bool{},
		validators:    map[string]ValidatorFunc{},
	}
	for _, typ := range ImplementedPackTypes {
		r.packTypes[typ] = true
	}
	for _, typ := range futurePackTypes {
		r.packTypes[typ] = true
	}
	return r
}

// RegisterPackType adds a custom pack type to the registry so it passes
// validation even without a registered validator.
func (r *Registry) RegisterPackType(name string) error {
	if r == nil {
		return fmt.Errorf("RegisterPackType called on nil Registry")
	}
	if name == "" {
		return fmt.Errorf("invalid pack type: name=%q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packTypes[name] = true
	return nil
}

// HasPackType reports whether a pack type is known to the registry.
func (r *Registry) HasPackType(name string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.packTypes[name]
}

// RegisterOperator adds a custom condition operator.
// Name must be non-empty and fn must not be nil, otherwise it's a no-op.
func (r *Registry) RegisterOperator(name string, fn OperatorFunc) error {
	if r == nil {
		return fmt.Errorf("RegisterOperator called on nil Registry")
	}
	if name == "" || fn == nil {
		return fmt.Errorf("invalid operator: name=%q, fn=%v", name, fn)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.operators[name] = fn
	return nil
}

// RegisterOperatorSpec registers a custom operator with optional type validation.
func (r *Registry) RegisterOperatorSpec(name string, spec OperatorSpec) error {
	if r == nil {
		return fmt.Errorf("RegisterOperatorSpec called on nil Registry")
	}
	if name == "" || spec.Fn == nil {
		return fmt.Errorf("invalid operator spec: name=%q, fn=%v", name, spec.Fn)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.operators[name] = spec.Fn
	r.operatorSpecs[name] = spec
	return nil
}

// OperatorSpec returns the registered type spec for an operator name.
func (r *Registry) OperatorSpec(name string) (OperatorSpec, bool) {
	if r == nil {
		return OperatorSpec{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	spec, ok := r.operatorSpecs[name]
	return spec, ok
}

// Operator looks up a registered operator by name.
func (r *Registry) Operator(name string) (OperatorFunc, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.operators[name]
	return fn, ok
}

// RegisterValidator registers a custom validator for a pack type.
// Also registers the pack type itself so it passes HasPackType checks.
func (r *Registry) RegisterValidator(packType string, fn ValidatorFunc) error {
	if r == nil {
		return fmt.Errorf("RegisterValidator called on nil Registry")
	}
	if packType == "" || fn == nil {
		return fmt.Errorf("invalid validator: packType=%q, fn=%v", packType, fn)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packTypes[packType] = true
	r.validators[packType] = fn
	return nil
}

// Validator looks up a registered validator by pack type.
func (r *Registry) Validator(packType string) (ValidatorFunc, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.validators[packType]
	return fn, ok
}
