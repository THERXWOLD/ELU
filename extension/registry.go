// Extension registry — the plugin backbone for custom operators, pack types,
// and validators. Register stuff here so the core doesn't need to know about it.
package extension

import "sync"

// OperatorFunc evaluates a condition operator at runtime.
// Takes left and right operands, returns whether the condition holds.
// Panics are caught by the caller, so don't worry about crashing the host.
type OperatorFunc func(left any, right any) bool

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

// Registry is a thread-safe container for operators, pack types, and validators.
// Use NewRegistry to get one with the built-in types preloaded.
type Registry struct {
	mu         sync.RWMutex
	operators  map[string]OperatorFunc
	packTypes  map[string]bool
	validators map[string]ValidatorFunc
}

// NewRegistry creates a registry preloaded with all built-in and future pack types.
func NewRegistry() *Registry {
	r := &Registry{
		operators:  map[string]OperatorFunc{},
		packTypes:  map[string]bool{},
		validators: map[string]ValidatorFunc{},
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
func (r *Registry) RegisterPackType(name string) {
	if name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packTypes[name] = true
}

// HasPackType reports whether a pack type is known to the registry.
func (r *Registry) HasPackType(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.packTypes[name]
}

// RegisterOperator adds a custom condition operator.
// Name must be non-empty and fn must not be nil, otherwise it's a no-op.
func (r *Registry) RegisterOperator(name string, fn OperatorFunc) {
	if name == "" || fn == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.operators[name] = fn
}

// Operator looks up a registered operator by name.
func (r *Registry) Operator(name string) (OperatorFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.operators[name]
	return fn, ok
}

// RegisterValidator registers a custom validator for a pack type.
// Also registers the pack type itself so it passes HasPackType checks.
func (r *Registry) RegisterValidator(packType string, fn ValidatorFunc) {
	if packType == "" || fn == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packTypes[packType] = true
	r.validators[packType] = fn
}

// Validator looks up a registered validator by pack type.
func (r *Registry) Validator(packType string) (ValidatorFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.validators[packType]
	return fn, ok
}
