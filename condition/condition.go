// Package condition parses and evaluates ELU condition trees.
// Supports all/any/not groups and shorthand expressions like "file.exists eq false".
package condition

import (
	"fmt"
	"math"
	"reflect"
	"strings"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/internal/glob"
	"github.com/therxwold/elu/value"
)

// Condition is a node in the condition tree. It can be a logical group
// (All/Any/Not) or a leaf comparison (Field + Op + Value/Ref).
// Never both at the same time — validateShape enforces that.
type Condition struct {
	All   []Condition `json:"all,omitempty"`
	Any   []Condition `json:"any,omitempty"`
	Not   *Condition  `json:"not,omitempty"`
	Field string      `json:"field,omitempty"`
	Op    string      `json:"op,omitempty"`
	Value any         `json:"value,omitempty"`
	Ref   string      `json:"ref,omitempty"`
}

// EvalContext is a bag of key-value pairs that conditions evaluate against.
// Keys use dot notation for nesting (e.g. "resource.owner_id").
type EvalContext map[string]any

// ParseSection parses a "when" section node into a Condition tree.
func ParseSection(n *ast.Node) (Condition, error) {
	if n == nil || n.Kind != ast.NodeSection || n.Key != "when" {
		return Condition{}, fmt.Errorf("expected when section")
	}
	return parseChildren(n.Children)
}

// parseChildren is the recursive workhorse. It walks AST children and
// dispatches to the right handler based on node kind.
func parseChildren(children []*ast.Node) (Condition, error) {
	var cond Condition
	seenAssign := map[string]bool{}
	seenGroup := map[string]bool{}
	implicitAll := false
	for _, child := range children {
		switch {
		case child.Kind == ast.NodeListItem:
			if len(seenAssign) > 0 || len(seenGroup) > 0 || cond.Not != nil {
				return Condition{}, fmt.Errorf("implicit when list cannot be mixed with assignments or explicit groups at line %d", child.Line)
			}
			implicitAll = true
			c, err := parseListItem(child)
			if err != nil {
				return Condition{}, err
			}
			cond.All = append(cond.All, c)
		case child.Kind == ast.NodeSection && child.Key == "all":
			if implicitAll {
				return Condition{}, fmt.Errorf("explicit all condition group cannot be mixed with implicit when list at line %d", child.Line)
			}
			if seenGroup["all"] {
				return Condition{}, fmt.Errorf("duplicate all condition group at line %d", child.Line)
			}
			seenGroup["all"] = true
			list, err := parseList(child.Children)
			if err != nil {
				return Condition{}, err
			}
			cond.All = append(cond.All, list...)
		case child.Kind == ast.NodeSection && child.Key == "any":
			if implicitAll {
				return Condition{}, fmt.Errorf("any condition group cannot be mixed with implicit when list at line %d", child.Line)
			}
			if seenGroup["any"] {
				return Condition{}, fmt.Errorf("duplicate any condition group at line %d", child.Line)
			}
			seenGroup["any"] = true
			list, err := parseList(child.Children)
			if err != nil {
				return Condition{}, err
			}
			cond.Any = append(cond.Any, list...)
		case child.Kind == ast.NodeSection && child.Key == "not":
			if implicitAll {
				return Condition{}, fmt.Errorf("not condition group cannot be mixed with implicit when list at line %d", child.Line)
			}
			if seenGroup["not"] || cond.Not != nil {
				return Condition{}, fmt.Errorf("duplicate not condition at line %d", child.Line)
			}
			seenGroup["not"] = true
			c, err := parseChildren(child.Children)
			if err != nil {
				return Condition{}, err
			}
			cond.Not = &c
		case child.Kind == ast.NodeSection && child.Key == "value":
			if seenAssign["value"] || seenGroup["value"] || cond.Value != nil {
				return Condition{}, fmt.Errorf("duplicate condition key %q at line %d", child.Key, child.Line)
			}
			seenAssign["value"] = true
			seenGroup["value"] = true
			v, err := sectionValue(child)
			if err != nil {
				return Condition{}, err
			}
			cond.Value = v
		case child.Kind == ast.NodeAssign:
			if seenAssign[child.Key] || seenGroup[child.Key] {
				return Condition{}, fmt.Errorf("duplicate condition key %q at line %d", child.Key, child.Line)
			}
			seenAssign[child.Key] = true
			if err := applyAssign(&cond, child); err != nil {
				return Condition{}, err
			}
		default:
			return Condition{}, fmt.Errorf("invalid condition item %q at line %d", child.Key, child.Line)
		}
	}
	if len(cond.All) == 0 && len(cond.Any) == 0 && cond.Not == nil && cond.Field == "" {
		return Condition{}, fmt.Errorf("empty condition")
	}
	if err := validateShape(cond); err != nil {
		return Condition{}, err
	}
	return cond, nil
}

// parseList collects a list of list-item children into conditions.
// Each child must be a list item, no exceptions.
func parseList(children []*ast.Node) ([]Condition, error) {
	var out []Condition
	for _, child := range children {
		if child.Kind != ast.NodeListItem {
			return nil, fmt.Errorf("condition list contains non-list item at line %d", child.Line)
		}
		c, err := parseListItem(child)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("condition group must contain at least one item")
	}
	return out, nil
}

// parseListItem handles a single list item, which can be a shorthand
// expression (Expr field) or a structured condition object (Children).
func parseListItem(item *ast.Node) (Condition, error) {
	if item.Expr != "" {
		if len(item.Children) > 0 || item.Value.Kind != "" {
			return Condition{}, fmt.Errorf("condition shorthand list item cannot have value or children at line %d", item.Line)
		}
		return ParseExpression(item.Expr)
	}
	if len(item.Children) == 0 {
		return Condition{}, fmt.Errorf("condition list item must be an object or shorthand expression at line %d", item.Line)
	}
	if item.Value.Kind != "" {
		return Condition{}, fmt.Errorf("condition list item must be an object or shorthand expression at line %d", item.Line)
	}
	c, err := parseChildren(item.Children)
	if err != nil {
		return Condition{}, err
	}
	return c, nil
}

// ParseExpression parses the preferred ELU condition shorthand used in lists.
// Examples: "file.exists eq false", "resource.owner_id eq $subject.id",
// "not resource.status eq 'deleted'".
func ParseExpression(expr string) (Condition, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return Condition{}, fmt.Errorf("empty condition expression")
	}
	negated := false
	if strings.HasPrefix(expr, "not ") {
		negated = true
		expr = strings.TrimSpace(strings.TrimPrefix(expr, "not "))
	}
	tokens, err := splitExpressionTokens(expr)
	if err != nil {
		return Condition{}, err
	}
	if len(tokens) < 2 {
		return Condition{}, fmt.Errorf("condition expression must contain field and operator")
	}
	field, op := tokens[0], tokens[1]
	if !isFieldPath(field) {
		return Condition{}, fmt.Errorf("invalid condition field %q", field)
	}
	cond := Condition{Field: field, Op: op}
	switch op {
	case "exists", "missing":
		if len(tokens) != 2 {
			return Condition{}, fmt.Errorf("operator %q does not accept a value", op)
		}
	default:
		if len(tokens) != 3 {
			return Condition{}, fmt.Errorf("operator %q requires exactly one value or reference", op)
		}
		raw := strings.TrimSpace(tokens[2])
		if strings.HasPrefix(raw, "$") {
			ref := strings.TrimPrefix(raw, "$")
			if !isFieldPath(ref) {
				return Condition{}, fmt.Errorf("invalid condition reference %q", raw)
			}
			cond.Ref = ref
		} else {
			v, err := parseExpressionValue(raw)
			if err != nil {
				return Condition{}, err
			}
			cond.Value = v
		}
	}
	if err := validateShape(cond); err != nil {
		return Condition{}, err
	}
	if negated {
		return Condition{Not: &cond}, nil
	}
	return cond, nil
}

// splitExpressionTokens tokenizes a condition expression string,
// respecting quoted strings and bracket-delimited inline lists.
func splitExpressionTokens(expr string) ([]string, error) {
	var tokens []string
	var b strings.Builder
	inQuote := false
	escaped := false
	bracketDepth := 0
	flush := func() {
		if b.Len() > 0 {
			tokens = append(tokens, b.String())
			b.Reset()
		}
	}
	for _, r := range expr {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			b.WriteRune(r)
			escaped = true
		case r == '"':
			b.WriteRune(r)
			inQuote = !inQuote
		case !inQuote && r == '[':
			bracketDepth++
			b.WriteRune(r)
		case !inQuote && r == ']':
			if bracketDepth == 0 {
				return nil, fmt.Errorf("unexpected ] in condition expression")
			}
			bracketDepth--
			b.WriteRune(r)
		case !inQuote && bracketDepth == 0 && (r == ' ' || r == '\t'):
			flush()
		default:
			b.WriteRune(r)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quoted string in condition expression")
	}
	if bracketDepth != 0 {
		return nil, fmt.Errorf("unterminated list in condition expression")
	}
	flush()
	return tokens, nil
}

// parseExpressionValue parses a literal value (scalar or inline list) from
// a condition expression token.
func parseExpressionValue(raw string) (any, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "[") || strings.HasSuffix(raw, "]") {
		return parseInlineList(raw)
	}
	v, err := value.ParseScalar(raw, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid condition value %q: %w", raw, err)
	}
	return value.GoValue(v), nil
}

// parseInlineList parses "[a, b, c]" syntax into a Go []any.
// Supports nested quotes and brackets within reason.
func parseInlineList(raw string) ([]any, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
		return nil, fmt.Errorf("invalid inline list %q", raw)
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]"))
	if inner == "" {
		return []any{}, nil
	}
	parts, err := splitCommaSeparated(inner)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(parts))
	for _, part := range parts {
		v, err := parseExpressionValue(part)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// splitCommaSeparated splits a string by commas, respecting quotes and brackets.
func splitCommaSeparated(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	inQuote := false
	escaped := false
	bracketDepth := 0
	for _, r := range s {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			b.WriteRune(r)
			escaped = true
		case r == '"':
			b.WriteRune(r)
			inQuote = !inQuote
		case !inQuote && r == '[':
			bracketDepth++
			b.WriteRune(r)
		case !inQuote && r == ']':
			if bracketDepth == 0 {
				return nil, fmt.Errorf("unexpected ] in inline list")
			}
			bracketDepth--
			b.WriteRune(r)
		case !inQuote && bracketDepth == 0 && r == ',':
			part := strings.TrimSpace(b.String())
			if part == "" {
				return nil, fmt.Errorf("empty item in inline list")
			}
			out = append(out, part)
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quoted string in inline list")
	}
	if bracketDepth != 0 {
		return nil, fmt.Errorf("unterminated nested inline list")
	}
	part := strings.TrimSpace(b.String())
	if part == "" {
		return nil, fmt.Errorf("empty item in inline list")
	}
	out = append(out, part)
	return out, nil
}

// isFieldPath validates that a string looks like a valid dot-separated
// field path (e.g. "resource.owner_id").
func isFieldPath(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
				return false
			}
			continue
		}
		if !(r == '_' || r == '.' || r == '-' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// applyAssign applies a parsed key=value assignment to a Condition.
// This is the structured (non-shorthand) way to build conditions.
func applyAssign(c *Condition, n *ast.Node) error {
	switch n.Key {
	case "field":
		c.Field = n.Value.StringValue()
	case "op":
		c.Op = n.Value.StringValue()
	case "ref":
		c.Ref = n.Value.StringValue()
	case "value":
		c.Value = value.GoValue(n.Value)
	default:
		return fmt.Errorf("unknown condition key %q at line %d", n.Key, n.Line)
	}
	return nil
}

// validateShape checks that a condition node has a valid shape:
// it must not mix logical groups with leaf fields, and leaf fields
// must have consistent operator/value/ref combinations.
func validateShape(c Condition) error {
	groupCount := 0
	if len(c.All) > 0 {
		groupCount++
	}
	if len(c.Any) > 0 {
		groupCount++
	}
	if c.Not != nil {
		groupCount++
	}
	hasGroup := groupCount > 0
	hasLeaf := c.Field != "" || c.Op != "" || c.Ref != "" || c.Value != nil
	if groupCount > 1 {
		return fmt.Errorf("condition node cannot mix all/any/not groups")
	}
	if hasGroup && hasLeaf {
		return fmt.Errorf("condition node cannot mix logical groups with field/op/value")
	}
	if hasGroup {
		return nil
	}
	if c.Field == "" {
		if c.Op != "" || c.Ref != "" || c.Value != nil {
			return fmt.Errorf("condition with op/ref/value must include field")
		}
		return fmt.Errorf("empty condition")
	}
	if c.Op == "" {
		return fmt.Errorf("condition for field %q is missing op", c.Field)
	}
	if c.Ref != "" && c.Value != nil {
		return fmt.Errorf("condition for field %q cannot use both value and ref", c.Field)
	}
	switch c.Op {
	case "exists", "missing":
		if c.Ref != "" || c.Value != nil {
			return fmt.Errorf("operator %q cannot use value or ref", c.Op)
		}
	default:
		if c.Ref == "" && c.Value == nil {
			return fmt.Errorf("condition for field %q using op %q requires value or ref", c.Field, c.Op)
		}
	}
	return nil
}

// sectionValue extracts a complex value from a value section node.
// Supports list-of-scalars, list-of-maps, and map-of-scalars.
func sectionValue(n *ast.Node) (any, error) {
	if len(n.Children) == 0 {
		return nil, fmt.Errorf("value section at line %d must not be empty", n.Line)
	}
	allList := true
	allAssign := true
	for _, child := range n.Children {
		allList = allList && child.Kind == ast.NodeListItem
		allAssign = allAssign && child.Kind == ast.NodeAssign
	}
	if allList {
		arr := make([]any, 0, len(n.Children))
		for _, item := range n.Children {
			if item.Value.Kind != "" && len(item.Children) == 0 {
				arr = append(arr, value.GoValue(item.Value))
				continue
			}
			m := map[string]any{}
			seen := map[string]bool{}
			for _, child := range item.Children {
				if child.Kind != ast.NodeAssign {
					return nil, fmt.Errorf("value list item at line %d must contain assignments only", item.Line)
				}
				if seen[child.Key] {
					return nil, fmt.Errorf("value list item at line %d has duplicate key %q", item.Line, child.Key)
				}
				seen[child.Key] = true
				m[child.Key] = value.GoValue(child.Value)
			}
			arr = append(arr, m)
		}
		return arr, nil
	}
	if allAssign {
		m := map[string]any{}
		seen := map[string]bool{}
		for _, child := range n.Children {
			if seen[child.Key] {
				return nil, fmt.Errorf("value section at line %d has duplicate key %q", n.Line, child.Key)
			}
			seen[child.Key] = true
			m[child.Key] = value.GoValue(child.Value)
		}
		return m, nil
	}
	return nil, fmt.Errorf("value section at line %d must contain either all list items or all assignments", n.Line)
}

// ValidateOperators recursively checks that every operator in a condition
// tree is either built-in or registered in the extension registry.
func ValidateOperators(cond Condition, reg *extension.Registry) error {
	if cond.Field != "" && !IsBuiltinOperator(cond.Op) {
		if reg == nil {
			return fmt.Errorf("unknown operator %q", cond.Op)
		}
		if _, ok := reg.Operator(cond.Op); !ok {
			return fmt.Errorf("unknown operator %q", cond.Op)
		}
	}
	for _, c := range cond.All {
		if err := ValidateOperators(c, reg); err != nil {
			return err
		}
	}
	for _, c := range cond.Any {
		if err := ValidateOperators(c, reg); err != nil {
			return err
		}
	}
	if cond.Not != nil {
		return ValidateOperators(*cond.Not, reg)
	}
	return nil
}

// IsBuiltinOperator returns true if the operator is one of ELU's built-in set.
func IsBuiltinOperator(op string) bool {
	switch op {
	case "eq", "neq", "in", "not_in", "contains", "exists", "missing", "matches", "lt", "lte", "gt", "gte", "starts_with", "ends_with":
		return true
	default:
		return false
	}
}

// Validate checks condition shape and operator availability.
// Safe to call for conditions constructed manually in Go, not just from .elu files.
func Validate(cond Condition, reg *extension.Registry) error {
	if err := validateTree(cond); err != nil {
		return err
	}
	return ValidateOperators(cond, reg)
}

// validateTree recursively validates the shape of every node in the tree.
func validateTree(cond Condition) error {
	if err := validateShape(cond); err != nil {
		return err
	}
	for _, c := range cond.All {
		if err := validateTree(c); err != nil {
			return err
		}
	}
	for _, c := range cond.Any {
		if err := validateTree(c); err != nil {
			return err
		}
	}
	if cond.Not != nil {
		return validateTree(*cond.Not)
	}
	return nil
}

// EvalOptions controls how runtime data problems are handled.
// The zero value preserves ELU's historical permissive condition semantics.
type EvalOptions struct {
	MissingFieldIsError bool
	TypeMismatchIsError bool
}

// strictEvalOptions are suitable for authorization and safety decisions.
var strictEvalOptions = EvalOptions{
	MissingFieldIsError: true,
	TypeMismatchIsError: true,
}

// Evaluate validates and then evaluates a condition tree against a context.
// It preserves the historical behavior where missing fields and incompatible
// operand types simply make a condition false. Security-sensitive callers
// should use EvaluateStrict.
func Evaluate(cond Condition, ctx EvalContext, reg *extension.Registry) (bool, error) {
	return EvaluateWithOptions(cond, ctx, reg, EvalOptions{})
}

// EvaluateStrict validates and evaluates using fail-closed runtime semantics.
// Missing fields, missing references, and incompatible operand types are errors.
func EvaluateStrict(cond Condition, ctx EvalContext, reg *extension.Registry) (bool, error) {
	return EvaluateWithOptions(cond, ctx, reg, strictEvalOptions)
}

// EvaluateWithOptions validates and evaluates a condition using opts.
func EvaluateWithOptions(cond Condition, ctx EvalContext, reg *extension.Registry, opts EvalOptions) (bool, error) {
	if err := Validate(cond, reg); err != nil {
		return false, err
	}
	return evalValidated(cond, ctx, reg, opts)
}

// evalValidated evaluates a condition tree that has already passed validation.
// Skips re-validation for performance — call Validate first if unsure.
func evalValidated(cond Condition, ctx EvalContext, reg *extension.Registry, opts EvalOptions) (bool, error) {
	if len(cond.All) > 0 {
		for _, c := range cond.All {
			ok, err := evalValidated(c, ctx, reg, opts)
			if err != nil || !ok {
				return ok, err
			}
		}
		return true, nil
	}
	if len(cond.Any) > 0 {
		for _, c := range cond.Any {
			ok, err := evalValidated(c, ctx, reg, opts)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	if cond.Not != nil {
		ok, err := evalValidated(*cond.Not, ctx, reg, opts)
		if err != nil {
			return false, err
		}
		return !ok, nil
	}
	left, exists := lookup(ctx, cond.Field)
	switch cond.Op {
	case "exists":
		return exists, nil
	case "missing":
		return !exists, nil
	}
	if !exists {
		if opts.MissingFieldIsError {
			return false, fmt.Errorf("condition field %q is missing", cond.Field)
		}
		return false, nil
	}
	var right any = cond.Value
	if cond.Ref != "" {
		rv, ok := lookup(ctx, cond.Ref)
		if !ok {
			if opts.MissingFieldIsError {
				return false, fmt.Errorf("condition reference %q is missing", cond.Ref)
			}
			return false, nil
		}
		right = rv
	}
	return evalOp(cond.Op, left, right, reg, opts)
}

// evalOp dispatches to the right comparison function based on operator name.
func evalOp(op string, left, right any, reg *extension.Registry, opts EvalOptions) (bool, error) {
	switch op {
	case "eq", "neq":
		if opts.TypeMismatchIsError && !equalityCompatible(left, right) {
			return false, typeMismatch(op, left, right)
		}
		equal := compareEqual(left, right)
		if op == "neq" {
			equal = !equal
		}
		return equal, nil
	case "contains", "in", "not_in":
		container, item := left, right
		if op == "in" || op == "not_in" {
			container, item = right, left
		}
		matched, compatible := containsChecked(container, item)
		if opts.TypeMismatchIsError && !compatible {
			return false, typeMismatch(op, left, right)
		}
		if op == "not_in" {
			matched = !matched
		}
		return matched, nil
	case "matches", "starts_with", "ends_with":
		ls, ok1 := left.(string)
		rs, ok2 := right.(string)
		if !ok1 || !ok2 {
			if opts.TypeMismatchIsError {
				return false, typeMismatch(op, left, right)
			}
			return false, nil
		}
		switch op {
		case "matches":
			return glob.Match(rs, ls), nil
		case "starts_with":
			return strings.HasPrefix(ls, rs), nil
		default:
			return strings.HasSuffix(ls, rs), nil
		}
	case "lt", "lte", "gt", "gte":
		lf, lok := number(left)
		rf, rok := number(right)
		if !lok || !rok {
			if opts.TypeMismatchIsError {
				return false, typeMismatch(op, left, right)
			}
			return false, nil
		}
		switch op {
		case "lt":
			return lf < rf, nil
		case "lte":
			return lf <= rf, nil
		case "gt":
			return lf > rf, nil
		case "gte":
			return lf >= rf, nil
		}
	default:
		if reg != nil {
			if fn, ok := reg.Operator(op); ok {
				if fn == nil {
					return false, fmt.Errorf("operator %q is registered with nil implementation", op)
				}
				return callCustomOperator(op, fn, left, right)
			}
		}
		return false, fmt.Errorf("unknown operator %q", op)
	}
	return false, fmt.Errorf("unhandled operator %q", op)
}

// callCustomOperator wraps a custom operator call in a panic recovery.
// If the operator panics, we return false instead of crashing.
func callCustomOperator(op string, fn extension.OperatorFunc, left, right any) (ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
			err = fmt.Errorf("operator %q panicked: %v", op, r)
		}
	}()
	return fn(left, right), nil
}

// lookup walks a dot-separated path through an EvalContext map.
// "resource.owner_id" first checks ctx["resource.owner_id"], then
// ctx["resource"]["owner_id"].
func lookup(ctx map[string]any, path string) (any, bool) {
	if v, ok := ctx[path]; ok {
		return v, true
	}
	parts := strings.Split(path, ".")
	var cur any = ctx
	for _, p := range parts {
		v, ok := lookupMapKey(cur, p)
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// lookupMapKey tries to extract a key from a map, using reflection if needed.
func lookupMapKey(container any, key string) (any, bool) {
	switch m := container.(type) {
	case map[string]any:
		v, ok := m[key]
		return v, ok
	}
	rv := reflect.ValueOf(container)
	if !rv.IsValid() || rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return nil, false
	}
	v := rv.MapIndex(reflect.ValueOf(key))
	if !v.IsValid() {
		return nil, false
	}
	return v.Interface(), true
}

// compareEqual checks deep equality between two values.
// Numbers are compared as float64 with an epsilon tolerance,
// everything else uses reflect.DeepEqual.
func compareEqual(a, b any) bool {
	if af, ok := number(a); ok {
		if bf, ok := number(b); ok {
			return floatEqual(af, bf)
		}
	}
	return reflect.DeepEqual(a, b)
}

const epsilon = 1e-9

// floatEqual compares two floats with an epsilon tolerance.
func floatEqual(a, b float64) bool {
	if a == b {
		return true
	}
	return math.Abs(a-b) < epsilon
}

// equalityCompatible reports whether eq/neq operands have compatible runtime types.
// Numeric Go types are intentionally cross-compatible.
func equalityCompatible(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	_, an := number(a)
	_, bn := number(b)
	if an || bn {
		return an && bn
	}
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}

func typeMismatch(op string, left, right any) error {
	return fmt.Errorf("operator %q received incompatible operands %T and %T", op, left, right)
}

// containsChecked checks membership and reports whether the operand types are
// meaningful for the operation.
func containsChecked(container, item any) (bool, bool) {
	switch c := container.(type) {
	case string:
		s, ok := item.(string)
		return ok && strings.Contains(c, s), ok
	case []string:
		s, ok := item.(string)
		if !ok {
			return false, false
		}
		for _, x := range c {
			if x == s {
				return true, true
			}
		}
		return false, true
	case []any:
		for _, x := range c {
			if compareEqual(x, item) {
				return true, true
			}
		}
		return false, true
	case map[string]any:
		s, ok := item.(string)
		if !ok {
			return false, false
		}
		_, exists := c[s]
		return exists, true
	default:
		rv := reflect.ValueOf(container)
		if !rv.IsValid() {
			return false, false
		}
		if rv.Kind() == reflect.Map && rv.Type().Key().Kind() == reflect.String {
			s, ok := item.(string)
			if !ok {
				return false, false
			}
			return rv.MapIndex(reflect.ValueOf(s)).IsValid(), true
		}
		if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
			for i := 0; i < rv.Len(); i++ {
				if compareEqual(rv.Index(i).Interface(), item) {
					return true, true
				}
			}
			return false, true
		}
		return false, false
	}
}

// number tries to convert a value to float64 for numeric comparison.
// Supports int, int64, int32, float64, float32.
func number(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case int32:
		return float64(x), true
	case float64:
		return x, true
	case float32:
		return float64(x), true
	default:
		return 0, false
	}
}
