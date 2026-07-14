// Package value defines the universal runtime value type for ELU.
// Everything in ELU — config values, policy data, condition results —
// eventually becomes a Value. It's the One Type To Rule Them All,
// and yes, I'm dramatic about it.
package value

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Kind tells you what sort of value you're dealing with.
// Everything in ELU eventually boils down to one of these.
type Kind string

const (
	// Null — the absence of value. Philosophically deep, practically empty.
	Null Kind = "null"
	// String — text, words, sentences, the usual.
	String Kind = "string"
	// Bool — true or false, no maybe.
	Bool Kind = "bool"
	// Int — whole numbers, for when you need to count.
	Int Kind = "int"
	// Float — numbers with decimal points. Precision is a lie.
	Float Kind = "float"
	// Map — key-value pairs, the workhorse of structured data.
	Map Kind = "map"
	// List — ordered collection. Order matters, obviously.
	List Kind = "list"
)

// Value is the universal ELU runtime value. It carries a Kind tag so you
// always know what you're looking at, plus a handful of optional fields
// that only make sense for certain kinds. Line/Col track provenance so
// error messages can point fingers.
type Value struct {
	Kind Kind             `json:"kind"`
	S    string           `json:"s,omitempty"`
	B    bool             `json:"b,omitempty"`
	I    int64            `json:"i,omitempty"`
	F    float64          `json:"f,omitempty"`
	M    map[string]Value `json:"m,omitempty"`
	L    []Value          `json:"l,omitempty"`
	Line int              `json:"line,omitempty"`
	Col  int              `json:"col,omitempty"`
}

// bareIdentRE matches strings that can be used as bare identifiers in ELU.
// No spaces, no quotes, just good old alphanumeric with some punctuation.
var bareIdentRE *regexp.Regexp

// init initializes the regexes used by the parser.
func init() {
	var err error
	bareIdentRE, err = regexp.Compile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	if err != nil {
		panic("elu.value: failed to compile bare identifier regex: " + err.Error())
	}
}

// VString wraps a string into a Value. Boring but essential.
func VString(s string) Value { return Value{Kind: String, S: s} }

// VBool wraps a bool into a Value. True or false, nothing tricky.
func VBool(b bool) Value { return Value{Kind: Bool, B: b} }

// VInt wraps an int64 into a Value. For when you need to count things.
func VInt(i int64) Value { return Value{Kind: Int, I: i} }

// VFloat wraps a float64 into a Value. Precision? In an ELU file? Unlikely.
func VFloat(f float64) Value { return Value{Kind: Float, F: f} }

// VMap wraps a map into a Value. The workhorse of structured policy data.
func VMap(m map[string]Value) Value { return Value{Kind: Map, M: m} }

// VList wraps a slice into a Value. Order matters, obviously.
func VList(l []Value) Value { return Value{Kind: List, L: l} }

// IsZero returns true when the Value hasn't been initialized.
// An empty Kind string is the zero value — don't try to use it.
func (v Value) IsZero() bool { return v.Kind == "" }

// StringValue converts any Value to its string representation.
// Maps and lists get Go's default formatting, which is good enough
// for diagnostics but don't expect it to be parseable.
func (v Value) StringValue() string {
	switch v.Kind {
	case String:
		return v.S
	case Bool:
		if v.B {
			return "true"
		}
		return "false"
	case Int:
		return strconv.FormatInt(v.I, 10)
	case Float:
		return strconv.FormatFloat(v.F, 'f', -1, 64)
	case Map:
		return fmt.Sprintf("%v", v.M)
	case List:
		return fmt.Sprintf("%v", v.L)
	default:
		return ""
	}
}

// ParseScalar tries really hard to turn a raw ELU token into a Value.
// It handles quoted strings, booleans, integers, floats, and bare
// identifiers (which get treated as strings because policy authors
// are lazy and we love them for it).
func ParseScalar(raw string, line, col int) (Value, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Value{Kind: Null, Line: line, Col: col}, nil
	}
	if strings.HasPrefix(raw, "\"") {
		s, err := strconv.Unquote(raw)
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: String, S: s, Line: line, Col: col}, nil
	}
	if raw == "true" || raw == "false" {
		return Value{Kind: Bool, B: raw == "true", Line: line, Col: col}, nil
	}
	if i, err := strconv.ParseInt(raw, 10, 64); err == nil && !hasLeadingZero(raw) {
		return Value{Kind: Int, I: i, Line: line, Col: col}, nil
	} else if err != nil && errors.Is(err, strconv.ErrRange) {
		return Value{}, fmt.Errorf("integer %q overflows int64 at line %d", raw, line)
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil && strings.ContainsAny(raw, ".eE") {
		return Value{Kind: Float, F: f, Line: line, Col: col}, nil
	}
	if raw == "*" || bareIdentRE.MatchString(raw) {
		return Value{Kind: String, S: raw, Line: line, Col: col}, nil
	}
	return Value{}, fmt.Errorf("bare string %q must be quoted", raw)
}

// hasLeadingZero checks if a numeric string starts with '0' (and is longer than 1).
// Used to reject octal-like literals because nobody needs that confusion.
func hasLeadingZero(s string) bool {
	return len(s) > 1 && s[0] == '0'
}

// GoValue strips the Value wrapper and returns a plain Go any.
// Maps become map[string]any, lists become []any, scalars become
// their natural Go types. Useful when you need to pass ELU data
// to code that doesn't know about Value.
func GoValue(v Value) any {
	switch v.Kind {
	case String:
		return v.S
	case Bool:
		return v.B
	case Int:
		return v.I
	case Float:
		return v.F
	case List:
		arr := make([]any, 0, len(v.L))
		for _, item := range v.L {
			arr = append(arr, GoValue(item))
		}
		return arr
	case Map:
		m := map[string]any{}
		for k, item := range v.M {
			m[k] = GoValue(item)
		}
		return m
	default:
		return nil
	}
}
