// Package util provides shared helpers used across ELU packages.
package util

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/internal/glob"
	"github.com/therxwold/elu/value"
)

// ActionTokenRE validates action tokens: alphanumeric with some punctuation.
var ActionTokenRE *regexp.Regexp

// init initializes the regexes used by the parser.
func init() {
	var err error
	ActionTokenRE, err = regexp.Compile(`^[a-zA-Z0-9_\-.:]+$`)
	if err != nil {
		panic("elu.internal.util: failed to compile action token regex: " + err.Error())
	}
}

// IsValidActionToken reports whether s is a valid action token or wildcard.
func IsValidActionToken(s string) bool {
	return s == "*" || ActionTokenRE.MatchString(s)
}

// HasRole checks if a role is in a list of roles.
func HasRole(roles []string, role string) bool {
	return slices.Contains(roles, role)
}

// MatchAction checks if a pattern matches an action.
// * matches everything, otherwise exact match.
func MatchAction(pattern, val string) bool {
	return pattern == "*" || pattern == val
}

// MatchResource checks if a resource pattern matches a value.
// Supports * and glob patterns.
func MatchResource(pattern, val string) bool {
	if pattern == "*" || pattern == val {
		return true
	}
	return glob.Match(pattern, val)
}

// StringList extracts a list of strings from a section node.
// Each child must be a list item with a string value.
func StringList(sec *ast.Node) ([]string, error) {
	if len(sec.Children) == 0 {
		return nil, fmt.Errorf("section %q at line %d must not be empty", sec.Key, sec.Line)
	}
	var out []string
	seen := map[string]bool{}
	for _, item := range sec.Children {
		if item.Kind != ast.NodeListItem || item.Value.Kind != value.String || len(item.Children) != 0 {
			return nil, fmt.Errorf("section %q at line %d expects string list items", sec.Key, item.Line)
		}
		if item.Value.S == "" {
			return nil, fmt.Errorf("section %q has empty item at line %d", sec.Key, item.Line)
		}
		if seen[item.Value.S] {
			return nil, fmt.Errorf("section %q has duplicate item %q", sec.Key, item.Value.S)
		}
		seen[item.Value.S] = true
		out = append(out, item.Value.S)
	}
	return out, nil
}
