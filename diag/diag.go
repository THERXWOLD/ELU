// Diagnostics — because things go wrong and you deserve to know where.
package diag

import (
	"fmt"
	"strings"
)

// Severity tells you how bad things are. Error means "this is broken",
// Warning means "you should probably look at this".
type Severity string

const (
	Error   Severity = "error"
	Warning Severity = "warning"
)

// Diagnostic is a single message pointing at something suspicious.
// File, Line, and Column help you find the problem without playing
// Where's Waldo in your policy files.
type Diagnostic struct {
	Severity Severity `json:"severity"`
	File     string   `json:"file,omitempty"`
	Line     int      `json:"line,omitempty"`
	Column   int      `json:"column,omitempty"`
	Message  string   `json:"message"`
}

// String renders a diagnostic the way you'd expect: file:line:col: severity: message.
func (d Diagnostic) String() string {
	loc := d.File
	if d.Line > 0 {
		loc = fmt.Sprintf("%s:%d:%d", loc, d.Line, d.Column)
	}
	if loc == "" {
		return fmt.Sprintf("%s: %s", d.Severity, d.Message)
	}
	return fmt.Sprintf("%s: %s: %s", loc, d.Severity, d.Message)
}

// Diagnostics is a list of Diagnostic that also implements error.
// Because one problem is never the whole story.
type Diagnostics []Diagnostic

// Error joins all diagnostics into one big error string.
// Empty list = empty string, so callers can check len first.
func (ds Diagnostics) Error() string {
	if len(ds) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, "\n")
}

// HasErrors returns true if any diagnostic in the list is Severity Error.
// Useful for quick bailouts without iterating manually.
func (ds Diagnostics) HasErrors() bool {
	for _, d := range ds {
		if d.Severity == Error {
			return true
		}
	}
	return false
}
