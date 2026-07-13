// Package parser turns .elu files into ASTs.
// If the file doesn't parse, you get diagnostics — not panics.
package parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/diag"
	"github.com/therxwold/elu/value"
)

const (
	maxInputSize = 10 * 1024 * 1024 // 10 MB
	maxNesting   = 100
)

var (
	packRE  *regexp.Regexp
	keyRE   *regexp.Regexp
	blockRE *regexp.Regexp
	sectRE  *regexp.Regexp
)

// parsedLine holds one non-empty, non-comment line from an .elu file.
// Indent is the number of leading spaces (must be multiples of 2).
type parsedLine struct {
	indent int
	text   string
	line   int
}

// init initializes the regexes used by the parser.
func init() {
	// Check regexes at init time to avoid panics later.
	// If it works it works
	var err error
	packRE, err = regexp.Compile(`^pack\s+"([^"]+)"\s+version\s+([0-9]+)\s*$`)
	if err != nil {
		panic("elu.parser: bad pack regex: " + err.Error())
	}
	keyRE, err = regexp.Compile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	if err != nil {
		panic("elu.parser: bad key regex: " + err.Error())
	}
	blockRE, err = regexp.Compile(`^([A-Za-z_][A-Za-z0-9_.-]*)\s+"([^"]+)"\s*:\s*$`)
	if err != nil {
		panic("elu.parser: bad block regex: " + err.Error())
	}
	sectRE, err = regexp.Compile(`^((?:[A-Za-z_][A-Za-z0-9_.-]*)|\*|"[^"]+")\s*:\s*$`)
	if err != nil {
		panic("elu.parser: bad section regex: " + err.Error())
	}
}

// ParseFile reads a file from disk and parses it into an AST.
func ParseFile(path string) (*ast.File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseString(path, string(b))
}

// ParseString parses an ELU document from a string.
// Returns diagnostics as error if there are parse errors.
func ParseString(path, src string) (*ast.File, error) {
	lines, diags := scanLines(path, src)
	if diags.HasErrors() {
		return nil, diags
	}
	if len(lines) == 0 {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Message: "empty .elu document"}}
	}

	if lines[0].indent != 0 {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Line: lines[0].line, Column: 1, Message: "pack header must start at column 1"}}
	}
	m := packRE.FindStringSubmatch(lines[0].text)
	if m == nil {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Line: lines[0].line, Column: 1, Message: `expected pack header: pack "id" version N`}}
	}
	// Parse the version number and create the AST file node.
	version, err := strconv.Atoi(m[2])
	if err != nil {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Line: lines[0].line, Column: 1, Message: fmt.Sprintf("invalid version number: %v", err)}}
	}

	// Reject version numbers less than 1, since we don't support them.
	if version < 1 {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Line: lines[0].line, Column: 1, Message: fmt.Sprintf("unsupported version number: %d", version)}}
	}

	f := &ast.File{Path: path, PackID: m[1], Version: version}

	if len(lines) < 2 {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Message: `missing type assignment: type = "pack_type"`}}
	}
	if lines[1].indent != 0 {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Line: lines[1].line, Column: 1, Message: "type assignment must start at column 1"}}
	}
	typNode, err := parseNode(lines[1])
	if err != nil {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Line: lines[1].line, Column: lines[1].indent + 1, Message: err.Error()}}
	}
	if typNode.Kind != ast.NodeAssign || typNode.Key != "type" || typNode.Value.Kind != value.String {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Line: lines[1].line, Column: lines[1].indent + 1, Message: `expected type assignment: type = "pack_type"`}}
	}
	f.Type = typNode.Value.S

	type frame struct {
		indent int
		node   *ast.Node
	}
	root := &ast.Node{Kind: ast.NodeSection, Key: "$root", Children: []*ast.Node{typNode}}
	stack := []frame{{indent: -2, node: root}}

	var out diag.Diagnostics
	for i := 2; i < len(lines); i++ {
		pl := lines[i]
		n, err := parseNode(pl)
		if err != nil {
			out = append(out, diag.Diagnostic{Severity: diag.Error, File: path, Line: pl.line, Column: pl.indent + 1, Message: err.Error()})
			continue
		}
		for len(stack) > 0 && pl.indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			out = append(out, diag.Diagnostic{Severity: diag.Error, File: path, Line: pl.line, Column: pl.indent + 1, Message: "invalid indentation"})
			continue
		}
		parent := stack[len(stack)-1]
		if pl.indent > parent.indent+2 {
			out = append(out, diag.Diagnostic{Severity: diag.Error, File: path, Line: pl.line, Column: pl.indent + 1, Message: "indentation jumped more than one level"})
			continue
		}
		if parent.node.Kind == ast.NodeListItem && (parent.node.Value.Kind != "" || parent.node.Expr != "") {
			out = append(out, diag.Diagnostic{Severity: diag.Error, File: path, Line: pl.line, Column: pl.indent + 1, Message: "scalar list item cannot have nested children"})
			continue
		}
		parent.node.Children = append(parent.node.Children, n)
		if n.Kind == ast.NodeListItem && n.Value.Kind == "" && len(n.Children) == 1 && n.Children[0].Kind == ast.NodeSection {
			if len(stack) >= maxNesting {
				out = append(out, diag.Diagnostic{Severity: diag.Error, File: path, Line: pl.line, Column: pl.indent + 1, Message: "nesting depth exceeds maximum"})
				continue
			}
			stack = append(stack, frame{indent: pl.indent, node: n})
			stack = append(stack, frame{indent: pl.indent + 2, node: n.Children[0]})
		} else if n.Kind == ast.NodeSection || n.Kind == ast.NodeBlock || n.Kind == ast.NodeListItem {
			if len(stack) >= maxNesting {
				out = append(out, diag.Diagnostic{Severity: diag.Error, File: path, Line: pl.line, Column: pl.indent + 1, Message: "nesting depth exceeds maximum"})
				continue
			}
			stack = append(stack, frame{indent: pl.indent, node: n})
		}
	}
	if out.HasErrors() {
		return nil, out
	}
	f.Nodes = root.Children[1:]
	return f, nil
}

// scanLines tokenizes an ELU source string into lines with indentation info.
// Rejects tabs and indentation that isn't a multiple of 2.
func scanLines(path, src string) ([]parsedLine, diag.Diagnostics) {
	if len(src) > maxInputSize {
		return nil, diag.Diagnostics{{Severity: diag.Error, File: path, Message: fmt.Sprintf("input size %d exceeds maximum of %d bytes", len(src), maxInputSize)}}
	}
	var lines []parsedLine
	var diags diag.Diagnostics
	sc := bufio.NewScanner(strings.NewReader(src))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := stripComment(sc.Text())
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indent := 0
		for indent < len(raw) {
			if raw[indent] == '\t' {
				diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: path, Line: lineNo, Column: indent + 1, Message: "tabs are not allowed for indentation"})
				break
			}
			if raw[indent] != ' ' {
				break
			}
			indent++
		}
		if indent%2 != 0 {
			diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: path, Line: lineNo, Column: 1, Message: "indentation must use multiples of 2 spaces"})
		}
		lines = append(lines, parsedLine{indent: indent, text: strings.TrimSpace(raw), line: lineNo})
	}
	if err := sc.Err(); err != nil {
		diags = append(diags, diag.Diagnostic{Severity: diag.Error, File: path, Message: err.Error()})
	}
	return lines, diags
}

// parseNode takes a single parsed line and turns it into an AST node.
// Handles list items (- ...), blocks (key "name":), sections (key:),
// and assignments (key = value).
func parseNode(pl parsedLine) (*ast.Node, error) {
	s := pl.text
	col := pl.indent + 1
	if strings.HasPrefix(s, "- ") {
		rest := strings.TrimSpace(strings.TrimPrefix(s, "- "))
		item := &ast.Node{Kind: ast.NodeListItem, Line: pl.line, Column: col}
		if rest == "" {
			return nil, fmt.Errorf("empty list item")
		}
		if key, raw, ok := splitAssignment(rest); ok {
			v, err := value.ParseScalar(raw, pl.line, col+strings.Index(s, raw))
			if err != nil {
				return nil, fmt.Errorf("invalid scalar: %w", err)
			}
			item.Children = append(item.Children, &ast.Node{Kind: ast.NodeAssign, Key: key, Value: v, Line: pl.line, Column: col + 2})
			return item, nil
		}
		if m := sectRE.FindStringSubmatch(rest); m != nil {
			key := strings.Trim(m[1], "\"")
			item.Children = append(item.Children, &ast.Node{Kind: ast.NodeSection, Key: key, Line: pl.line, Column: col + 2})
			return item, nil
		}
		if looksLikeConditionExpr(rest) {
			item.Expr = rest
			return item, nil
		}
		v, err := value.ParseScalar(rest, pl.line, col+2)
		if err != nil {
			return nil, fmt.Errorf("invalid scalar: %w", err)
		}
		item.Value = v
		return item, nil
	}
	if m := blockRE.FindStringSubmatch(s); m != nil {
		return &ast.Node{Kind: ast.NodeBlock, Key: m[1], Name: m[2], Line: pl.line, Column: col}, nil
	}
	if m := sectRE.FindStringSubmatch(s); m != nil {
		key := strings.Trim(m[1], "\"")
		return &ast.Node{Kind: ast.NodeSection, Key: key, Line: pl.line, Column: col}, nil
	}
	if key, raw, ok := splitAssignment(s); ok {
		v, err := value.ParseScalar(raw, pl.line, col+strings.Index(s, raw))
		if err != nil {
			return nil, fmt.Errorf("invalid scalar: %w", err)
		}
		return &ast.Node{Kind: ast.NodeAssign, Key: key, Value: v, Line: pl.line, Column: col}, nil
	}
	return nil, fmt.Errorf("could not parse line %q", s)
}

// looksLikeConditionExpr does a quick heuristic check to see if a string
// looks like a condition shorthand expression (e.g. "file.exists eq false").
// This lets the parser treat it as Expr rather than failing to parse it.
func looksLikeConditionExpr(s string) bool {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return false
	}
	if fields[0] == "not" {
		if len(fields) < 3 {
			return false
		}
		fields = fields[1:]
	}
	if !keyRE.MatchString(fields[0]) {
		return false
	}
	switch fields[1] {
	case "exists", "missing":
		return len(fields) == 2
	case "eq", "neq", "in", "not_in", "contains", "matches", "lt", "lte", "gt", "gte", "starts_with", "ends_with":
		return len(fields) >= 3
	default:
		return false
	}
}

// splitAssignment splits "key = value" into its parts, respecting quotes.
// Returns false if the line doesn't look like a valid assignment.
func splitAssignment(s string) (string, string, bool) {
	inQuote := false
	escaped := false
	for i, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case r == '=' && !inQuote:
			key := strings.TrimSpace(s[:i])
			val := strings.TrimSpace(s[i+1:])
			if key == "" || val == "" || !keyRE.MatchString(key) {
				return "", "", false
			}
			return key, val, true
		}
	}
	return "", "", false
}

// stripComment removes everything from the first unquoted # to end of line.
func stripComment(s string) string {
	inQuote := false
	escaped := false
	for i, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case r == '#' && !inQuote:
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return strings.TrimRight(s, " \t")
}
