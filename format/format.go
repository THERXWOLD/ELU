// Package format renders parsed ELU ASTs back into canonical text.
// Comments are not preserved in v1 (don't @ me).
package format

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/value"
)

// String parses and formats an ELU document from a string.
func String(path, src string) (string, error) {
	f, err := parser.ParseString(path, src)
	if err != nil {
		return "", err
	}
	return File(f), nil
}

// Bytes parses and formats an ELU document from a byte slice.
func Bytes(path string, src []byte) ([]byte, error) {
	out, err := String(path, string(src))
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// Path formats the file at path in place. Overwrites the original. It creates a temp file first, then renames it to the original file.
func Path(path string) error {
	// removing .tmp file in case of failure
	err := os.Remove(path + ".tmp")
	if err != nil {
		return err
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Format the file and write it back to disk.
	out, err := Bytes(path, b)
	if err != nil {
		return err
	}

	// writing to a temp file first, then renaming, to avoid data loss in case of errors
	tmpPath := path + ".tmp"
	err = os.WriteFile(tmpPath, out, 0o644)
	if err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// File renders a parsed ELU AST back to canonical formatted text.
// This is the canonical form — everything else is just noise.
func File(f *ast.File) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "pack %q version %d\n", f.PackID, f.Version)
	fmt.Fprintf(&b, "type = %q\n", f.Type)
	// Render all nodes in the file.
	for _, n := range f.Nodes {
		b.WriteByte('\n')
		writeNode(&b, n, 0)
	}
	// Add a newline if the file didn't end with one.
	// This is important for tools that expect a newline at the end of files.
	if !bytes.HasSuffix(b.Bytes(), []byte("\n")) {
		b.WriteByte('\n')
	}
	return b.String()
}

// writeNode serializes a single AST node to the buffer at the given indentation level.
func writeNode(b *bytes.Buffer, n *ast.Node, indent int) {
	pad := strings.Repeat(" ", indent)
	switch n.Kind {
	case ast.NodeBlock:
		// Blocks are rendered as key: name\n{ children }.
		fmt.Fprintf(b, "%s%s %q:\n", pad, n.Key, n.Name)
		for _, c := range n.Children {
			writeNode(b, c, indent+2)
		}
	case ast.NodeSection:
		// Sections are rendered as key:\n{ children }.
		fmt.Fprintf(b, "%s%s:\n", pad, sectionKey(n.Key))
		for _, c := range n.Children {
			writeNode(b, c, indent+2)
		}
	case ast.NodeAssign:
		// Assignments are rendered as key = value\n.
		fmt.Fprintf(b, "%s%s = %s\n", pad, n.Key, renderValue(n.Value))
	case ast.NodeListItem:
		// List items are rendered as either an expression, a value, or a section.
		writeListItem(b, n, indent)
	}
}

// writeListItem serializes a list item. Handles expressions, values,
// inline assignments, and inline sections.
func writeListItem(b *bytes.Buffer, n *ast.Node, indent int) {
	pad := strings.Repeat(" ", indent)
	if n.Expr != "" {
		fmt.Fprintf(b, "%s- %s\n", pad, n.Expr)
		return
	}
	if n.Value.Kind != "" {
		fmt.Fprintf(b, "%s- %s\n", pad, renderValue(n.Value))
		return
	}
	if len(n.Children) > 0 {
		c := n.Children[0]
		switch c.Kind {
		case ast.NodeAssign:
			fmt.Fprintf(b, "%s- %s = %s\n", pad, c.Key, renderValue(c.Value))
			for _, rest := range n.Children[1:] {
				writeNode(b, rest, indent+2)
			}
			return
		case ast.NodeSection:
			fmt.Fprintf(b, "%s- %s:\n", pad, sectionKey(c.Key))
			for _, gc := range c.Children {
				writeNode(b, gc, indent+2)
			}
			for _, rest := range n.Children[1:] {
				writeNode(b, rest, indent+2)
			}
			return
		}
	}
	fmt.Fprintf(b, "%s-\n", pad)
	for _, c := range n.Children {
		writeNode(b, c, indent+2)
	}
}

// sectionKey formats a section key, quoting it if it contains special chars.
func sectionKey(key string) string {
	if key == "*" || isBareKey(key) {
		return key
	}
	return fmt.Sprintf("%q", key)
}

// isBareKey checks if a string is a valid bare (unquoted) ELU identifier.
func isBareKey(s string) bool {
	if s == "" {
		return false
	}
	// Check first rune separately, since it can't be a digit or dot.
	for i, r := range s {
		if i == 0 {
			// Check if the rune is a valid first rune.
			if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
				return false
			}
			continue
		}
		// Check if the rune is a valid identifier rune.
		if !(r == '_' || r == '.' || r == '-' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// renderValue formats a value.Value for output. Strings get quoted,
// booleans and numbers get their natural representation.
func renderValue(v value.Value) string {
	switch v.Kind {
	case value.String:
		return fmt.Sprintf("%q", v.S)
	case value.Bool:
		if v.B {
			return "true"
		}
		return "false"
	case value.Int:
		return fmt.Sprintf("%d", v.I)
	case value.Float:
		return fmt.Sprintf("%g", v.F)
	default:
		return fmt.Sprintf("%q", v.StringValue())
	}
}
