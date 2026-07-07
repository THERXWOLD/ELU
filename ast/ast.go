// AST types — the middle ground between raw ELU text and something you can
// actually work with in Go.
package ast

import "github.com/therxwold/elu/value"

// NodeKind classifies what sort of AST node you're looking at.
type NodeKind string

const (
	// NodeAssign — key = value, the bread and butter of ELU.
	NodeAssign NodeKind = "assign"
	// NodeSection — [square brackets] mean we're changing the subject.
	NodeSection NodeKind = "section"
	// NodeBlock — a named block, because nesting is how we cope.
	NodeBlock NodeKind = "block"
	// NodeListItem — dash-prefixed list item, for when order matters.
	NodeListItem NodeKind = "list_item"
)

// File is the root of a parsed ELU document. Holds the pack header
// (ID, version, type) and every top-level node that survived parsing.
type File struct {
	Path    string  `json:"path,omitempty"`
	PackID  string  `json:"pack_id"`
	Version int     `json:"version"`
	Type    string  `json:"type"`
	Nodes   []*Node `json:"nodes"`
}

// Node is a generic AST element. Assignments, sections, blocks, list items —
// they all get flattened into this one struct. Kind tells you the variant,
// the rest of the fields make sense (or are empty) depending on that.
type Node struct {
	Kind NodeKind `json:"kind"`
	Key  string   `json:"key,omitempty"`
	Name string   `json:"name,omitempty"`
	// Expr holds a condition shorthand like "file.exists eq false" when
	// a list item couldn't be parsed as a structured value. We tried.
	Expr     string      `json:"expr,omitempty"`
	Value    value.Value `json:"value,omitempty"`
	Children []*Node     `json:"children,omitempty"`
	Line     int         `json:"line,omitempty"`
	Column   int         `json:"column,omitempty"`
}

// FirstBlock digs through a node's children and returns the first block
// matching the given kind key. Nil if your hopes are dashed.
func (n *Node) FirstBlock(kind string) *Node {
	for _, child := range n.Children {
		if child.Kind == NodeBlock && child.Key == kind {
			return child
		}
	}
	return nil
}

// FindBlock hunts through a node list for the first block with a matching kind.
// Returns nil because sometimes the block just isn't there.
func FindBlock(nodes []*Node, kind string) *Node {
	for _, n := range nodes {
		if n.Kind == NodeBlock && n.Key == kind {
			return n
		}
	}
	return nil
}

// FindAssign searches a node list for an assignment with the given key
// and returns its value. The bool is false if you're looking for something
// that doesn't exist — like a bug-free codebase.
func FindAssign(nodes []*Node, key string) (value.Value, bool) {
	for _, n := range nodes {
		if n.Kind == NodeAssign && n.Key == key {
			return n.Value, true
		}
	}
	return value.Value{}, false
}

// FindSection scans a node list for the first section with the given key.
// Sections are how ELU organizes things, and this is how you find them.
func FindSection(nodes []*Node, key string) *Node {
	for _, n := range nodes {
		if n.Kind == NodeSection && n.Key == key {
			return n
		}
	}
	return nil
}
