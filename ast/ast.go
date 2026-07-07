// AST types — the middle ground between raw ELU text and something you can
// actually work with in Go.
package ast

import "github.com/therxwold/elu/value"

// NodeKind classifies what sort of AST node you're looking at.
type NodeKind string

const (
	NodeAssign   NodeKind = "assign"
	NodeSection  NodeKind = "section"
	NodeBlock    NodeKind = "block"
	NodeListItem NodeKind = "list_item"
)

// File is the root of a parsed ELU document. It holds the pack header
// (ID, version, type) and all the top-level nodes that follow.
type File struct {
	Path    string  `json:"path,omitempty"`
	PackID  string  `json:"pack_id"`
	Version int     `json:"version"`
	Type    string  `json:"type"`
	Nodes   []*Node `json:"nodes"`
}

// Node is a generic AST element. Every ELU construct — assignments,
// sections, blocks, list items — gets flattened into this structure.
// The Kind field tells you which variant you've got, and the rest of
// the fields shake out accordingly.
type Node struct {
	Kind NodeKind `json:"kind"`
	Key  string   `json:"key,omitempty"`
	Name string   `json:"name,omitempty"`
	// Expr stores a condition shorthand expression like
	// "file.exists eq false" when the node is a list item that
	// couldn't be parsed as a structured value.
	Expr     string      `json:"expr,omitempty"`
	Value    value.Value `json:"value,omitempty"`
	Children []*Node     `json:"children,omitempty"`
	Line     int         `json:"line,omitempty"`
	Column   int         `json:"column,omitempty"`
}

// FirstBlock walks a node's children and returns the first block with
// the given kind key. Returns nil if nothing matches.
func (n *Node) FirstBlock(kind string) *Node {
	for _, child := range n.Children {
		if child.Kind == NodeBlock && child.Key == kind {
			return child
		}
	}
	return nil
}

// FindBlock scans a node list for the first block with the matching kind.
func FindBlock(nodes []*Node, kind string) *Node {
	for _, n := range nodes {
		if n.Kind == NodeBlock && n.Key == kind {
			return n
		}
	}
	return nil
}

// FindAssign searches a node list for an assignment with the given key
// and returns its value. The bool tells you whether it was found.
func FindAssign(nodes []*Node, key string) (value.Value, bool) {
	for _, n := range nodes {
		if n.Kind == NodeAssign && n.Key == key {
			return n.Value, true
		}
	}
	return value.Value{}, false
}

// FindSection scans a node list for the first section with the given key.
func FindSection(nodes []*Node, key string) *Node {
	for _, n := range nodes {
		if n.Kind == NodeSection && n.Key == key {
			return n
		}
	}
	return nil
}
