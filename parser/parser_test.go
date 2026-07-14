package parser_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/therxwold/elu/ast"
	"github.com/therxwold/elu/parser"
)

const accessPolicySrc = `pack "app.security.access" version 1
type = "access_policy"

access "website":
  default = "deny"

  role "guest":
    allow:
      read:
        - "page.public"
        - "blog.post.published"
`

func TestParseAccessPolicy(t *testing.T) {
	f, err := parser.ParseString("access.elu", accessPolicySrc)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if f.PackID != "app.security.access" {
		t.Fatalf("bad pack id: %s", f.PackID)
	}
	if f.Version != 1 {
		t.Fatalf("bad version: %d", f.Version)
	}
	if f.Type != "access_policy" {
		t.Fatalf("bad type: %s", f.Type)
	}
	if ast.FindBlock(f.Nodes, "access") == nil {
		t.Fatalf("missing access block")
	}
}

func TestInvalidIndentation(t *testing.T) {
	src := "pack \"x\" version 1\ntype = \"access_policy\"\n\naccess \"site\":\n   default = \"deny\"\n"
	_, err := parser.ParseString("bad.elu", src)
	if err == nil {
		t.Fatal("expected indentation error")
	}
}

func TestCommentInsideQuotedString(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  default = "deny # not a comment"
`
	f, err := parser.ParseString("quoted.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	block := ast.FindBlock(f.Nodes, "access")
	if block == nil {
		t.Fatal("missing access block")
	}
}

func TestScalarListItemCannotHaveChildren(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  roles:
    - "admin"
      invalid = "child"
`
	_, err := parser.ParseString("bad.elu", src)
	if err == nil {
		t.Fatal("expected scalar list item nested child error")
	}
}

func TestHeaderAndTypeMustBeTopLevel(t *testing.T) {
	tests := []string{
		"  pack \"x\" version 1\ntype = \"access_policy\"\n",
		"pack \"x\" version 1\n  type = \"access_policy\"\n",
	}
	for _, src := range tests {
		_, err := parser.ParseString("bad.elu", src)
		if err == nil {
			t.Fatalf("expected header/type indentation error for:\n%s", src)
		}
	}
}

func TestListItemInlineSectionParses(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "r":
    rule "not_banned":
      effect = "allow"
      action = "read"
      resource = "x"

      when:
        all:
          - not:
              field = "subject.roles"
              op = "contains"
              value = "banned"
`
	_, err := parser.ParseString("inline-section.elu", src)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAssignmentKeySyntaxIsValidated(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  bad key = "value"
`
	_, err := parser.ParseString("bad.elu", src)
	if err == nil {
		t.Fatal("expected invalid assignment key syntax to fail")
	}
}

func TestBareStringWithSpacesRequiresQuotes(t *testing.T) {
	src := `pack "x" version 1
type = "skill_pack"

skill "x":
  category = engineering work
  risk = "medium"
  steps:
    - "do thing"
`
	_, err := parser.ParseString("bad.elu", src)
	if err == nil {
		t.Fatal("expected bare string with spaces to fail")
	}
}

func TestConditionExpressionListItemParses(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"

access "site":
  role "r":
    rule "ok":
      effect = "allow"
      action = "read"
      resource = "x"

      when:
        - file.exists eq false
`
	f, err := parser.ParseString("condition-expr.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	accessBlock := ast.FindBlock(f.Nodes, "access")
	if accessBlock == nil {
		t.Fatal("missing access block")
	}
}

func buildHugeList(n int) string {
	var b strings.Builder
	b.WriteString(`pack "x" version 1
type = "access_policy"

access "site":
  roles:
`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "    - \"role_%d\"\n", i)
	}
	return b.String()
}

func TestHugeListRejected(t *testing.T) {
	src := buildHugeList(10_001)
	_, err := parser.ParseString("big.elu", src)
	if err == nil {
		t.Fatal("expected list size error")
	}
}

func TestDefaultLimitReasonable(t *testing.T) {
	src := buildHugeList(9_999)
	f, err := parser.ParseString("ok.elu", src)
	if err != nil {
		t.Fatalf("default limit should allow 9999 items: %v", err)
	}
	_ = f
}

func TestCustomLimitWorks(t *testing.T) {
	src := buildHugeList(15)
	opts := parser.Options{MaxListItems: 10}
	_, err := parser.ParseStringWithOptions("custom.elu", src, opts)
	if err == nil {
		t.Fatal("expected custom limit to reject 15 items")
	}
}

func TestCustomLimitAllowsUnderLimit(t *testing.T) {
	src := buildHugeList(10)
	opts := parser.Options{MaxListItems: 10}
	f, err := parser.ParseStringWithOptions("custom.elu", src, opts)
	if err != nil {
		t.Fatalf("custom limit should allow exactly 10 items: %v", err)
	}
	_ = f
}

func buildHugeDoc(nodes int) string {
	var b strings.Builder
	b.WriteString(`pack "x" version 1
type = "access_policy"

`)
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "key_%d = \"val\"\n", i)
	}
	return b.String()
}

func TestTotalNodesRejected(t *testing.T) {
	src := buildHugeDoc(500_001)
	_, err := parser.ParseString("big.elu", src)
	if err == nil {
		t.Fatal("expected total nodes error")
	}
}
