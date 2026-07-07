package parser_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/therxwold/elu/parser"
)

func TestGoldenASTBasic(t *testing.T) {
	f, err := parser.ParseFile("testdata/ast_basic.elu")
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := "testdata/ast_basic.golden.json"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("AST golden mismatch\nGOT:\n%s\nWANT:\n%s", got, want)
	}
}
