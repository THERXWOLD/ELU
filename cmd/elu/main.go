// ELU CLI — the command-line face of the policy DSL.
//
// Credits:
//
//	Technical Design: Naru K
//	Implementation:  AIRI
//	Special thanks to ChatGPT-chan for not letting us ship broken golden tests.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/therxwold/elu/access"
	"github.com/therxwold/elu/condition"
	"github.com/therxwold/elu/extension"
	"github.com/therxwold/elu/format"
	eluglob "github.com/therxwold/elu/internal/glob"
	"github.com/therxwold/elu/parser"
	"github.com/therxwold/elu/repo"
	"github.com/therxwold/elu/route"
	"github.com/therxwold/elu/validate"
	"github.com/therxwold/elu/value"
)

// main is the entry point for the ELU CLI.
func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		check(os.Args[2:])
	case "ast":
		ast(os.Args[2:])
	case "fmt":
		fmtCmd(os.Args[2:])
	case "explain":
		explain(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

// usage prints the usage message for the ELU CLI.
func usage() {
	fmt.Fprintln(os.Stderr, "usage: elu <check|fmt|ast|explain> [options] [files...]")
}

// check validates the specified files and reports any issues found.
func check(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	strict := fs.Bool("strict", false, "reject unknown pack types")
	production := fs.Bool("production", false, "production strict mode: strict validation and warnings as failures")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "elu check: no files")
		os.Exit(2)
	}
	paths, err := expandInputs(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	failed := false
	reg := extension.NewRegistry()
	for _, path := range paths {
		f, err := parser.ParseFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
			continue
		}
		diags := validate.File(f, reg, *strict || *production)
		for _, d := range diags {
			fmt.Fprintln(os.Stderr, d.String())
			if *production && d.Severity == "warning" {
				failed = true
			}
		}
		if diags.HasErrors() {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// matchGlob checks if a value matches a glob pattern. It returns true if the value matches the pattern, false otherwise.
func expandInputs(args []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, arg := range args {
		matches, err := expandPattern(arg)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			matches = []string{arg}
		}
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out, nil
}

// expandPattern expands a glob pattern into a list of matching files.
// If the pattern contains no glob characters, it returns nil to indicate that
// the caller should treat it as a literal file path.
func expandPattern(pattern string) ([]string, error) {
	if !hasGlob(pattern) {
		return nil, nil
	}
	if strings.Contains(pattern, "**") {
		return expandDoubleStar(pattern)
	}
	return filepath.Glob(pattern)
}

// hasGlob reports whether a string contains glob characters.
// This is a simple heuristic and does not guarantee that the string is a valid glob pattern.
func hasGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// expandDoubleStar expands a glob pattern containing "**" into a list of matching files.
// It walks the filesystem to find matches, because filepath.Glob does not support "**".
func expandDoubleStar(pattern string) ([]string, error) {
	cleaned := filepath.Clean(pattern)
	idx := strings.Index(cleaned, "**")
	if idx < 0 {
		return filepath.Glob(pattern)
	}
	root := cleaned[:idx]
	root = strings.TrimRight(root, string(os.PathSeparator))
	if root == "" {
		root = "."
	}
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// checking if is symlink
		if d.Type()&os.ModeSymlink != 0 {
			// skip symlinks to avoid infinite loops
			return nil
		}
		if eluglob.Match(cleaned, path) {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// ast prints the abstract syntax tree for the specified file.
func ast(args []string) {
	fs := flag.NewFlagSet("ast", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "elu ast: expected one file")
		os.Exit(2)
	}
	f, err := parser.ParseFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	err = enc.Encode(f)
	if err != nil {
		fatal(err)
	}
}

// fmtCmd formats the specified files.
func fmtCmd(args []string) {
	fs := flag.NewFlagSet("fmt", flag.ExitOnError)
	checkOnly := fs.Bool("check", false, "check whether files are formatted without writing")
	write := fs.Bool("w", true, "write formatted output back to files")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "elu fmt: no files")
		os.Exit(2)
	}
	paths, err := expandInputs(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	failed := false
	for _, path := range paths {
		in, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
			continue
		}
		out, err := format.Bytes(path, in)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
			continue
		}
		if *checkOnly {
			if string(in) != string(out) {
				fmt.Fprintf(os.Stderr, "%s: not formatted\n", path)
				failed = true
			}
			continue
		}
		if !*write {
			fmt.Print(string(out))
			continue
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// stringList is a list of strings for use with flag.Var. It allows repeated flags to accumulate values.
type stringList []string

// String returns the string representation of the stringList, which is a comma-separated list of values.
func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// splitExplainArgs separates the file argument from flags.
// The file may appear anywhere in args. Bool flags are known so
// their values aren't mistaken for positionals.
func splitExplainArgs(args []string) (file string, flags []string) {
	knownBool := map[string]bool{"mfa": true, "json": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			if file != "" {
				return "", nil
			}
			file = a
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if knownBool[name] {
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return file, flags
}

// explain explains the evaluation of a policy file.
// It supports access_policy, repo_policy, and route_policy types. It takes various flags to specify the request context for evaluation.
// The result is printed in JSON format by default, but can be printed in a human-readable format if the --json flag is not set.
func explain(args []string) {
	fileArg, flagArgs := splitExplainArgs(args)
	if fileArg == "" {
		fmt.Fprintln(os.Stderr, "elu explain: expected one .elu policy file")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	var roles stringList
	fs.Var(&roles, "role", "role to include; may be repeated")
	subject := fs.String("subject", "", "subject id")
	action := fs.String("action", "", "action for access/repo policies")
	resource := fs.String("resource", "", "resource/path for access/repo policies")
	method := fs.String("method", "", "HTTP method for route policies")
	path := fs.String("path", "", "HTTP path for route policies")
	mfa := fs.Bool("mfa", false, "set auth.mfa=true for route policies")
	var ctxList stringList
	fs.Var(&ctxList, "ctx", "context key=value; may be repeated")
	jsonOut := fs.Bool("json", false, "emit JSON")
	_ = fs.Parse(flagArgs)
	ctx, err := parseContext(ctxList)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	f, err := parser.ParseFile(fileArg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	reg := extension.NewRegistry()
	if diags := validate.File(f, reg, true); diags.HasErrors() {
		fmt.Fprintln(os.Stderr, diags.Error())
		os.Exit(1)
	}
	var result any
	switch f.Type {
	case "access_policy":
		if *action == "" || *resource == "" {
			fmt.Fprintln(os.Stderr, "access_policy explain requires --action and --resource")
			os.Exit(2)
		}
		p, err := access.Decode(f)
		if err != nil {
			fatal(err)
		}
		d := p.Evaluate(access.Request{SubjectID: *subject, Roles: roles, Action: *action, Resource: *resource, Context: ctx}, reg)
		result = d
	case "repo_policy":
		if *action == "" || *resource == "" {
			fmt.Fprintln(os.Stderr, "repo_policy explain requires --action and --resource")
			os.Exit(2)
		}
		p, err := repo.Decode(f)
		if err != nil {
			fatal(err)
		}
		d := p.Evaluate(repo.Request{Action: *action, Resource: *resource, Context: ctx}, reg)
		result = d
	case "route_policy":
		if *method == "" || *path == "" {
			fmt.Fprintln(os.Stderr, "route_policy explain requires --method and --path")
			os.Exit(2)
		}
		p, err := route.Decode(f)
		if err != nil {
			fatal(err)
		}
		d := p.Evaluate(route.Request{SubjectID: *subject, Method: *method, Path: *path, Roles: roles, MFA: *mfa, Context: ctx}, reg)
		result = d
	default:
		fmt.Fprintf(os.Stderr, "elu explain does not support pack type %q yet\n", f.Type)
		os.Exit(2)
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(result)
		if err != nil {
			fatal(err)
		}
		return
	}
	err = printExplain(result)
	if err != nil {
		fatal(err)
	}
}

// fatal prints an error message to stderr and exits the program with a non-zero status code.
func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// parseContext parses a list of context key=value strings into a condition.EvalContext map.
func parseContext(items []string) (condition.EvalContext, error) {
	ctx := condition.EvalContext{}
	for _, item := range items {
		k, raw, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("invalid --ctx %q, expected key=value", item)
		}
		v, err := value.ParseScalar(strings.TrimSpace(raw), 0, 0)
		if err != nil {
			return nil, fmt.Errorf("invalid --ctx %q: %w", item, err)
		}
		ctx[strings.TrimSpace(k)] = value.GoValue(v)
	}
	return ctx, nil
}

// printExplain prints the evaluation result in a human-readable format.
func printExplain(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal explain result: %w", err)
	}
	fmt.Println(string(b))
	return nil
}
