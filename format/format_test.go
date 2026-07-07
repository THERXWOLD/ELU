package format_test

import (
	"strings"
	"testing"

	"github.com/therxwold/elu/format"
)

func TestFormatString(t *testing.T) {
	src := `pack "x" version 1
type = "access_policy"
access "site":
  default = "deny"
  role "admin":
    allow:
      read:
        - "*"
`
	out, err := format.String("bad.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	want := `pack "x" version 1
type = "access_policy"

access "site":
  default = "deny"
  role "admin":
    allow:
      read:
        - "*"
`
	if out != want {
		t.Fatalf("unexpected format:\n%s", out)
	}
}

func TestFormatRoundTripParses(t *testing.T) {
	src := `pack "x" version 1
type = "route_policy"

routes "site":
  public:
    - method = "GET"
      path = "/"
`
	out, err := format.String("route.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `- method = "GET"`) {
		t.Fatalf("formatted output missing inline assignment:\n%s", out)
	}
	if _, err := format.String("route.elu", out); err != nil {
		t.Fatalf("formatted output should parse: %v", err)
	}
}

func TestFormatPreservesConditionShorthand(t *testing.T) {
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
        - resource.owner_id eq $subject.id
`
	out, err := format.String("shorthand.elu", src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `- file.exists eq false`) || !strings.Contains(out, `- resource.owner_id eq $subject.id`) {
		t.Fatalf("formatted output lost shorthand conditions:\n%s", out)
	}
}
