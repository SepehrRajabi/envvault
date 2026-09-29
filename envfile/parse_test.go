package envfile

import (
	"reflect"
	"testing"
)

func TestParseStripsSurroundingQuotes(t *testing.T) {
	content := []byte(`DOUBLE="hello world"
SINGLE='single quoted'
PLAIN=plain
EMPTY=""
`)

	vars, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := map[string]string{
		"DOUBLE": "hello world",
		"SINGLE": "single quoted",
		"PLAIN":  "plain",
		"EMPTY":  "",
	}
	got := make(map[string]string, len(vars))
	for _, v := range vars {
		got[v.Key] = v.Value
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseSkipsBlankLinesAndComments(t *testing.T) {
	content := []byte("\n# a comment\nKEY=value\n   \n#another\n")
	vars, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(vars) != 1 || vars[0].Key != "KEY" || vars[0].Value != "value" {
		t.Fatalf("unexpected vars: %+v", vars)
	}
}

func TestParseInvalidLineReturnsErrorWithLineNumber(t *testing.T) {
	content := []byte("KEY=value\nNOT_VALID_LINE\n")
	_, err := Parse(content)
	if err == nil {
		t.Fatal("expected error for line without '='")
	}
	perr, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("expected *ParseError, got %T", err)
	}
	if perr.Line != 2 {
		t.Fatalf("expected error on line 2, got %d", perr.Line)
	}
	if perr.Error() != "Parse error on line 2: Invalid format" {
		t.Fatalf("unexpected error message: %q", perr.Error())
	}
}

func TestStripExportPrefix(t *testing.T) {
	tests := []struct{ in, want string }{
		{"export FOO", "FOO"},
		{"export\tFOO", "FOO"},
		{"FOO", "FOO"},
		{"exported_at", "exported_at"},
		{"export", "export"},
	}
	for _, tt := range tests {
		if got := StripExportPrefix(tt.in); got != tt.want {
			t.Errorf("StripExportPrefix(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestUnquote(t *testing.T) {
	tests := []struct{ in, want string }{
		{`"hello"`, "hello"},
		{`'hello'`, "hello"},
		{"hello", "hello"},
		{`"`, `"`},
		{`""`, ""},
		{`"mismatched'`, `"mismatched'`},
	}
	for _, tt := range tests {
		if got := unquote(tt.in); got != tt.want {
			t.Errorf("unquote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDiff(t *testing.T) {
	a := []EnvVar{
		{Key: "A", Value: "1"},
		{Key: "B", Value: "2"},
		{Key: "C", Value: "3"},
	}
	b := []EnvVar{
		{Key: "A", Value: "1"},
		{Key: "B", Value: "20"},
		{Key: "D", Value: "4"},
	}

	added, removed, changed := Diff(a, b)

	if len(added) != 1 || added[0].Key != "D" {
		t.Fatalf("unexpected added: %+v", added)
	}
	if len(removed) != 1 || removed[0].Key != "C" {
		t.Fatalf("unexpected removed: %+v", removed)
	}
	if len(changed) != 1 || changed[0].Old.Key != "B" || changed[0].Old.Value != "2" || changed[0].New.Value != "20" {
		t.Fatalf("unexpected changed: %+v", changed)
	}
}
