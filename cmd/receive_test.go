package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/envfile"
)

func TestFormatEnvFileSortsAndQuotes(t *testing.T) {
	out := formatEnvFile(map[string]string{
		"ZED":   "last",
		"ALPHA": "first",
		"SPACE": "has space",
	})

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), out)
	}
	if lines[0] != "ALPHA=first" || lines[1] != `SPACE="has space"` || lines[2] != "ZED=last" {
		t.Fatalf("unexpected sorted/quoted output:\n%s", out)
	}
}

func TestImportVariablesMergesIntoExistingFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".env.local")
	if err := os.WriteFile(target, []byte("EXISTING=old\nKEEP=yes\n"), 0644); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	err := importVariables(map[string]string{
		"EXISTING": "new", // overrides
		"ADDED":    "brand-new",
	}, target)
	if err != nil {
		t.Fatalf("importVariables: %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}

	parsed, err := envfile.Parse(string(data))
	if err != nil {
		t.Fatalf("parse merged file: %v", err)
	}

	got := make(map[string]string, len(parsed))
	for _, v := range parsed {
		got[v.Key] = v.Value
	}

	want := map[string]string{"EXISTING": "new", "KEEP": "yes", "ADDED": "brand-new"}
	for k, wantVal := range want {
		if got[k] != wantVal {
			t.Fatalf("key %q = %q, want %q\nfile:\n%s", k, got[k], wantVal, data)
		}
	}
}

func TestImportVariablesCreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fresh.env")

	if err := importVariables(map[string]string{"ONLY": "value"}, target); err != nil {
		t.Fatalf("importVariables: %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read created file: %v", err)
	}
	if !strings.Contains(string(data), "ONLY=value") {
		t.Fatalf("expected new file to contain ONLY=value, got:\n%s", data)
	}
}
