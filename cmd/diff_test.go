package cmd

import (
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/envfile"
)

func TestBuildDiffResultRedactsValuesByDefault(t *testing.T) {
	added := []envfile.EnvVar{{Key: "API_KEY", Value: "secret"}}
	removed := []envfile.EnvVar{{Key: "OLD_KEY", Value: "old-secret"}}
	changed := []struct{ Old, New envfile.EnvVar }{
		{Old: envfile.EnvVar{Key: "DATABASE_URL", Value: "old"}, New: envfile.EnvVar{Key: "DATABASE_URL", Value: "new"}},
	}

	result := buildDiffResult("a.env", "b.env", added, removed, changed, false)
	if result.Added[0].Value != "" || result.Removed[0].Value != "" || result.Changed[0].OldValue != "" || result.Changed[0].NewValue != "" {
		t.Fatalf("expected values to be omitted by default: %+v", result)
	}
}

func TestBuildDiffResultIncludesValuesWhenRequested(t *testing.T) {
	added := []envfile.EnvVar{{Key: "API_KEY", Value: "secret"}}
	result := buildDiffResult("a.env", "b.env", added, nil, nil, true)
	if result.Added[0].Value != "secret" {
		t.Fatalf("expected value to be included, got %+v", result.Added[0])
	}
}

func TestFormatDiffResultKeysOnly(t *testing.T) {
	result := diffResult{
		Added:   []diffEntry{{Key: "API_KEY", Value: "secret"}},
		Removed: []diffEntry{{Key: "OLD_KEY", Value: "old-secret"}},
		Changed: []diffChange{{Key: "DATABASE_URL", OldValue: "old", NewValue: "new"}},
	}

	output := formatDiffResult(result, diffFormatOptions{KeysOnly: true})
	if strings.Contains(output, "secret") || strings.Contains(output, "old") || strings.Contains(output, "new") || strings.Contains(output, "=") {
		t.Fatalf("expected keys-only output without values, got:\n%s", output)
	}
	for _, key := range []string{"API_KEY", "OLD_KEY", "DATABASE_URL"} {
		if !strings.Contains(output, key) {
			t.Fatalf("expected output to contain key %s, got:\n%s", key, output)
		}
	}
}

func TestFormatDiffResultShowsValues(t *testing.T) {
	result := diffResult{
		Added:   []diffEntry{{Key: "API_KEY", Value: "secret"}},
		Changed: []diffChange{{Key: "DATABASE_URL", OldValue: "old", NewValue: "new"}},
	}

	output := formatDiffResult(result, diffFormatOptions{ShowValues: true})
	for _, want := range []string{"API_KEY=secret", "DATABASE_URL=old", "DATABASE_URL=new"} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}
