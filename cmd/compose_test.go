package cmd

import (
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/envfile"
)

func TestFormatComposeYAML(t *testing.T) {
	vars := []envfile.EnvVar{
		{Key: "DATABASE_URL", Value: "postgres://user:pass@localhost/db"},
		{Key: "DEBUG", Value: "true"},
	}

	got := formatComposeYAML("api", "example/api:latest", vars)
	wantParts := []string{
		"services:\n",
		"  api:\n",
		"    image: \"example/api:latest\"\n",
		"    environment:\n",
		"      DATABASE_URL: \"postgres://user:pass@localhost/db\"\n",
		"      DEBUG: \"true\"\n",
	}
	for _, want := range wantParts {
		if !strings.Contains(got, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, got)
		}
	}
}

func TestYAMLScalarEscapesQuotesAndBackslashes(t *testing.T) {
	got := yamlScalar(`C:\tmp\"secret"`)
	want := `"C:\\tmp\\\"secret\""`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
