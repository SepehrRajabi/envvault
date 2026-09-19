package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetSchemaFlags() {
	schemaOutputPath = ""
	schemaForce = false
	schemaOptional = false
	schemaCheckStrict = false
	algorithm = ""
}

func TestSchemaInitCommandWritesDefaultTemplate(t *testing.T) {
	resetSchemaFlags()
	t.Cleanup(resetSchemaFlags)

	dir := t.TempDir()
	out := filepath.Join(dir, ".envschema")
	schemaOutputPath = out

	if err := schemaInitCmd.RunE(schemaInitCmd, nil); err != nil {
		t.Fatalf("schema init: %v", err)
	}

	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if !strings.Contains(string(content), "DATABASE_URL") {
		t.Fatalf("expected default template content, got:\n%s", content)
	}
}

func TestSchemaInitCommandRefusesToOverwriteWithoutForce(t *testing.T) {
	resetSchemaFlags()
	t.Cleanup(resetSchemaFlags)

	dir := t.TempDir()
	out := filepath.Join(dir, ".envschema")
	if err := os.WriteFile(out, []byte("existing"), 0600); err != nil {
		t.Fatalf("seed existing schema: %v", err)
	}
	schemaOutputPath = out

	if err := schemaInitCmd.RunE(schemaInitCmd, nil); err == nil {
		t.Fatal("expected schema init to refuse to overwrite an existing file without --force")
	}

	schemaForce = true
	if err := schemaInitCmd.RunE(schemaInitCmd, nil); err != nil {
		t.Fatalf("expected --force to allow overwrite, got %v", err)
	}
}

func TestSchemaInitCommandInfersFromEnvFile(t *testing.T) {
	resetSchemaFlags()
	t.Cleanup(resetSchemaFlags)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("PORT=8080\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	out := filepath.Join(dir, ".envschema")
	schemaOutputPath = out

	if err := schemaInitCmd.RunE(schemaInitCmd, []string{envPath}); err != nil {
		t.Fatalf("schema init from env file: %v", err)
	}

	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated schema: %v", err)
	}
	if !strings.Contains(string(content), "PORT") {
		t.Fatalf("expected generated schema to mention PORT, got:\n%s", content)
	}
}

func TestSchemaGenerateCommandOptionalRules(t *testing.T) {
	resetSchemaFlags()
	t.Cleanup(resetSchemaFlags)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("PORT=8080\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	out := filepath.Join(dir, ".envschema")
	schemaOutputPath = out
	schemaOptional = true

	if err := schemaGenerateCmd.RunE(schemaGenerateCmd, []string{envPath}); err != nil {
		t.Fatalf("schema generate: %v", err)
	}

	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated schema: %v", err)
	}
	if strings.Contains(string(content), "PORT = required") {
		t.Fatalf("expected --optional to generate non-required rules, got:\n%s", content)
	}
}

func TestEnsureSchemaOutputWritableRejectsWrongExtension(t *testing.T) {
	dir := t.TempDir()
	if err := ensureSchemaOutputWritable(filepath.Join(dir, "schema.txt"), false); err == nil {
		t.Fatal("expected non-.envschema extension to be rejected")
	}
}

func TestSchemaCheckCommandMatchesTopLevelCheck(t *testing.T) {
	resetSchemaFlags()
	t.Cleanup(resetSchemaFlags)

	dir := t.TempDir()
	schemaPath := filepath.Join(dir, ".envschema")
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(schemaPath, []byte("PORT = required, uint, 1-65535\n"), 0600); err != nil {
		t.Fatalf("write schema: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("PORT=8080\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	if err := schemaCheckCmd.RunE(schemaCheckCmd, []string{schemaPath, envPath}); err != nil {
		t.Fatalf("schema check: %v", err)
	}
}
