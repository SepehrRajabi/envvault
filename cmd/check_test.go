package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunSchemaCheckValidPasses(t *testing.T) {
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, ".envschema")
	envPath := filepath.Join(dir, ".env")

	if err := os.WriteFile(schemaPath, []byte("PORT = required, uint, 1-65535\n"), 0600); err != nil {
		t.Fatalf("write schema: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("PORT=8080\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	if err := runSchemaCheck(schemaPath, envPath, false); err != nil {
		t.Fatalf("expected schema check to pass, got %v", err)
	}
}

func TestRunSchemaCheckMissingRequiredKeyFails(t *testing.T) {
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, ".envschema")
	envPath := filepath.Join(dir, ".env")

	if err := os.WriteFile(schemaPath, []byte("PORT = required, uint, 1-65535\n"), 0600); err != nil {
		t.Fatalf("write schema: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("OTHER=1\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	if err := runSchemaCheck(schemaPath, envPath, false); err == nil {
		t.Fatal("expected schema check to fail when a required key is missing")
	}
}

func TestRunSchemaCheckStrictRejectsExtraKeys(t *testing.T) {
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, ".envschema")
	envPath := filepath.Join(dir, ".env")

	if err := os.WriteFile(schemaPath, []byte("PORT = required, uint, 1-65535\n"), 0600); err != nil {
		t.Fatalf("write schema: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("PORT=8080\nEXTRA=1\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	if err := runSchemaCheck(schemaPath, envPath, false); err != nil {
		t.Fatalf("expected non-strict check to allow extra keys, got %v", err)
	}
	if err := runSchemaCheck(schemaPath, envPath, true); err == nil {
		t.Fatal("expected --strict to reject keys not defined in the schema")
	}
}

func TestCheckCommandWiresStrictFlag(t *testing.T) {
	checkStrict = false
	t.Cleanup(func() { checkStrict = false })

	dir := t.TempDir()
	schemaPath := filepath.Join(dir, ".envschema")
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(schemaPath, []byte("PORT = required, uint, 1-65535\n"), 0600); err != nil {
		t.Fatalf("write schema: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("PORT=8080\nEXTRA=1\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	checkStrict = true
	if err := checkCmd.RunE(checkCmd, []string{schemaPath, envPath}); err == nil {
		t.Fatal("expected check --strict to reject undeclared keys")
	}
}
