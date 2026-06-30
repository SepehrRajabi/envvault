package cmd

import (
	"strings"
	"testing"
)

func TestSetEnvValueAddsAndUpdates(t *testing.T) {
	content := []byte("# comment\nFOO=bar\n")

	updated, existed, err := setEnvValue(content, "API_KEY", "secret")
	if err != nil {
		t.Fatalf("setEnvValue add: %v", err)
	}
	if existed {
		t.Fatalf("expected key to be added, not updated")
	}
	if got := string(updated); got != "# comment\nFOO=bar\nAPI_KEY=secret\n" {
		t.Fatalf("unexpected add output:\n%s", got)
	}

	updated, existed, err = setEnvValue(updated, "FOO", "baz")
	if err != nil {
		t.Fatalf("setEnvValue update: %v", err)
	}
	if !existed {
		t.Fatalf("expected key to be updated")
	}
	if got := string(updated); got != "# comment\nFOO=baz\nAPI_KEY=secret\n" {
		t.Fatalf("unexpected update output:\n%s", got)
	}
}

func TestUnsetEnvValue(t *testing.T) {
	updated, removed, err := unsetEnvValue([]byte("FOO=bar\nAPI_KEY=secret\n"), "FOO")
	if err != nil {
		t.Fatalf("unsetEnvValue: %v", err)
	}
	if !removed {
		t.Fatalf("expected key to be removed")
	}
	if got := string(updated); got != "API_KEY=secret\n" {
		t.Fatalf("unexpected unset output: %q", got)
	}
}

func TestRenameEnvKey(t *testing.T) {
	updated, err := renameEnvKey([]byte("OLD=value\nOTHER=yes\n"), "OLD", "NEW")
	if err != nil {
		t.Fatalf("renameEnvKey: %v", err)
	}
	if got := string(updated); got != "NEW=value\nOTHER=yes\n" {
		t.Fatalf("unexpected rename output: %q", got)
	}
}

func TestRenameEnvKeyRejectsExistingTarget(t *testing.T) {
	_, err := renameEnvKey([]byte("OLD=value\nNEW=already\n"), "OLD", "NEW")
	if err == nil || !strings.Contains(err.Error(), "target key already exists") {
		t.Fatalf("expected existing target error, got %v", err)
	}
}
