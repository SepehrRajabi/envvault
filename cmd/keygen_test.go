package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestKeygenCommandWritesToCustomOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	outPath := filepath.Join(dir, "keys.txt")
	keygenOutput = outPath
	t.Cleanup(func() { keygenOutput = "" })

	out := captureStdout(t, func() {
		if err := keygenCmd.RunE(keygenCmd, nil); err != nil {
			t.Fatalf("keygen: %v", err)
		}
	})

	if !strings.Contains(out, "Public key:") {
		t.Fatalf("expected output to print a public key, got:\n%s", out)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected key file to be written: %v", err)
	}
	if !strings.Contains(string(data), "AGE-SECRET-KEY-") {
		t.Fatalf("expected private key to be written, got:\n%s", data)
	}

	// The written identity must actually be a valid, usable Age key.
	identities, err := age.ParseIdentities(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("expected valid age identity in key file: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("expected exactly one identity, got %d", len(identities))
	}
}

func TestKeygenCommandAppendsToExistingFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	outPath := filepath.Join(dir, "keys.txt")
	keygenOutput = outPath
	t.Cleanup(func() { keygenOutput = "" })

	if err := keygenCmd.RunE(keygenCmd, nil); err != nil {
		t.Fatalf("keygen (first): %v", err)
	}
	if err := keygenCmd.RunE(keygenCmd, nil); err != nil {
		t.Fatalf("keygen (second): %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if strings.Count(string(data), "AGE-SECRET-KEY-") != 2 {
		t.Fatalf("expected two appended keys, got:\n%s", data)
	}
}
