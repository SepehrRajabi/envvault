package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteSecretFileTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("OLD=1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(path, []byte("NEW=2\n")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	if got, _ := os.ReadFile(path); string(got) != "NEW=2\n" {
		t.Errorf("content = %q", got)
	}
}

func TestWriteSecretFileRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, ".env")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(link, []byte("SECRET=1\n")); err == nil {
		t.Fatal("expected symlink to be refused")
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep" {
		t.Errorf("symlink target was modified: %q", got)
	}
}

func TestReceiveImportWritesOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	target := filepath.Join(t.TempDir(), "sub", ".env.local")
	if err := importVariables(map[string]string{"A": "1"}, target); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("imported file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestValidateReceivedVars(t *testing.T) {
	ok := map[string]string{"API_KEY": "abc 123"}
	if err := validateReceivedVars(ok, false); err != nil {
		t.Fatalf("valid vars rejected: %v", err)
	}
	bad := []map[string]string{
		{"A;touch /tmp/pwn": "1"},
		{"A$(id)": "1"},
		{"GOOD": "x\nEVIL=1"},
		{"GOOD": "x\x00y"},
		{"PATH": "/tmp/evil"},
		{"ld_preload": "/tmp/x.so"},
		{"AGE_IDENTITY": "AGE-SECRET-KEY-1"},
	}
	for _, v := range bad {
		if err := validateReceivedVars(v, false); err == nil {
			t.Errorf("expected rejection of %v", v)
		}
	}
	if err := validateReceivedVars(map[string]string{"PATH": "/usr/bin"}, true); err != nil {
		t.Errorf("--allow-sensitive should permit PATH: %v", err)
	}
	if err := validateReceivedVars(map[string]string{"A;x": "1"}, true); err == nil {
		t.Error("--allow-sensitive must not permit invalid names")
	}
}
