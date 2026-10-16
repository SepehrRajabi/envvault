package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/crypto"
)

func TestExportCommandPrintsEnvLines(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	algorithm = ""

	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := exportCmd.RunE(exportCmd, []string{vaultPath}); err != nil {
			t.Fatalf("export: %v", err)
		}
	})

	if !strings.Contains(out, "secret=very_secret") {
		t.Fatalf("expected export output to contain the decrypted variable, got %q", out)
	}
}

func TestExportCommandInvalidVaultErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	algorithm = ""

	vaultPath := filepath.Join(t.TempDir(), "corrupt.env.vault")
	if err := os.WriteFile(vaultPath, []byte("not a vault"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := exportCmd.RunE(exportCmd, []string{vaultPath}); err == nil {
		t.Fatal("expected export of a corrupt vault to fail")
	}
}

// --shell output must be inert under eval: no command substitution, no
// word-splitting, values round-trip exactly.
func TestExportShellIsSafeToEval(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", testPass)
	algorithm = ""

	dir := t.TempDir()
	pwned := filepath.Join(dir, "pwned")
	content := "PLAIN=ok\n" +
		"SPACED=a b  c\n" +
		"INJECT=$(touch " + pwned + ")\n" +
		"TICKS=`touch " + pwned + "`\n" +
		"SEMI=x; touch " + pwned + "\n" +
		"QUOTE=it's \"here\"\n"
	path := filepath.Join(dir, "v.env.vault")
	enc, err := crypto.Encrypt([]byte(content), []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, enc, 0600)

	exportShell = true
	t.Cleanup(func() { exportShell = false })
	out := captureStdout(t, func() {
		if err := exportCmd.RunE(exportCmd, []string{path}); err != nil {
			t.Fatal(err)
		}
	})

	script := out + `printf '%s|%s|%s|%s|%s|%s' "$PLAIN" "$SPACED" "$INJECT" "$TICKS" "$SEMI" "$QUOTE"`
	got, err := exec.Command("sh", "-c", script).Output()
	if err != nil {
		t.Fatalf("eval failed: %v\n%s", err, script)
	}
	want := "ok|a b  c|$(touch " + pwned + ")|`touch " + pwned + "`|x; touch " + pwned + `|it's "here"`
	if string(got) != want {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got, want)
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Fatal("command injection executed")
	}
}
