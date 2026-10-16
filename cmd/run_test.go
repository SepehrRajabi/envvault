package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/SepehrRajabi/envvault/crypto"
)

func TestRunCommandInjectsDecryptedEnvVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relies on a POSIX shell")
	}
	t.Setenv("HOME", t.TempDir())
	algorithm = ""

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("INJECTED_VAR=hello-from-vault\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	outPath := filepath.Join(dir, "out.txt")

	// Plain (non-vault) env file: run.go's loadVars skips the password
	// prompt entirely for non-".env.vault" content, so this is safe to
	// exercise without any stdin/keyring setup.
	args := []string{envPath, "sh", "-c", "echo \"$INJECTED_VAR\" > \"$1\"", "run-test", outPath}
	if err := runCmd.RunE(runCmd, args); err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected child process to write output file: %v", err)
	}
	if strings.TrimSpace(string(data)) != "hello-from-vault" {
		t.Fatalf("expected injected env var to reach child process, got %q", data)
	}
}

func TestRunDoesNotLeakCredentialsToChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relies on a POSIX shell")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-91")
	t.Setenv("AGE_IDENTITY", "AGE-SECRET-KEY-1NOTREALKEY")
	t.Setenv("KEEP_ME", "visible")
	algorithm = ""

	dir := t.TempDir()
	vault := filepath.Join(dir, "v.env.vault")
	enc, err := crypto.Encrypt([]byte("FROM_VAULT=yes\n"), []byte("correct-horse-battery-staple-91"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vault, enc, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.txt")

	// ENVVAULT_PASSWORD must also be honored by run (it is how CI supplies it).
	script := `printf '%s|%s|%s|%s' "${ENVVAULT_PASSWORD-unset}" "${AGE_IDENTITY-unset}" "$KEEP_ME" "$FROM_VAULT" > "$1"`
	if err := runCmd.RunE(runCmd, []string{vault, "sh", "-c", script, "run-test", out}); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "unset|unset|visible|yes" {
		t.Fatalf("child env = %q, want credentials stripped", got)
	}
}

func TestRunCredentialsSkipsPromptForAgePubkey(t *testing.T) {
	t.Setenv("ENVVAULT_PASSWORD", "")
	p, _ := crypto.GetProvider("age-pubkey")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.Encrypt([]byte("A=1\n"), []byte(id.Recipient().String()), p)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := runCredentials(enc, "x.vault")
	if err != nil {
		t.Fatalf("age-pubkey vault should not prompt: %v", err)
	}
	lb.Unlock()
}
