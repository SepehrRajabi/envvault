package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/keyring"
)

// doctorCheck is one row of `envvault doctor` output: a labeled pass/warn/fail
// result plus an optional hint shown when it isn't a clean pass.
type doctorCheck struct {
	Name   string
	OK     bool
	Warn   bool // true for a non-fatal issue (renders ⚠️ instead of ❌)
	Detail string
	Hint   string
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose your envvault environment",
	Long:  "Checks the local environment for common issues: keyring access, age identities, editor config, git protection, and vault file health.",
	RunE: func(cmd *cobra.Command, args []string) error {
		runDoctor()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor() {
	checks := []doctorCheck{
		checkOSKeyring(),
		checkAgeIdentity(),
		checkEditor(),
		checkGitignore(),
		checkPreCommitHook(),
		checkMemoryLock(),
	}

	fmt.Println("\n🩺 envvault doctor")
	fmt.Println(strings.Repeat("─", 100))
	fmt.Printf("%-28s %-8s %s\n", "Check", "Status", "Detail")
	fmt.Println(strings.Repeat("─", 100))

	failures := 0
	for _, c := range checks {
		status := "✅ OK"
		if !c.OK {
			if c.Warn {
				status = "⚠️  WARN"
			} else {
				status = "❌ FAIL"
				failures++
			}
		}
		fmt.Printf("%-28s %-8s %s\n", c.Name, status, c.Detail)
		if !c.OK && c.Hint != "" {
			fmt.Printf("%-28s %-8s %s %s\n", "", "", "  →", c.Hint)
		}
	}
	fmt.Println(strings.Repeat("─", 100))

	fmt.Printf("\nversion: %s\n", fullVersion())

	fmt.Println("\n🔐 Supported algorithms")
	for _, info := range crypto.ListProviders(false) {
		marker := " "
		if crypto.Default() != nil && info.ID == crypto.Default().AlgorithmID() {
			marker = "*"
		}
		security := "insecure"
		if info.Secure {
			security = "secure"
		}
		fmt.Printf("  %s %s (%s)\n", marker, info.ID, security)
	}

	fmt.Println("\n📦 Vault files")
	reportSuspiciousVaultFiles()

	if failures > 0 {
		fmt.Printf("\n%d check(s) failed.\n", failures)
	} else {
		fmt.Println("\nAll checks passed.")
	}
}

func checkOSKeyring() doctorCheck {
	if err := keyring.CheckAvailable(); err != nil {
		return doctorCheck{Name: "OS keyring", Detail: err.Error(),
			Hint: "keys and tokens will need to be entered manually each run"}
	}
	return doctorCheck{Name: "OS keyring", OK: true, Detail: "available"}
}

func checkAgeIdentity() doctorCheck {
	if key := os.Getenv("AGE_IDENTITY"); key != "" {
		return doctorCheck{Name: "Age identity", OK: true, Detail: "set via AGE_IDENTITY"}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return doctorCheck{Name: "Age identity", Warn: true, Detail: "could not determine home directory"}
	}

	candidates := []string{
		filepath.Join(home, ".envvault", "keys.txt"),
		filepath.Join(home, ".config", "age", "keys.txt"),
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return doctorCheck{Name: "Age identity", OK: true, Detail: path}
		}
	}

	return doctorCheck{Name: "Age identity", Warn: true, Detail: "no identity file found",
		Hint: "only needed for the age-pubkey algorithm; set AGE_IDENTITY or create ~/.envvault/keys.txt"}
}

// checkEditor mirrors launchEditor's own fallback order (VISUAL, then
// EDITOR, then a platform default), since edit doesn't actually fail when
// neither env var is set — it falls back to notepad/vi. The check only
// warns if even that fallback binary can't be found on PATH.
func checkEditor() doctorCheck {
	source := "VISUAL"
	editor := os.Getenv("VISUAL")
	if editor == "" {
		source = "EDITOR"
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		source = "default"
		if runtime.GOOS == "windows" {
			editor = "notepad"
		} else {
			editor = "vi"
		}
	}

	bin := strings.Fields(editor)[0]
	if _, err := exec.LookPath(bin); err != nil {
		return doctorCheck{Name: "Editor", Warn: true, Detail: fmt.Sprintf("%s (%s) not found on PATH", editor, source),
			Hint: "'envvault edit' will fail; set $EDITOR to an installed editor"}
	}
	return doctorCheck{Name: "Editor", OK: true, Detail: fmt.Sprintf("%s (%s)", editor, source)}
}

func checkGitignore() doctorCheck {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		return doctorCheck{Name: ".gitignore", Warn: true, Detail: "not a git repository"}
	}
	if hasGitignorePatterns() {
		return doctorCheck{Name: ".gitignore", OK: true, Detail: "configured with .env patterns"}
	}
	return doctorCheck{Name: ".gitignore", Detail: "missing .env patterns", Hint: "run: envvault guard --init"}
}

func checkPreCommitHook() doctorCheck {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		return doctorCheck{Name: "Git pre-commit hook", Warn: true, Detail: "not a git repository"}
	}
	if hasPreCommitHook() {
		return doctorCheck{Name: "Git pre-commit hook", OK: true, Detail: "installed"}
	}
	return doctorCheck{Name: "Git pre-commit hook", Warn: true, Detail: "not installed", Hint: "run: envvault guard --hook"}
}

func checkMemoryLock() doctorCheck {
	lb, err := crypto.NewLockedBytes(32)
	if err != nil {
		return doctorCheck{Name: "Memory lock (mlock)", Warn: true, Detail: err.Error(),
			Hint: "decrypted secrets may be swappable to disk"}
	}
	defer lb.Unlock()
	return doctorCheck{Name: "Memory lock (mlock)", OK: true, Detail: "supported"}
}

// reportSuspiciousVaultFiles scans the current directory for vault files
// that fail structural verification (corrupted/tampered) or whose extension
// disagrees with their content (e.g. a plaintext .env.vault, or an envelope
// missing the .vault suffix).
func reportSuspiciousVaultFiles() {
	entries, err := os.ReadDir(".")
	if err != nil {
		fmt.Printf("  could not scan directory: %v\n", err)
		return
	}

	var suspicious []string
	scanned := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		data, err := os.ReadFile(name)
		if err != nil {
			continue
		}

		if !isVaultFile(name, data) {
			continue
		}
		scanned++

		if _, err := crypto.Verify(data); err != nil {
			suspicious = append(suspicious, fmt.Sprintf("%s: %v", name, err))
		}
	}

	if scanned == 0 {
		fmt.Println("  no vault files found")
		return
	}
	if len(suspicious) == 0 {
		fmt.Printf("  %d vault file(s) scanned, none suspicious\n", scanned)
		return
	}
	for _, s := range suspicious {
		fmt.Printf("  ⚠️  %s\n", s)
	}
}
