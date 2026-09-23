package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status of all vault files in the current directory",
	Long:  "Display information about all .env*.vault files including their encryption method, keyring status, and modification times.",
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultFiles, err := findVaultFiles(".")
		if err != nil {
			return fmt.Errorf("scanning directory: %w", err)
		}

		if len(vaultFiles) == 0 {
			fmt.Println("No vault files found in current directory")
			return nil
		}

		fmt.Println("\n📦 Vault Status")
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("%-25s %-20s %-15s %-35s\n", "File", "Algorithm", "Keyring", "Last Modified")
		fmt.Println(strings.Repeat("─", 120))

		for _, vaultFile := range vaultFiles {
			info, err := getVaultInfo(vaultFile)
			if err != nil {
				fmt.Printf("%-25s %-20s %-15s %-35s\n", vaultFile, "ERROR", "?", err.Error())
				continue
			}

			keyringStatus := "❌ No"
			if info.HasKeyring {
				keyringStatus = "✅ Yes"
			}

			fi, _ := os.Stat(vaultFile)
			modTime := ""
			if fi != nil {
				modTime = fi.ModTime().Format("2006-01-02 15:04:05")
			}

			fmt.Printf("%-25s %-20s %-15s %-35s\n", vaultFile, info.Algorithm, keyringStatus, modTime)
		}

		fmt.Println(strings.Repeat("─", 120))

		// Check git setup
		fmt.Println("\n🔐 Git Protection")
		printGitStatus()

		fmt.Println("\n🐞 Debug Mode")
		printDebugStatus()

		return nil
	},
}

// VaultInfo summarizes a vault file's metadata for display, without
// decrypting it. See getVaultInfo.
type VaultInfo struct {
	Algorithm  string
	HasKeyring bool
	Version    uint8
}

func findVaultFiles(dir string) ([]string, error) {
	var vaultFiles []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".vault") {
			vaultFiles = append(vaultFiles, entry.Name())
		}
	}

	return vaultFiles, nil
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func printGitStatus() {
	// Check if it's a git repository
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Println("⚠️  Not a git repository")
		return
	}

	// Check .gitignore
	hasGitignore := hasGitignorePatterns()
	if hasGitignore {
		fmt.Println("   ✅ .gitignore configured with .env patterns")
	} else {
		fmt.Println("   ❌ .gitignore missing .env patterns")
		fmt.Println("      Run: envvault guard --init")
	}

	// Check pre-commit hook
	hasHook := hasPreCommitHook()
	if hasHook {
		fmt.Println("   ✅ Pre-commit hook installed")
	} else {
		fmt.Println("   ❌ Pre-commit hook not installed")
		fmt.Println("      Run: envvault guard --hook")
	}
}

func hasGitignorePatterns() bool {
	gitignorePath := ".gitignore"
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		return false
	}

	content := string(data)
	// Check for the key envvault patterns
	patterns := []string{".env", "!.env.vault"}
	for _, pattern := range patterns {
		if !strings.Contains(content, pattern) {
			return false
		}
	}
	return true
}

// debugEnvValue and isDebugEnabled mirror main.go's own DEBUG parsing
// (DEBUG=1/true enables debug mode, anything else — including unset —
// leaves it disabled).
func debugEnvValue() string {
	return os.Getenv("DEBUG")
}

func isDebugEnabled() bool {
	v := strings.ToLower(debugEnvValue())
	return v == "1" || v == "true"
}

func printDebugStatus() {
	raw := debugEnvValue()
	if raw == "" {
		fmt.Println("   ⚠️  DEBUG not set (disabled)")
		return
	}
	if isDebugEnabled() {
		fmt.Printf("   ✅ DEBUG=%s (enabled)\n", raw)
	} else {
		fmt.Printf("   ⚠️  DEBUG=%s (set, but not a recognized truthy value — disabled)\n", raw)
	}
}

func hasPreCommitHook() bool {
	hookPath := filepath.Join(".git", "hooks", "pre-commit")
	data, err := os.ReadFile(hookPath)
	if err != nil {
		return false
	}

	content := string(data)
	return strings.Contains(content, "envvault guard")
}
