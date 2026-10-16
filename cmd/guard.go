package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	guardInit bool
	guardHook bool
)

var guardCmd = &cobra.Command{
	Use:   "guard",
	Short: "Prevent accidental commits of unencrypted .env files",
	Long:  "Checks git staging area for unencrypted .env files. Use --init to update .gitignore or --hook to install a pre-commit hook.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if guardInit {
			return initGitignore()
		}
		if guardHook {
			return installPreCommitHook()
		}
		return checkStagedFiles()
	},
}

func init() {
	guardCmd.Flags().BoolVar(&guardInit, "init", false, "Add .env patterns to .gitignore")
	guardCmd.Flags().BoolVar(&guardHook, "hook", false, "Install a git pre-commit hook")
	rootCmd.AddCommand(guardCmd)
}

// isDangerousEnvFile checks if a file looks like an unencrypted .env file
func isDangerousEnvFile(file string) bool {
	base := filepath.Base(file)
	// ".env", ".env.local", "prod.env", "app.env.production", ...
	if !strings.HasPrefix(base, ".env") && !strings.HasSuffix(base, ".env") && !strings.Contains(base, ".env.") {
		return false
	}
	// Allow encrypted vaults, examples/templates, and schema files (which
	// hold key names and types, not values).
	allowedSuffixes := []string{".vault", ".example", ".template", ".sample", ".envschema", ".env.schema"}
	for _, suffix := range allowedSuffixes {
		if strings.HasSuffix(base, suffix) {
			return false
		}
	}
	return true
}

func checkStagedFiles() error {
	// Get staged files from git
	// -z: NUL-separated, unquoted paths (git otherwise quotes names with
	// unusual characters, which would defeat the name matching below).
	out, err := exec.Command("git", "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR").Output()
	if err != nil {
		// Not a git repo or git not installed
		return fmt.Errorf("not a git repository (or git is not installed)")
	}

	files := strings.Split(string(out), "\x00")
	var dangerous []string

	for _, file := range files {
		if file == "" {
			continue
		}
		if isDangerousEnvFile(file) {
			dangerous = append(dangerous, file)
		}
	}

	if len(dangerous) == 0 {
		fmt.Println("✅ No unencrypted .env files found in staging area.")
		return nil
	}

	fmt.Println("❌ Danger! Unencrypted .env files found in git staging area:")
	for _, f := range dangerous {
		fmt.Printf("   - %s\n", f)
	}
	fmt.Println()
	fmt.Println("To fix this, run:")
	fmt.Println("  envvault lock <file>    # Encrypt the file")
	fmt.Println("  git rm --cached <file>  # Remove it from the staging area")
	fmt.Println("  envvault guard --init   # Update .gitignore")

	return fmt.Errorf("unencrypted .env files staged for commit")
}

func initGitignore() error {
	gitignorePath := ".gitignore"

	// Check if .gitignore exists
	var f *os.File
	if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
		f, err = os.Create(gitignorePath)
		if err != nil {
			return fmt.Errorf("creating .gitignore: %w", err)
		}
		fmt.Println("📝 Created .gitignore")
	} else {
		f, err = os.OpenFile(gitignorePath, os.O_RDWR, 0644)
		if err != nil {
			return fmt.Errorf("opening .gitignore: %w", err)
		}
	}
	defer f.Close()

	// Read existing content
	scanner := bufio.NewScanner(f)
	existingLines := make(map[string]bool)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		existingLines[line] = true
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading .gitignore: %w", err)
	}

	// Patterns to add
	patterns := []string{
		"# envvault",
		".env",
		".env.*",
		"!.env.vault",
		"!.env.example",
		"!.env.template",
		"*.env",
		"!*.env.example",
		"!*.vault",
		".envvault-*",
	}

	// Append missing patterns
	var toAdd []string
	for _, p := range patterns {
		if !existingLines[p] {
			toAdd = append(toAdd, p)
		}
	}

	if len(toAdd) == 0 {
		fmt.Println("✅ .gitignore already configured correctly.")
		return nil
	}

	// Add a newline if file doesn't end with one
	stat, _ := f.Stat()
	if stat.Size() > 0 {
		f.Seek(-1, 2)
		buf := make([]byte, 1)
		f.Read(buf)
		if buf[0] != '\n' {
			f.WriteString("\n")
		}
	}

	for _, p := range toAdd {
		f.WriteString(p + "\n")
	}

	fmt.Println("🔒 Updated .gitignore with .env patterns")
	return nil
}

func installPreCommitHook() error {
	// Ensure .git/hooks exists
	hooksDir := ".git/hooks"
	if _, err := os.Stat(hooksDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository (missing .git/hooks)")
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	hookContent := `#!/bin/sh
# envvault pre-commit hook
envvault guard
if [ $? -ne 0 ]; then
    echo "Commit aborted: unencrypted .env files detected."
    exit 1
fi
`

	// Check if hook already exists
	if _, err := os.Stat(hookPath); err == nil {
		// Read existing hook to see if we already injected it
		data, _ := os.ReadFile(hookPath)
		if strings.Contains(string(data), "envvault guard") {
			fmt.Println("✅ Pre-commit hook already installed.")
			return nil
		}
		// Insert the guard right after the shebang. Appending could leave it
		// unreachable behind an earlier `exit 0` in the existing hook.
		existing := string(data)
		block := strings.TrimPrefix(hookContent, "#!/bin/sh\n")
		var updated string
		if strings.HasPrefix(existing, "#!") {
			nl := strings.IndexByte(existing, '\n')
			if nl < 0 {
				nl = len(existing)
				existing += "\n"
			}
			updated = existing[:nl+1] + block + existing[nl+1:]
		} else {
			updated = "#!/bin/sh\n" + block + existing
		}
		if err := os.WriteFile(hookPath, []byte(updated), 0755); err != nil {
			return fmt.Errorf("updating existing hook: %w", err)
		}
		fmt.Println("🪝 Added envvault guard to the start of the existing pre-commit hook.")
		return nil
	}

	// Create new hook
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\n"+hookContent), 0755); err != nil {
		return fmt.Errorf("writing pre-commit hook: %w", err)
	}

	fmt.Println("🪝 Created .git/hooks/pre-commit")
	fmt.Println("   Unencrypted .env files will now be blocked automatically on commit.")
	return nil
}
