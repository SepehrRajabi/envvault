package cmd

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var editCmd = &cobra.Command{
	Use:   "edit [vault-file]",
	Short: "Edit an encrypted vault file in your default editor",
	Long: "Decrypts a .env.vault file into a temporary file, opens it in $EDITOR, " +
		"and re-encrypts it on save. The decrypted file never persists to disk.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// 1. Read the encrypted vault
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		// 2. Get password
		password, err := crypto.GetPassword("Enter your Password: ")
		if err != nil {
			return err
		}

		// 3. Decrypt
		var p crypto.Provider
		if algorithm != "" {
			var err error
			p, err = crypto.GetProvider(algorithm)
			if err != nil {
				return fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
			}
		}
		decrypted, err := crypto.Decrypt(data, password, p)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}

		// 4. Create a secure temp file
		tmpFile, err := createSecureTempFile(filePath)
		if err != nil {
			return fmt.Errorf("creating temp file: %w", err)
		}
		tmpPath := tmpFile.Name()

		// CRITICAL: Always remove the temp file when we're done,
		// regardless of how this function exits (panic, error, success).
		defer secureCleanup(tmpPath)

		// 5. Write decrypted content to temp file
		if _, err := tmpFile.Write(decrypted); err != nil {
			tmpFile.Close()
			return fmt.Errorf("writing temp file: %w", err)
		}
		tmpFile.Close()

		// 6. Compute checksum BEFORE editing to detect changes
		originalHash := sha256.Sum256(decrypted)

		// 7. Launch editor
		if err := launchEditor(tmpPath); err != nil {
			return fmt.Errorf("editor failed: %w", err)
		}

		// 8. Read the modified content
		modified, err := os.ReadFile(tmpPath)
		if err != nil {
			return fmt.Errorf("reading modified content: %w", err)
		}

		// 9. Check if anything actually changed
		newHash := sha256.Sum256(modified)
		if bytes.Equal(originalHash[:], newHash[:]) {
			fmt.Println("📝 No changes detected. Vault unchanged.")
			return nil
		}

		// 10. Re-encrypt with the same password
		encrypted, err := crypto.Encrypt(modified, password)
		if err != nil {
			return fmt.Errorf("re-encrypting: %w", err)
		}

		// 11. Atomically write back to the vault file
		if err := atomicWrite(filePath, encrypted); err != nil {
			return fmt.Errorf("writing vault: %w", err)
		}

		fmt.Printf("🔒 Saved changes to %s\n", filePath)
		_ = history.Record("Edit", filePath, algorithm)

		return nil
	},
}

// createSecureTempFile creates a temp file with restricted permissions
// in the same directory as the vault, so editor swap files stay isolated.
func createSecureTempFile(vaultPath string) (*os.File, error) {
	dir := filepath.Dir(vaultPath)
	base := filepath.Base(vaultPath)

	// Strip .vault extension for editor syntax highlighting
	base = strings.TrimSuffix(base, ".vault")

	// Pattern: ".envvault-<random>-.env"
	pattern := fmt.Sprintf(".envvault-*-%s", base)

	tmpFile, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}

	// Restrict permissions: only the owner can read/write
	if err := os.Chmod(tmpFile.Name(), 0600); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, err
	}

	return tmpFile, nil
}

// secureCleanup overwrites the temp file with zeros before deleting it.
// This is best-effort: SSDs and journaled filesystems may still retain data.
func secureCleanup(path string) {
	// Try to overwrite with zeros first
	if info, err := os.Stat(path); err == nil {
		zeros := make([]byte, info.Size())
		_ = os.WriteFile(path, zeros, 0600)
	}
	_ = os.Remove(path)
}

// launchEditor opens the file in the user's preferred editor.
func launchEditor(path string) error {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		// Sensible defaults per OS
		if runtime.GOOS == "windows" {
			editor = "notepad"
		} else {
			editor = "vi"
		}
	}

	// Split editor command in case it has flags (e.g., "code --wait")
	parts := strings.Fields(editor)
	args := append(parts[1:], path)

	cmd := exec.Command(parts[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// atomicWrite writes data by first writing to a temp file in the same directory,
// then renaming it. This prevents corruption if the program is interrupted.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".envvault-write-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	// On any failure, clean up the temp file
	defer func() {
		if _, err := os.Stat(tmpPath); err == nil {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	// Atomically replace the original file
	return os.Rename(tmpPath, path)
}

func init() {
	rootCmd.AddCommand(editCmd)
}
