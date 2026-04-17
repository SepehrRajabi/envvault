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

var editRecipient string

var editCmd = &cobra.Command{
	Use:   "edit [vault-file]",
	Short: "Edit an encrypted vault file in your default editor",
	Long: "Decrypts a .env.vault file into a temporary file, opens it in $EDITOR, " +
		"and re-encrypts it on save. Re-uses the existing password by default.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// 1. Read the encrypted vault
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		// 2. Get credentials (handles password prompt OR age-pubkey automatically)
		password, err := getVaultCredentials(data)
		if err != nil {
			return err
		}

		// 3. Decrypt
		var p crypto.Provider
		if algorithm != "" {
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

		// CRITICAL: Always remove the temp file when we're done
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

		// 10. Determine how to re-encrypt
		var newPassword []byte

		alg, _ := crypto.PeekAlgorithm(data)

		if alg == "age-pubkey" {
			// We can't reuse the "password" because it was empty for pubkey.
			// We need the user to specify --recipient again, or give a new password.
			if editRecipient != "" {
				newPassword = []byte(editRecipient)
				p, err = crypto.GetProvider("age-pubkey")
				if err != nil {
					return err
				}
			} else {
				fmt.Println("Vault was encrypted with a public key. Please enter a new password to re-encrypt (or run with --recipient).")
				newPassword, err = crypto.GetPassword("Enter new password: ")
				if err != nil {
					return err
				}
				confirm, err := crypto.GetPassword("Confirm new password: ")
				if err != nil {
					return err
				}
				if string(newPassword) != string(confirm) {
					return fmt.Errorf("passwords do not match")
				}
				if err := crypto.CheckPasswordStrength(newPassword, false); err != nil {
					return err
				}
			}
		} else {
			// Standard password vault: reuse the same password!
			newPassword = password
		}

		// 11. Re-encrypt
		encrypted, err := crypto.Encrypt(modified, newPassword, p)
		if err != nil {
			return fmt.Errorf("re-encrypting: %w", err)
		}

		// 12. Atomically write back to the vault file
		if err := atomicWrite(filePath, encrypted); err != nil {
			return fmt.Errorf("writing vault: %w", err)
		}

		fmt.Printf("🔒 Saved changes to %s\n", filePath)
		_ = history.Record("Edit", filePath, p.AlgorithmID())

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
func secureCleanup(path string) {
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
		if runtime.GOOS == "windows" {
			editor = "notepad"
		} else {
			editor = "vi"
		}
	}

	parts := strings.Fields(editor)
	args := append(parts[1:], path)

	cmd := exec.Command(parts[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func init() {
	editCmd.Flags().StringVarP(&editRecipient, "recipient", "r", "", "Re-encrypt with an Age public key (age1...) after editing")

	rootCmd.AddCommand(editCmd)
}
