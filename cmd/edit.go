package cmd

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
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

		if err := enforceTrust(filePath, data); err != nil {
			return err
		}

		// 2. Get credentials (handles password prompt OR age-pubkey automatically)
		password, err := getVaultCredentials(data, filePath)
		if err != nil {
			return err
		}
		// Ensure password is wiped after decryption
		defer crypto.SecureWipe(password)

		// 3. Decrypt into locked memory to prevent swapping to disk
		var p crypto.Provider
		if algorithm != "" {
			p, err = crypto.GetProvider(algorithm)
			if err != nil {
				return fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
			}
		}
		lockedPlaintext, err := crypto.DecryptSecure(data, password, p)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
		defer lockedPlaintext.Unlock()

		decrypted := lockedPlaintext.Bytes()

		// 4. Parse .env contents to validate structure before editing
		if _, err := envfile.Parse(decrypted); err != nil {
			return fmt.Errorf("parsing env file: %w", err)
		}

		// 5. Create a secure temp file inside a private (0700) directory
		// that never lives in the vault's own directory, so it can't be
		// committed by accident and editor swap/backup/undo files are
		// confined to a directory we remove wholesale.
		tmpFile, err := createSecureTempFile(filePath)
		if err != nil {
			return fmt.Errorf("creating temp file: %w", err)
		}
		tmpPath := tmpFile.Name()

		// CRITICAL: Always remove the temp directory when we're done
		defer secureCleanup(filepath.Dir(tmpPath))

		// 6. Write decrypted content to temp file
		if _, err := tmpFile.Write(decrypted); err != nil {
			tmpFile.Close()
			return fmt.Errorf("writing temp file: %w", err)
		}
		tmpFile.Close()

		// 7. Compute checksum BEFORE editing to detect changes
		originalHash := sha256.Sum256(decrypted)

		// 8. Launch editor
		if err := launchEditor(tmpPath); err != nil {
			return fmt.Errorf("editor failed: %w", err)
		}

		// 9. Read the modified content
		modified, err := os.ReadFile(tmpPath)
		if err != nil {
			return fmt.Errorf("reading modified content: %w", err)
		}

		// 10. Check if anything actually changed
		newHash := sha256.Sum256(modified)
		if bytes.Equal(originalHash[:], newHash[:]) {
			fmt.Println("📝 No changes detected. Vault unchanged.")
			return nil
		}

		// 11. Parse edited .env contents to validate structure before re-encryption
		if _, err := envfile.Parse(modified); err != nil {
			return fmt.Errorf("parsing edited env file: %w", err)
		}

		// 12. Determine how to re-encrypt
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
				defer crypto.SecureWipe(newPassword)
				confirm, err := crypto.GetPassword("Confirm new password: ")
				if err != nil {
					return err
				}
				defer crypto.SecureWipe(confirm)
				if !bytes.Equal(newPassword, confirm) {
					return fmt.Errorf("passwords do not match")
				}
				if err := crypto.CheckPasswordStrength(newPassword, false); err != nil {
					return err
				}
				p = crypto.Default()
			}
		} else {
			// Standard password vault: reuse the same credentials under the
			// vault's existing algorithm.
			var secret []byte
			p, secret, err = reencryptionPlan(data, password)
			if err != nil {
				return err
			}
			newPassword = secret
			if alg == "shamir-aes256gcm" {
				defer crypto.SecureWipe(secret)
			}
		}

		// 13. Re-encrypt
		encrypted, err := crypto.Encrypt(modified, newPassword, p)
		if err != nil {
			return fmt.Errorf("re-encrypting: %w", err)
		}

		// 14. Atomically write back to the vault file, unless it changed on
		// disk while we were editing (we'd silently discard that change, or
		// overwrite a file someone substituted).
		if current, err := os.ReadFile(filePath); err != nil || !bytes.Equal(current, data) {
			return fmt.Errorf("%s changed on disk while editing; refusing to overwrite it (your edits were not saved)", filePath)
		}
		if err := atomicWrite(filePath, encrypted); err != nil {
			return fmt.Errorf("writing vault: %w", err)
		}

		// 15. Refresh the trust pin to match the freshly-edited content,
		// otherwise the next unlock/export/run would flag this legitimate
		// change as a substitution.
		record := crypto.TrustRecord{Algorithm: p.AlgorithmID(), Checksum: crypto.HashVaultChecksum(encrypted)}
		if p.AlgorithmID() == "age-pubkey" {
			if newHdr, err := crypto.Verify(encrypted); err == nil {
				record.Recipients = crypto.RecipientsFromHeader(newHdr)
			}
		}
		if err := crypto.SetTrust(filePath, record); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: failed to update trust pin for %s: %v\n", filePath, err)
		}

		fmt.Printf("🔒 Saved changes to %s\n", filePath)
		_ = history.Record("Edit", filePath, p.AlgorithmID())

		return nil
	},
}

// editTempRoot picks the most RAM-backed, per-user location available for
// the plaintext temp directory: $XDG_RUNTIME_DIR (a per-user tmpfs on Linux),
// then /dev/shm on Linux, then the OS temp dir (per-user on macOS/Windows).
// It is deliberately never the vault's own directory.
func editTempRoot() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	if runtime.GOOS == "linux" {
		if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
			return "/dev/shm"
		}
	}
	return os.TempDir()
}

// createSecureTempFile creates a temp file for editing vaultPath inside a
// fresh 0700 directory under editTempRoot.
func createSecureTempFile(vaultPath string) (*os.File, error) {
	dir, err := os.MkdirTemp(editTempRoot(), "envvault-edit-*")
	if err != nil {
		return nil, err
	}

	// Strip .vault extension for editor syntax highlighting
	base := strings.TrimSuffix(filepath.Base(vaultPath), ".vault")

	tmpFile, err := os.OpenFile(filepath.Join(dir, base), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return tmpFile, nil
}

// secureCleanup overwrites every file in dir (the edited file plus any
// swap/backup/undo files the editor left beside it) with zeros, then
// removes the directory. Overwriting is best-effort: it doesn't help on
// copy-on-write or journaling filesystems, which is why the directory
// lives on tmpfs where available.
func secureCleanup(dir string) {
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			_ = os.WriteFile(path, make([]byte, info.Size()), 0600)
		}
		return nil
	})
	_ = os.RemoveAll(dir)
}

// editorNoLeakArgs returns extra flags that stop well-known editors from
// writing plaintext to places outside the temp directory (e.g. vim's
// ~/.viminfo, or swap/undo files).
func editorNoLeakArgs(editor string) []string {
	name := strings.TrimSuffix(strings.ToLower(filepath.Base(editor)), ".exe")
	switch name {
	case "vim", "nvim":
		return []string{"-n", "-i", "NONE", "-c", "set nobackup nowritebackup noundofile"}
	}
	return nil
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
	args := append(append([]string{}, parts[1:]...), editorNoLeakArgs(parts[0])...)
	args = append(args, path)

	cmd := exec.Command(parts[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Keep this process alive while the editor runs so the deferred
	// cleanup of the plaintext temp directory always executes. Ctrl-C
	// already reaches the editor via the terminal's process group; signals
	// aimed only at us (kill, SIGHUP on terminal close) are forwarded.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-sigs:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()

	return cmd.Wait()
}

func init() {
	editCmd.Flags().StringVarP(&editRecipient, "recipient", "r", "", "Re-encrypt with an Age public key (age1...) after editing")

	rootCmd.AddCommand(editCmd)
}
