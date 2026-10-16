package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/spf13/cobra"
)

// gitHashPattern matches a full SHA-1 or SHA-256 git object id. The hash in a
// vault header is attacker-controlled; anything else (notably a leading "-")
// would be passed to git as an option.
var gitHashPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

var verifyCommitCmd = &cobra.Command{
	Use:   "verify-commit [vault-file]",
	Short: "Verify embedded git commit signature metadata",
	Long:  "Checks that the vault file contains git commit metadata and validates the commit signature against the current repository.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		hdr, err := crypto.Verify(data)
		if err != nil {
			fmt.Printf("❌ Invalid vault: %v\n", err)
			return fmt.Errorf("verification failed")
		}

		if hdr.Commit == nil || hdr.Commit.Hash == "" {
			fmt.Println("❌ No git commit metadata found in vault header.")
			fmt.Println("   Run envvault lock from inside a git repository to embed commit metadata.")
			return fmt.Errorf("commit metadata missing")
		}

		if !gitHashPattern.MatchString(hdr.Commit.Hash) {
			fmt.Printf("❌ Embedded commit hash %q is not a valid git object id.\n", sanitizeForTerminal(hdr.Commit.Hash))
			return fmt.Errorf("invalid commit hash")
		}

		fmt.Printf("🔐 Commit metadata embedded in %s:\n", sanitizeForTerminal(filePath))
		fmt.Printf("   Commit:           %s\n", hdr.Commit.Hash)
		fmt.Printf("   Author:           %s\n", sanitizeForTerminal(hdr.Commit.Author))
		fmt.Printf("   Signer:           %s\n", sanitizeForTerminal(hdr.Commit.Signer))
		fmt.Printf("   Signer key:       %s\n", sanitizeForTerminal(hdr.Commit.SignerKey))
		fmt.Printf("   Signature status: %s\n", gitSignatureStatusDescription(sanitizeForTerminal(hdr.Commit.SignatureStatus)))
		fmt.Println("   Note: this metadata is recorded by whoever ran `lock` and is not signed by the vault.")
		fmt.Println("         The check below only shows the named commit exists here and is validly signed;")
		fmt.Println("         it does not prove the vault's contents came from that commit.")

		if !isGitRepository() {
			fmt.Println("⚠️  Current directory is not a git repository, cannot verify the embedded commit signature.")
			return fmt.Errorf("not a git repository")
		}

		found, err := gitCommitExists(hdr.Commit.Hash)
		if err != nil {
			return fmt.Errorf("checking git object: %w", err)
		}
		if !found {
			fmt.Printf("❌ Commit %s is not present in this repository.\n", hdr.Commit.Hash)
			return fmt.Errorf("commit not found")
		}

		output, err := verifyGitCommit(hdr.Commit.Hash)
		if err != nil {
			fmt.Println("❌ Commit signature verification failed:")
			fmt.Printf("   %s\n", sanitizeForTerminal(strings.TrimSpace(output)))
			return fmt.Errorf("commit signature verification failed")
		}

		fmt.Printf("✅ Commit signature for %s is valid and verified.\n", hdr.Commit.Hash)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCommitCmd)
}

func gitSignatureStatusDescription(status string) string {
	switch status {
	case "G":
		return "GOOD"
	case "U":
		return "GOOD, UNTRUSTED"
	case "B":
		return "BAD"
	case "X":
		return "EXPIRED"
	case "Y":
		return "EXPIRED, REVOKED"
	case "R":
		return "REVOKED"
	case "E":
		return "ERROR"
	case "N":
		return "NO SIGNATURE"
	default:
		return status
	}
}

func isGitRepository() bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}

	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

func gitCommitExists(hash string) (bool, error) {
	cmd := exec.Command("git", "cat-file", "-e", fmt.Sprintf("%s^{commit}", hash))
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func verifyGitCommit(hash string) (string, error) {
	cmd := exec.Command("git", "verify-commit", hash)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
