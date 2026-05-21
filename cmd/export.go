package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export [vault-file]",
	Short: "Export environment variables from a vault file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// 1. Read the vault file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		// 2. Get credentials (handles password prompt OR age-pubkey automatically)
		password, err := getVaultCredentials(data, filePath)
		if err != nil {
			return err
		}
		defer crypto.SecureWipe(password)

		// 3. Decrypt to locked memory
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

		// 4. Parse .env contents to validate structure
		if _, err := envfile.Parse(string(decrypted)); err != nil {
			return fmt.Errorf("parsing env file: %w", err)
		}

		// 5, Output to env variables
		var out strings.Builder
		lines := strings.SplitSeq(string(decrypted), "\n")
		for line := range lines {
			fmt.Fprintf(&out, "%s\n", strings.TrimSpace(line))
		}
		fmt.Printf("%s", out.String())

		alg, _ := crypto.PeekAlgorithm(data)
		// Print to std.Stderr so it does not interfere with the export command output
		fmt.Fprintf(os.Stderr, "🔓 Exported %s \n", filePath)
		_ = history.Record("Export", "$ENV", alg)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(exportCmd)
}
