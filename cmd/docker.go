package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var dockerOutput string

var dockerCmd = &cobra.Command{
	Use:   "docker [vault-file]",
	Short: "Output decrypted secrets in Docker --env-file format",
	Long: "Decrypts a .env.vault file and outputs KEY=VALUE lines compatible with 'docker run --env-file'.\n" +
		"Supports ENVVAULT_PASSWORD and Age public keys for non-interactive use.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Read the vault file
		filePath := args[0]
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

		// 4. Parse .env contents
		vars, err := envfile.Parse(string(decrypted))
		if err != nil {
			return fmt.Errorf("parsing env file: %w", err)
		}

		// 5. Determine output destination
		var out *os.File
		if dockerOutput != "" {
			out, err = os.Create(dockerOutput)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer out.Close()
			// Restrict permissions since it contains raw secrets temporarily
			out.Chmod(0600)
		} else {
			out = os.Stdout
		}

		// 6. Write clean KEY=VALUE format
		for _, v := range vars {
			fmt.Fprintf(out, "%s=%s\n", v.Key, v.Value)
		}

		_ = history.Record("Docker", filePath, p.AlgorithmID())
		return nil
	},
}

func init() {
	dockerCmd.Flags().StringVarP(&dockerOutput, "output", "o", "", "Write to a file instead of stdout")

	rootCmd.AddCommand(dockerCmd)
}
