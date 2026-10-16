package cmd

import (
	"bytes"
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

		if err := enforceTrust(filePath, data); err != nil {
			return err
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
		vars, err := envfile.Parse(decrypted)
		if err != nil {
			return fmt.Errorf("parsing env file: %w", err)
		}

		// 5. Determine output destination
		// 6. Write clean KEY=VALUE format
		var buf bytes.Buffer
		for _, v := range vars {
			fmt.Fprintf(&buf, "%s=%s\n", v.Key, v.Value)
		}
		if dockerOutput != "" {
			if err := writeSecretFile(dockerOutput, buf.Bytes()); err != nil {
				return fmt.Errorf("writing output file: %w", err)
			}
		} else {
			os.Stdout.Write(buf.Bytes())
		}

		alg, _ := crypto.PeekAlgorithm(data)
		_ = history.Record("Docker", filePath, alg)
		return nil
	},
}

func init() {
	dockerCmd.Flags().StringVarP(&dockerOutput, "output", "o", "", "Write to a file instead of stdout")

	rootCmd.AddCommand(dockerCmd)
}
