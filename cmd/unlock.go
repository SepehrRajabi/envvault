package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var unlockOutput string

var unlockCmd = &cobra.Command{
	Use:   "unlock [vault-file]",
	Short: "Decrypt a .env.vault file back to .env",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// 1. Read the vault file
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

		// 4. Determine output path
		outPath := unlockOutput
		if outPath == "" {
			outPath = filePath
			// Strip .vault suffix if present
			if len(outPath) > 6 && outPath[len(outPath)-6:] == ".vault" {
				outPath = outPath[:len(outPath)-6]
			}
		}

		// 5. Write to disk with restricted permissions
		if err := os.WriteFile(outPath, decrypted, 0600); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}

		alg, _ := crypto.PeekAlgorithm(data)
		fmt.Printf("🔓 Decrypted %s → %s\n", filePath, outPath)
		_ = history.Record("Unlock", outPath, alg)

		return nil
	},
}

func init() {
	unlockCmd.Flags().StringVarP(&unlockOutput, "output", "o", "", "output file path")

	unlockCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return []string{"vault"}, cobra.ShellCompDirectiveFilterFileExt
	}

	rootCmd.AddCommand(unlockCmd)
}
