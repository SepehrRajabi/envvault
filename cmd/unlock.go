package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
)

var unlockedFileOutputPath string

var unlockCmd = &cobra.Command{
	Use:   "unlock [filePath]",
	Short: "Unlocks the .env file with the given password",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("Could not open the file at given path: %s", filePath)
		}

		password, err := crypto.GetPassword("Enter Password: ")
		if err != nil {
			return fmt.Errorf("Could not read password: %w", err)
		}

		confirm, err := crypto.GetPassword("Confirm Password: ")
		if err != nil {
			return fmt.Errorf("Could not read password confirmation: %w", err)
		}

		if string(password) != string(confirm) {
			return fmt.Errorf("Provided password and its confirmation do not match")
		}

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
			return fmt.Errorf("Could not decrypt the file with the given password, %w", err)
		}

		outPutPath := unlockedFileOutputPath
		if outPutPath == "" {
			outPutPath = filePath
			if len(outPutPath) > 6 && outPutPath[len(outPutPath)-6:] == ".vault" {
				outPutPath = outPutPath[:len(outPutPath)-6]
			}
		}

		if err := os.WriteFile(outPutPath, decrypted, 0600); err != nil {
			return fmt.Errorf("writing %s: %w", outPutPath, err)
		}

		_ = history.Record("Unlock", filePath, algorithm)

		fmt.Printf("🔒 Decrypted %s → %s (%s)\n", filePath, outPutPath, p.AlgorithmID())
		return nil
	},
}

func init() {
	unlockCmd.Flags().StringVarP(&unlockedFileOutputPath, "output", "o", "", "output file path")
	rootCmd.AddCommand(unlockCmd)
}
