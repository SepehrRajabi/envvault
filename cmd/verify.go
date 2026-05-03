package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [vault-file]",
	Short: "Verify the integrity and metadata of a vault file",
	Long:  "Checks if a vault file is structurally valid, has a supported algorithm, and isn't corrupted. Does not require a password.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		info, err := crypto.Verify(data)
		if err != nil {
			fmt.Printf("❌ Invalid vault: %v\n", err)
			return fmt.Errorf("verification failed")
		}

		fmt.Printf("✅ Valid vault\n")
		fmt.Printf("   Version:   %d\n", info.Version)
		fmt.Printf("   Algorithm: %s\n", info.Algorithm)
		fmt.Printf("   Checksum:  %s...\n", info.Checksum[:16])
		if info.Commit != nil {
			fmt.Printf("   Git commit: %s\n", info.Commit.Hash)
			fmt.Printf("   Commit signer: %s\n", info.Commit.Signer)
			fmt.Printf("   Signature: %s\n", info.Commit.SignatureStatus)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
