package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/spf13/cobra"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect [vault-file]",
	Short: "Show metadata for a vault file",
	Long:  "Reads the vault envelope header and displays vault metadata without decrypting the contents.",
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
			return fmt.Errorf("inspection failed")
		}

		provider, err := crypto.GetProvider(hdr.Algorithm)
		secure := "unknown"
		if err == nil {
			if provider.Description().Secure {
				secure = "yes"
			} else {
				secure = "no"
			}
		}

		authMethod := "password"
		switch hdr.Algorithm {
		case "age-pubkey":
			authMethod = "Age identity"
		case "shamir-aes256gcm":
			authMethod = "Shamir shares"
		}

		fmt.Printf("🔍 Vault metadata for %s:\n", filePath)
		fmt.Printf("   Version:         %d\n", hdr.Version)
		fmt.Printf("   Algorithm:       %s\n", hdr.Algorithm)
		fmt.Printf("   Secure:          %s\n", secure)
		fmt.Printf("   Authentication:  %s\n", authMethod)
		fmt.Printf("   Checksum:        %s...\n", hdr.Checksum[:16])

		if len(hdr.ProviderParams) > 0 {
			if recipients, ok := hdr.ProviderParams["recipients"].([]any); ok && len(recipients) > 0 {
				fmt.Printf("   Recipients:\n")
				for _, recipient := range recipients {
					if str, ok := recipient.(string); ok {
						fmt.Printf("     - %s\n", str)
					}
				}
			} else {
				fmt.Printf("   Provider params: %d\n", len(hdr.ProviderParams))
			}
		}

		if hdr.Commit != nil {
			fmt.Printf("   Git commit:       %s\n", hdr.Commit.Hash)
			fmt.Printf("   Commit author:    %s\n", hdr.Commit.Author)
			fmt.Printf("   Commit signer:    %s\n", hdr.Commit.Signer)
			fmt.Printf("   Signer key:       %s\n", hdr.Commit.SignerKey)
			fmt.Printf("   Signature status: %s\n", hdr.Commit.SignatureStatus)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
