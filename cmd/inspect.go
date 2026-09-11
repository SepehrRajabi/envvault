package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/spf13/cobra"
)

var jsonMetadata bool

type jsonMetadataOutput struct {
	File           string                    `json:"file"`
	Version        int                       `json:"version"`
	Algorithm      algorithmJSONEntry        `json:"algorithm"`
	Secure         string                    `json:"secure"`
	Authentication string                    `json:"auth_method"`
	Recipients     []string                  `json:"recipients,omitempty"`
	Checksum       string                    `json:"checksum"`
	Git            *crypto.GitCommitMetadata `json:"git,omitempty"`
}

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
			if jsonMetadata {
				return fmt.Errorf("invalid vault: %w", err)
			}
			fmt.Printf("❌ Invalid vault: %v\n", err)
			return fmt.Errorf("inspection failed")
		}

		provider, providerErr := crypto.GetProvider(hdr.Algorithm)
		secure := "unknown"
		algorithm := algorithmJSONEntry{ID: hdr.Algorithm}
		if providerErr == nil {
			description := provider.Description()
			if description.Secure {
				secure = "yes"
			} else {
				secure = "no"
			}

			defaultID := ""
			if crypto.Default() != nil {
				defaultID = crypto.Default().AlgorithmID()
			}
			algorithm = algorithmJSONEntry{
				ID:          description.ID,
				Description: description.Description,
				Secure:      description.Secure,
				Default:     description.ID == defaultID,
			}
		}

		authMethod := "password"
		switch hdr.Algorithm {
		case "age-pubkey":
			authMethod = "Age identity"
		case "shamir-aes256gcm":
			authMethod = "Shamir shares"
		}

		recipients := make([]string, 0)
		if len(hdr.ProviderParams) > 0 {
			if rawRecipients, ok := hdr.ProviderParams["recipients"].([]any); ok && len(rawRecipients) > 0 {
				for _, recipient := range rawRecipients {
					if str, ok := recipient.(string); ok {
						recipients = append(recipients, str)
					}
				}
			}
		}

		if jsonMetadata {
			metadata := jsonMetadataOutput{
				File:           filePath,
				Version:        int(hdr.Version),
				Algorithm:      algorithm,
				Secure:         secure,
				Authentication: authMethod,
				Recipients:     recipients,
				Checksum:       hdr.Checksum,
				Git:            hdr.Commit,
			}

			jsonData, err := json.MarshalIndent(metadata, "", "  ")
			if err != nil {
				return fmt.Errorf("encoding inspect json: %w", err)
			}
			fmt.Println(string(jsonData))
			return nil
		}

		fmt.Printf("🔍 Vault metadata for %s:\n", filePath)
		fmt.Printf("   Version:         %d\n", hdr.Version)
		fmt.Printf("   Algorithm:       %s\n", hdr.Algorithm)
		fmt.Printf("   Secure:          %s\n", secure)
		fmt.Printf("   Authentication:  %s\n", authMethod)
		fmt.Printf("   Checksum:        %s...\n", hdr.Checksum[:16])

		for _, recipient := range recipients {
			fmt.Printf("   Recipient:       %s\n", recipient)
		}

		if len(hdr.ProviderParams) > 0 && len(recipients) == 0 {
			fmt.Printf("   Provider params: %d\n", len(hdr.ProviderParams))
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
	inspectCmd.Flags().BoolVarP(&jsonMetadata, "json", "j", false, "output metadata as JSON")

	rootCmd.AddCommand(inspectCmd)
}
