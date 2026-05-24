package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var keysAddCmd = &cobra.Command{
	Use:   "add [vault-file] [name] [public-key]",
	Short: "Add a new recipient key to a vault file",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		name := args[1]
		pubKey := args[2]
		role, _ := cmd.Flags().GetString("role")

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		hdr, err := crypto.Verify(data)
		if err != nil {
			return fmt.Errorf("verifying %s: %w", filePath, err)
		}

		extraInfo := map[string]any{
			"name": name,
			"role": role,
		}

		if hdr.ProviderParams == nil {
			hdr.ProviderParams = make(map[string]any)
		}

		if hdr.ProviderParams["recipients"] == nil {
			hdr.ProviderParams["recipients"] = []any{}
		}
		hdr.ProviderParams["recipients"] = append(hdr.ProviderParams["recipients"].([]any), extraInfo)

		_ = history.Record("AddKey", filePath, hdr.Algorithm)
		fmt.Printf("Added key '%s' with public key: %s and role: %s\n", name, pubKey, role)
		return nil
	},
}

var keysRemoveCmd = &cobra.Command{
	Use:   "remove [vault-file] [name]",
	Short: "Remove a recipient key from a vault file",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		name := args[1]

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		hdr, err := crypto.Verify(data)
		if err != nil {
			return fmt.Errorf("verifying %s: %w", filePath, err)
		}

		params, ok := hdr.ProviderParams["recipients"].([]any)
		if !ok {
			return fmt.Errorf("no recipients found in %s", filePath)
		}

		var updatedRecipients []any
		for _, r := range params {
			rec, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if rec["name"] != name {
				updatedRecipients = append(updatedRecipients, rec)
			}
		}

		hdr.ProviderParams["recipients"] = updatedRecipients

		_ = history.Record("RemoveKey", filePath, hdr.Algorithm)
		fmt.Printf("Removed key: %s\n", name)
		return nil
	},
}

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage keys and recipients",
	Long:  `Manage encryption keys, recipients, and key-related operations.`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Help()
		return nil
	},
}

func init() {
	keysCmd.AddCommand(keysAddCmd)
	keysCmd.AddCommand(keysRemoveCmd)

	keysAddCmd.Flags().String("role", "", "Role for the key (optional)")

	rootCmd.AddCommand(keysCmd)
}
