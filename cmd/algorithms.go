package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/SepehrRajabi/envvault/crypto"
)

var (
	verboseAlgorithms    bool
	onlySecureAlgorithms bool
	jsonAlgorithms       bool
)

type algorithmJSONEntry struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Secure      bool   `json:"secure"`
	Default     bool   `json:"default"`
}

var algCmd = &cobra.Command{
	Use:   "algorithms",
	Short: "List available encryption algorithms",
	RunE: func(cmd *cobra.Command, args []string) error {
		providers := crypto.ListProviders(onlySecureAlgorithms)
		defaultID := ""
		if crypto.Default() != nil {
			defaultID = crypto.Default().AlgorithmID()
		}

		if jsonAlgorithms {
			entries := make([]algorithmJSONEntry, 0, len(providers))
			for _, info := range providers {
				entries = append(entries, algorithmJSONEntry{
					ID:          info.ID,
					Description: info.Description,
					Secure:      info.Secure,
					Default:     info.ID == defaultID,
				})
			}
			encoded, err := json.MarshalIndent(entries, "", "  ")
			if err != nil {
				return fmt.Errorf("encoding algorithms json: %w", err)
			}
			fmt.Println(string(encoded))
			return nil
		}

		if verboseAlgorithms {
			fmt.Println("Available algorithms:")
			for _, info := range providers {
				marker := " "
				if info.ID == defaultID {
					marker = "*"
				}
				security := "insecure"
				if info.Secure {
					security = "secure"
				}
				fmt.Printf("  %s %s (%s)\n", marker, info.ID, security)
				fmt.Printf("    %s\n", info.Description)
				fmt.Println()
			}
		} else {
			fmt.Println("\n* = default")

			fmt.Println("Available algorithms:")
			for _, info := range providers {
				marker := " "
				if info.ID == defaultID {
					marker = "*"
				}
				fmt.Printf("  %s %s\n", marker, info.ID)
			}
		}
		return nil
	},
}

func init() {
	algCmd.Flags().BoolVarP(&verboseAlgorithms, "verbose", "v", false, "Show detailed algorithm information")
	algCmd.Flags().BoolVarP(&onlySecureAlgorithms, "secure", "s", false, "Show only secure algorithms")
	algCmd.Flags().BoolVar(&jsonAlgorithms, "json", false, "Output algorithms as JSON")
	rootCmd.AddCommand(algCmd)
}
