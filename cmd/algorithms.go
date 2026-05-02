package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/SepehrRajabi/envvault/crypto"
)

var verboseAlgorithms bool

var algCmd = &cobra.Command{
	Use:   "algorithms",
	Short: "List available encryption algorithms",
	Run: func(cmd *cobra.Command, args []string) {
		if verboseAlgorithms {
			fmt.Println("Available algorithms:")
			for _, info := range crypto.ListProviders() {
				marker := " "
				if info.ID == crypto.Default().AlgorithmID() {
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
			for _, info := range crypto.ListProviders() {
				marker := " "
				if info.ID == crypto.Default().AlgorithmID() {
					marker = "*"
				}
				fmt.Printf("  %s %s\n", marker, info.ID)
			}
		}
	},
}

func init() {
	algCmd.Flags().BoolVarP(&verboseAlgorithms, "verbose", "v", false, "Show detailed algorithm information")
	rootCmd.AddCommand(algCmd)
}
