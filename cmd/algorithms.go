package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/SepehrRajabi/envvault/crypto"
)

var algCmd = &cobra.Command{
	Use:   "algorithms",
	Short: "List available encryption algorithms",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("\n* = default")

		fmt.Println("Available algorithms:")
		for _, info := range crypto.ListProviders() {
			marker := " "
			if info.ID == crypto.Default().AlgorithmID() {
				marker = "*"
			}
			fmt.Printf("  %s %s\n", marker, info.ID)
		}
	},
}

func init() {
	rootCmd.AddCommand(algCmd)
}
