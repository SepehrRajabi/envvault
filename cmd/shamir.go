package cmd

import (
	"fmt"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/spf13/cobra"
)

var (
	shamirSplitShares    int
	shamirSplitThreshold int
	shamirSplitOutDir    string
)

var shamirCmd = &cobra.Command{
	Use:   "shamir",
	Short: "Work with Shamir secret shares",
	Long:  "Utilities for splitting and combining secrets with Shamir Secret Sharing.",
}

var shamirSplitCmd = &cobra.Command{
	Use:   "split [secret]",
	Short: "Split a secret into Shamir shares",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		secret := []byte(args[0])
		shares, err := crypto.SplitSecretToBase64(secret, shamirSplitShares, shamirSplitThreshold)
		if err != nil {
			return err
		}

		fmt.Printf("Generated %d shares (threshold %d):\n", len(shares), shamirSplitThreshold)
		for i, s := range shares {
			fmt.Printf("  share %d: %s\n", i+1, s)
		}
		if shamirSplitOutDir != "" {
			paths, err := writeSharesToFiles(shamirSplitOutDir, "shamir-share", shares)
			if err != nil {
				return err
			}
			fmt.Printf("Saved %d share files to %s\n", len(paths), shamirSplitOutDir)
		}
		return nil
	},
}

var shamirCombineCmd = &cobra.Command{
	Use:   "combine [share1] [share2] ...",
	Short: "Combine Shamir shares and recover the secret",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		parts := make([]string, 0, len(args))
		for _, arg := range args {
			for _, p := range strings.Split(arg, ",") {
				trimmed := strings.TrimSpace(p)
				if trimmed != "" {
					parts = append(parts, trimmed)
				}
			}
		}

		secret, err := crypto.CombineSecretFromBase64(parts)
		if err != nil {
			return err
		}
		fmt.Println(string(secret))
		return nil
	},
}

func init() {
	shamirSplitCmd.Flags().IntVar(&shamirSplitShares, "shares", 5, "Number of shares to generate")
	shamirSplitCmd.Flags().IntVar(&shamirSplitThreshold, "threshold", 3, "Minimum shares required to reconstruct")
	shamirSplitCmd.Flags().StringVar(&shamirSplitOutDir, "out-dir", "", "Directory to write each generated share into its own file")

	shamirCmd.AddCommand(shamirSplitCmd)
	shamirCmd.AddCommand(shamirCombineCmd)
	rootCmd.AddCommand(shamirCmd)
}
