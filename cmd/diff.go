package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff [file1] [file2]",
	Short: "Compare two .env files by key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}

		varsA, err := envfile.Parse(string(a))
		if err != nil {
			return err
		}
		varsB, err := envfile.Parse(string(b))
		if err != nil {
			return err
		}

		added, removed, changed := envfile.Diff(varsA, varsB)
		output := envfile.FormatDiff(added, removed, changed)

		if output == "" {
			fmt.Println("✅ No differences found")
			return nil
		}

		fmt.Printf("Comparing %s ↔ %s:\n\n", args[0], args[1])
		fmt.Print(output)

		fmt.Printf("\n%d added, %d removed, %d changed\n",
			len(added), len(removed), len(changed))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(diffCmd)
}
