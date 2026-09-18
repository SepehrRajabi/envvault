package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/spf13/cobra"
)

var (
	trustClear      bool
	trustShow       bool
	trustAlgorithm  string
	trustRecipients []string
)

var trustCmd = &cobra.Command{
	Use:   "trust [vault-file]",
	Short: "Pin a vault's expected algorithm/recipients to detect substitution",
	Long: `envvault records the algorithm (and, for public-key vaults, the recipient
set) a vault was locked with. unlock/export/run/share check a vault's actual
contents against this pin, so a vault file replaced on disk with content
encrypted differently — even content the victim's own key can decrypt — is
rejected instead of silently accepted.

'envvault lock' pins this automatically. Use this command to:
  - inspect the current pin:      envvault trust .env.vault --show
  - remove a pin:                 envvault trust .env.vault --clear
  - pre-register expected values
    (e.g. in CI, from a secret,
    before the vault file exists): envvault trust .env.vault --algorithm age-pubkey --recipient age1...
  - pin a vault you just verified
    by other means:               envvault trust .env.vault`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		if trustClear {
			if err := crypto.ClearTrust(filePath); err != nil {
				return err
			}
			fmt.Printf("🗑️  Cleared trust pin for %s\n", filePath)
			return nil
		}

		if trustShow {
			record, ok, err := crypto.GetTrust(filePath)
			if err != nil {
				return err
			}
			if !ok {
				fmt.Printf("No trust pin recorded for %s\n", filePath)
				return nil
			}
			fmt.Printf("Trust pin for %s:\n", filePath)
			fmt.Printf("  Algorithm:  %s\n", record.Algorithm)
			if len(record.Recipients) > 0 {
				fmt.Printf("  Recipients: %s\n", strings.Join(record.Recipients, ", "))
			}
			return nil
		}

		if trustAlgorithm != "" {
			// Pre-registering expected values, independent of any file on disk.
			record := crypto.TrustRecord{Algorithm: trustAlgorithm, Recipients: trustRecipients}
			if err := crypto.SetTrust(filePath, record); err != nil {
				return err
			}
			fmt.Printf("📌 Pinned expected algorithm %q for %s\n", trustAlgorithm, filePath)
			return nil
		}

		// Default: pin whatever the vault currently contains, after verifying
		// its structure. This is an explicit trust decision by the operator —
		// use it only after confirming the vault's contents by other means.
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		hdr, err := crypto.Verify(data)
		if err != nil {
			return fmt.Errorf("verifying %s: %w", filePath, err)
		}

		record := crypto.TrustRecord{
			Algorithm:  hdr.Algorithm,
			Recipients: crypto.RecipientsFromHeader(hdr),
		}
		if err := crypto.SetTrust(filePath, record); err != nil {
			return err
		}

		fmt.Printf("📌 Pinned %s as trusted (algorithm: %s", filePath, record.Algorithm)
		if len(record.Recipients) > 0 {
			fmt.Printf(", recipients: %s", strings.Join(record.Recipients, ", "))
		}
		fmt.Println(")")

		return nil
	},
}

func init() {
	trustCmd.Flags().BoolVar(&trustClear, "clear", false, "Remove the trust pin for this vault path")
	trustCmd.Flags().BoolVar(&trustShow, "show", false, "Show the trust pin for this vault path")
	trustCmd.Flags().StringVar(&trustAlgorithm, "algorithm", "", "Pre-register an expected algorithm (e.g. for CI, before the vault exists)")
	trustCmd.Flags().StringArrayVar(&trustRecipients, "recipient", nil, "Pre-register an expected recipient public key (repeatable, use with --algorithm)")

	rootCmd.AddCommand(trustCmd)
}
