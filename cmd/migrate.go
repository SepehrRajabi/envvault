package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var (
	from   string
	to     string
	output string

	migrateAllowInsecure bool
)

var migrateCmd = &cobra.Command{
	Use:   "migrate [vault-file]",
	Short: "Change the encryption algorithm of an existing vault file",
	Long:  "Migrate allows you to change the encryption algorithm of an existing vault file. ",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// 1. Read the vault file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		if err := enforceTrust(filePath, data); err != nil {
			return err
		}

		// 2. Get credentials (handles password prompt OR age-pubkey automatically)
		password, err := getVaultCredentials(data, filePath)
		if err != nil {
			return err
		}
		defer crypto.SecureWipe(password)

		// 3. Decrypt with old algorithm to locked memory
		var oldProvider crypto.Provider
		if from != "" {
			oldProvider, err = crypto.GetProvider(from)
			if err != nil {
				return fmt.Errorf("unknown old algorithm %q: %w", from, err)
			}
		}
		oldAlg, err := crypto.PeekAlgorithm(data)
		if err != nil {
			return err
		}
		if oldAlg == "age-pubkey" {
			return fmt.Errorf("%s uses public-key encryption; migrate only converts password-based vaults (re-lock it with `envvault lock` instead)", filePath)
		}
		lockedPlaintext, err := crypto.DecryptSecure(data, password, oldProvider)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
		defer lockedPlaintext.Unlock()

		decrypted := lockedPlaintext.Bytes()

		// 4. Encrypt with the new algorithm; with no --to, keep the vault's
		// current one rather than silently switching to the default.
		newAlg := to
		if newAlg == "" {
			newAlg = oldAlg
		}
		newProvider, err := crypto.GetProvider(newAlg)
		if err != nil {
			return fmt.Errorf("unknown new algorithm %q: %w", newAlg, err)
		}
		if newAlg != oldAlg {
			if err := requireSecureAlgorithm(newProvider, migrateAllowInsecure); err != nil {
				return err
			}
		}
		if newAlg == "age-pubkey" {
			return fmt.Errorf("cannot migrate to age-pubkey: it needs recipients; use `envvault lock -r` instead")
		}

		// A Shamir source's credential is a list of shares; the secret they
		// reconstruct is the original password.
		newSecret := password
		if oldAlg == "shamir-aes256gcm" {
			threshold, err := crypto.DecodeShamirPayloadThreshold(data)
			if err != nil {
				return err
			}
			newSecret, err = crypto.ShamirSecretFromShares(password, threshold)
			if err != nil {
				return err
			}
			defer crypto.SecureWipe(newSecret)
		}
		if newAlg == "shamir-aes256gcm" {
			newProvider = crypto.NewShamirProvider(5, 3)
		}
		encrypted, err := crypto.Encrypt(decrypted, newSecret, newProvider)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
		if exporter, ok := newProvider.(crypto.ShareExporter); ok {
			fmt.Fprintln(os.Stderr, "Shamir shares (store separately, each with a different holder):")
			for i, s := range exporter.GeneratedShares() {
				fmt.Fprintf(os.Stderr, "  share %d: %s\n", i+1, s)
			}
		}

		// 5. Write back to file
		outPath := filePath
		if output != "" {
			outPath = output
		}
		if err := atomicWrite(outPath, encrypted); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}

		// 6. Refresh the trust pin to match the migrated content (new
		// algorithm and possibly new path), otherwise the next
		// unlock/export/run would flag this legitimate change as a
		// substitution.
		if newHdr, err := crypto.Verify(encrypted); err == nil {
			record := crypto.TrustRecord{
				Algorithm:  newHdr.Algorithm,
				Recipients: crypto.RecipientsFromHeader(newHdr),
				Checksum:   crypto.HashVaultChecksum(encrypted),
			}
			if err := crypto.SetTrust(outPath, record); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Warning: failed to update trust pin for %s: %v\n", outPath, err)
			}
		}

		if output != "" {
			fmt.Printf("Successfully migrated %s to %s with new encryption algorithm\n", filePath, output)
		} else {
			fmt.Printf("Successfully migrated %s to new encryption algorithm\n", filePath)
		}

		_ = history.Record("Migrate", filePath, to)

		return nil
	},
}

func init() {
	migrateCmd.Flags().StringVar(&from, "from", "", "Current encryption algorithm (optional, will auto-detect if not provided)")
	migrateCmd.Flags().StringVar(&to, "to", "", "New encryption algorithm (optional, defaults to same as old)")
	migrateCmd.Flags().BoolVar(&migrateAllowInsecure, "allow-insecure", false, "Allow migrating to an insecure algorithm (not recommended)")
	migrateCmd.Flags().StringVar(&output, "output", "", "Output file for the migrated vault (optional)")

	rootCmd.AddCommand(migrateCmd)
}
