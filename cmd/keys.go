package cmd

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var keysAddCmd = &cobra.Command{
	Use:   "add [vault-file] [name] [public-key]",
	Short: "Add a new recipient to an age-pubkey vault and re-encrypt it",
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
		if hdr.Algorithm != "age-pubkey" {
			return fmt.Errorf("keys add only supports age-pubkey vaults (got %q); use envvault migrate to convert it first", hdr.Algorithm)
		}
		if err := enforceTrust(filePath, data); err != nil {
			return err
		}

		recipients := crypto.RecipientsFromHeader(hdr)
		if slices.Contains(recipients, pubKey) {
			return fmt.Errorf("%s is already a recipient of %s", pubKey, filePath)
		}
		recipients = append(recipients, pubKey)

		password, err := getVaultCredentials(data, filePath)
		if err != nil {
			return err
		}
		defer crypto.SecureWipe(password)

		lockedPlaintext, err := crypto.DecryptSecure(data, password, nil)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
		defer lockedPlaintext.Unlock()

		provider := &crypto.AgePubKeyProvider{ID: "age-pubkey"}
		encrypted, err := crypto.Encrypt(lockedPlaintext.Bytes(), []byte(strings.Join(recipients, ",")), provider)
		if err != nil {
			return fmt.Errorf("re-encrypting: %w", err)
		}
		if err := atomicWrite(filePath, encrypted); err != nil {
			return fmt.Errorf("writing %s: %w", filePath, err)
		}

		if err := crypto.SetTrust(filePath, crypto.TrustRecord{Algorithm: "age-pubkey", Recipients: recipients}); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: failed to update trust pin for %s: %v\n", filePath, err)
		}

		_ = history.Record("AddKey", filePath, hdr.Algorithm)
		if role != "" {
			fmt.Printf("Added recipient '%s' (role: %s) with public key %s to %s\n", name, role, pubKey, filePath)
		} else {
			fmt.Printf("Added recipient '%s' with public key %s to %s\n", name, pubKey, filePath)
		}
		return nil
	},
}

var keysRemoveCmd = &cobra.Command{
	Use:   "remove [vault-file] [public-key]",
	Short: "Remove a recipient from an age-pubkey vault and re-encrypt it",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		pubKey := args[1]

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		hdr, err := crypto.Verify(data)
		if err != nil {
			return fmt.Errorf("verifying %s: %w", filePath, err)
		}
		if hdr.Algorithm != "age-pubkey" {
			return fmt.Errorf("keys remove only supports age-pubkey vaults (got %q)", hdr.Algorithm)
		}
		if err := enforceTrust(filePath, data); err != nil {
			return err
		}

		recipients := crypto.RecipientsFromHeader(hdr)
		if len(recipients) == 0 {
			return fmt.Errorf("no recipients found in %s", filePath)
		}
		if !slices.Contains(recipients, pubKey) {
			return fmt.Errorf("%s is not a recipient of %s", pubKey, filePath)
		}
		remaining := slices.DeleteFunc(slices.Clone(recipients), func(r string) bool { return r == pubKey })
		if len(remaining) == 0 {
			return fmt.Errorf("refusing to remove the last recipient of %s (vault would become undecryptable)", filePath)
		}

		password, err := getVaultCredentials(data, filePath)
		if err != nil {
			return err
		}
		defer crypto.SecureWipe(password)

		lockedPlaintext, err := crypto.DecryptSecure(data, password, nil)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
		defer lockedPlaintext.Unlock()

		provider := &crypto.AgePubKeyProvider{ID: "age-pubkey"}
		encrypted, err := crypto.Encrypt(lockedPlaintext.Bytes(), []byte(strings.Join(remaining, ",")), provider)
		if err != nil {
			return fmt.Errorf("re-encrypting: %w", err)
		}
		if err := atomicWrite(filePath, encrypted); err != nil {
			return fmt.Errorf("writing %s: %w", filePath, err)
		}

		if err := crypto.SetTrust(filePath, crypto.TrustRecord{Algorithm: "age-pubkey", Recipients: remaining}); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: failed to update trust pin for %s: %v\n", filePath, err)
		}

		_ = history.Record("RemoveKey", filePath, hdr.Algorithm)
		fmt.Printf("Removed recipient %s from %s\n", pubKey, filePath)
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

	keysAddCmd.Flags().String("role", "", "Role for the key (optional, cosmetic only — not persisted in the vault)")

	rootCmd.AddCommand(keysCmd)
}
