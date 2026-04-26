package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var (
	algorithm       string
	listAlgs        bool
	allowWeak       bool
	allowInsecure   bool
	recipient       []string
	shamirShares    int
	shamirThreshold int
	shamirSharesDir string
)

var lockCmd = &cobra.Command{
	Use:   "lock [file]",
	Short: "Encrypt an .env file into a .env.vault file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		var password []byte

		// Mode 1: Public Key Encryption
		if len(recipient) > 0 {
			if algorithm != "" && algorithm != "age-pubkey" {
				return fmt.Errorf("cannot use --recipient with algorithm %s (must be age-pubkey)", algorithm)
			}
			algorithm = "age-pubkey"
			password = []byte(strings.Join(recipient, ","))
		} else {
			// Mode 2: Password Encryption
			password, err = crypto.GetPassword("Enter password: ")
			if err != nil {
				return err
			}

			confirm, err := crypto.GetPassword("Confirm password: ")
			if err != nil {
				return err
			}
			if string(password) != string(confirm) {
				return fmt.Errorf("passwords do not match")
			}

			if err := crypto.CheckPasswordStrength(password, allowWeak); err != nil {
				return err
			}
		}

		var p crypto.Provider
		if algorithm != "" {
			if algorithm == "shamir-aes256gcm" {
				if shamirThreshold < 2 {
					return fmt.Errorf("invalid --threshold %d (must be >= 2)", shamirThreshold)
				}
				if shamirShares < shamirThreshold {
					return fmt.Errorf("--shares (%d) must be >= --threshold (%d)", shamirShares, shamirThreshold)
				}
				p = &crypto.ShamirAESGCMProvider{
					ID:        "shamir-aes256gcm",
					Time:      3,
					Memory:    64 * 1024,
					Threads:   4,
					SaltLen:   32,
					NonceLen:  12,
					Shares:    shamirShares,
					Threshold: shamirThreshold,
				}
			} else {
				p, err = crypto.GetProvider(algorithm)
				if err != nil {
					return fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
				}
			}
		} else {
			p = crypto.Default()
		}

		if !allowInsecure {
			if !p.Description().Secure {
				return fmt.Errorf("selected algorithm, %s, is not secure (use --allow-insecure to override)", p.AlgorithmID())
			}
		} else {
			fmt.Printf("⚠️  Warning: --allow-insecure is set, allowing use of insecure algorithms (not recommended)")
			if p.Description().Secure {
				fmt.Printf("Selected algorithm, %s, is considered secure", p.AlgorithmID())
			} else {
				fmt.Printf("Selected algorithm, %s, is NOT considered secure", p.AlgorithmID())
			}
			fmt.Printf("Use envvault algorithms to see security ratings of available algorithms")
			fmt.Printf("⚠️  Warning: Using an insecure algorithm may put your secrets at risk of compromise")
			fmt.Printf("If you are unsure, use the default algorithm (no --algorithm flag) which is currently %s", crypto.Default().AlgorithmID())
			fmt.Printf("⚠️  Warning: --allow-insecure should only be used for testing or compatibility with legacy data, not for new vaults")
		}

		encrypted, err := crypto.Encrypt(data, password, p)
		if err != nil {
			return fmt.Errorf("encrypting: %w", err)
		}

		outPath := filePath + ".vault"
		if err := os.WriteFile(outPath, encrypted, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}

		algID := "aes256gcm-argon2id"
		if p != nil {
			algID = p.AlgorithmID()
		} else if def := crypto.Default(); def != nil {
			algID = def.AlgorithmID()
		}

		fmt.Printf("🔒 Encrypted %s → %s (%s)\n", filePath, outPath, algID)
		if shareProvider, ok := p.(crypto.ShareExporter); ok {
			shares := shareProvider.GeneratedShares()
			if len(shares) > 0 {
				fmt.Fprintln(os.Stderr, "Shamir shares (store separately, each with a different holder):")
				for i, s := range shares {
					fmt.Fprintf(os.Stderr, "  share %d: %s\n", i+1, s)
				}
				if shamirSharesDir != "" {
					base := strings.TrimSuffix(filepath.Base(outPath), filepath.Ext(outPath))
					paths, err := writeSharesToFiles(shamirSharesDir, base+"-share", shares)
					if err != nil {
						return err
					}
					fmt.Fprintf(os.Stderr, "Saved %d share files to %s\n", len(paths), shamirSharesDir)
				}
			}
		}
		_ = history.Record("Lock", outPath, algID)
		return nil
	},
}

func init() {
	lockCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "", "Encryption algorithm (see: envvault algorithms)")
	lockCmd.Flags().BoolVar(&listAlgs, "list-algorithms", false, "List available algorithms and exit")
	lockCmd.Flags().BoolVar(&allowWeak, "allow-weak", false, "Allow weak passwords (not recommended)")
	lockCmd.Flags().BoolVar(&allowInsecure, "allow-insecure", false, "Allow insecure algorithms (not recommended)")
	lockCmd.Flags().StringArrayVarP(&recipient, "recipient", "r", nil, "Age public key(s) (age1...) for public key encryption (can be specified multiple times)")
	lockCmd.Flags().IntVar(&shamirShares, "shares", 5, "Number of Shamir shares to generate (shamir-aes256gcm)")
	lockCmd.Flags().IntVar(&shamirThreshold, "threshold", 3, "Minimum shares required to decrypt (shamir-aes256gcm)")
	lockCmd.Flags().StringVar(&shamirSharesDir, "shares-dir", "", "Directory to write each generated Shamir share into its own file")

	rootCmd.AddCommand(lockCmd)
}
