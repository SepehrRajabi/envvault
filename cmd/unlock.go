package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var (
	unlockOutput  string
	requestAccess bool
	quorumShare   string
)

var unlockCmd = &cobra.Command{
	Use:     "unlock [vault-file]",
	Short:   "Decrypt a .env.vault file back to .env",
	Aliases: []string{"decrypt"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// 1. Read the vault file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		if requestAccess {
			return unlockWithShamirQuorum(filePath, data)
		}

		// 2. Get credentials (handles password prompt OR age-pubkey automatically)
		password, err := getVaultCredentials(data, filePath)
		if err != nil {
			return err
		}

		// 3. Decrypt
		var p crypto.Provider
		if algorithm != "" {
			p, err = crypto.GetProvider(algorithm)
			if err != nil {
				return fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
			}
		}
		decrypted, err := crypto.Decrypt(data, password, p)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}

		// 4. Parse .env contents to validate structure
		if _, err := envfile.Parse(string(decrypted)); err != nil {
			return fmt.Errorf("parsing env file: %w", err)
		}

		// 5. Determine output path
		outPath := unlockOutput
		if outPath == "" {
			outPath = filePath
			// Strip .vault suffix if present
			if len(outPath) > 6 && outPath[len(outPath)-6:] == ".vault" {
				outPath = outPath[:len(outPath)-6]
			}
		}

		// 6. Write to disk with restricted permissions
		if err := os.WriteFile(outPath, decrypted, 0600); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}

		alg, _ := crypto.PeekAlgorithm(data)
		fmt.Printf("🔓 Decrypted %s → %s\n", filePath, outPath)
		_ = history.Record("Unlock", outPath, alg)

		return nil
	},
}

func init() {
	unlockCmd.Flags().StringVarP(&unlockOutput, "output", "o", "", "output file path")
	unlockCmd.Flags().BoolVar(&requestAccess, "request-access", false, "Request quorum approval for Shamir decryption and store submitted share until threshold is reached")
	unlockCmd.Flags().StringVar(&quorumShare, "share", "", "Shamir share to submit in request-access mode")

	rootCmd.AddCommand(unlockCmd)
}

func unlockWithShamirQuorum(filePath string, data []byte) error {
	alg, err := crypto.PeekAlgorithm(data)
	if err != nil {
		return err
	}
	if alg != "shamir-aes256gcm" {
		return fmt.Errorf("request-access is only supported for Shamir vaults")
	}

	threshold, err := crypto.DecodeShamirPayloadThreshold(data)
	if err != nil {
		return err
	}

	statePath, err := quorumStatePath(filePath)
	if err != nil {
		return err
	}

	fileHash := sha256Sum(data)
	state, err := loadQuorumState(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		state = &quorumState{
			VaultPath:   filePath,
			PayloadHash: fileHash,
			Threshold:   threshold,
			Shares:      nil,
		}
	}

	if state.PayloadHash != fileHash {
		return fmt.Errorf("quorum state file %s is stale or belongs to a different vault", statePath)
	}
	if state.Threshold == 0 {
		state.Threshold = threshold
	}
	if state.Threshold != threshold {
		return fmt.Errorf("existing quorum state threshold %d does not match vault threshold %d", state.Threshold, threshold)
	}

	if quorumShare == "" {
		shareBytes, err := crypto.GetPassword(fmt.Sprintf("Enter Shamir share to submit for %s: ", filepath.Base(filePath)))
		if err != nil {
			return err
		}
		quorumShare = strings.TrimSpace(string(shareBytes))
	}
	if quorumShare == "" {
		return fmt.Errorf("no Shamir share provided")
	}

	if !isValidBase64(quorumShare) {
		return fmt.Errorf("invalid Shamir share encoding")
	}

	if slices.Contains(state.Shares, quorumShare) {
		remaining := max(threshold-len(state.Shares), 0)
		fmt.Printf("✅ Share already submitted. Waiting for %d more share(s)...\n", remaining)
		return nil
	}

	state.Shares = append(state.Shares, quorumShare)

	if len(state.Shares) < threshold {
		if err := saveQuorumState(statePath, state); err != nil {
			return err
		}
		fmt.Printf("✅ Share recorded. Waiting for %d more share(s) to reach threshold.\n", threshold-len(state.Shares))
		return nil
	}

	// Enough shares have been collected.
	password := []byte(strings.Join(state.Shares[:threshold], ","))
	decrypted, err := crypto.Decrypt(data, password, nil)
	if err != nil {
		return fmt.Errorf("decryption failed after collecting quorum shares: %w", err)
	}

	if err := clearQuorumState(statePath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to remove quorum state file %s: %v\n", statePath, err)
	}

	if _, err := envfile.Parse(string(decrypted)); err != nil {
		return fmt.Errorf("parsing env file after quorum decryption: %w", err)
	}

	outPath := unlockOutput
	if outPath == "" {
		outPath = filePath
		if len(outPath) > 6 && outPath[len(outPath)-6:] == ".vault" {
			outPath = outPath[:len(outPath)-6]
		}
	}

	if err := os.WriteFile(outPath, decrypted, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}

	alg, _ = crypto.PeekAlgorithm(data)
	fmt.Printf("🔓 Decrypted %s → %s\n", filePath, outPath)
	_ = history.Record("Unlock", outPath, alg)
	return nil
}
