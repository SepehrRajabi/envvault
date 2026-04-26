package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [vaultfile] -- [command] [args...]",
	Short: "Run a command with decrypted environment variables injected in memory",
	Example: `  envvault run .env.vault -- node server.js
  envvault run .env.vault -- python main.py --port 8080
  envvault run .env.prod.vault -- docker-compose up`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		envFilePath := args[0]
		command := args[1]
		commandArgs := args[2:]

		// Loader function
		loadVars := func(filePath string) ([]envfile.EnvVar, error) {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", filePath, err)
			}

			// Detect if it's a vault file
			if isVaultFile(filePath, data) {
				password, err := crypto.GetPassword("Enter password for " + filePath + ": ")
				if err != nil {
					return nil, err
				}

				// Try to decrypt
				var p crypto.Provider
				if algorithm != "" {
					var err error
					p, err = crypto.GetProvider(algorithm)
					if err != nil {
						return nil, fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
					}
				}
				decrypted, err := crypto.Decrypt(data, password, p)
				if err != nil {
					return nil, fmt.Errorf("decrypting failed for %s: %w", filePath, err)
				}

				return envfile.Parse(string(decrypted))
			}
			return envfile.Parse(string(data))
		}

		envVars, err := loadVars(envFilePath)
		if err != nil {
			fmt.Printf("Error loading envfile: %v\n", err)
			return err
		}

		// 3. Inherit the current process's environment and merge with the new env vars
		finalEnv := os.Environ()
		envMap := make(map[string]string)
		for _, e := range finalEnv {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				envMap[parts[0]] = parts[1]
			}
		}

		// Apply the new env vars over the inherited ones
		for _, e := range envVars {
			envMap[e.Key] = e.Value
		}

		// Convert map back to slice for exec.Command
		var mergedEnv []string
		for k, v := range envMap {
			mergedEnv = append(mergedEnv, fmt.Sprintf("%s=%s", k, v))
		}

		// 4. Set up the command context and signal handling
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		execCmd := exec.CommandContext(ctx, command, commandArgs...)
		execCmd.Env = mergedEnv

		// Connect standard streams so the child process behaves like a native tool
		execCmd.Stdin = os.Stdin
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr

		// 5. Forward OS signals (Ctrl+C, etc.) to the child process
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigChan
			if execCmd.Process != nil {
				// Send the signal to the child process
				execCmd.Process.Signal(sig)
			}
		}()

		// 6. Start the process
		if err := execCmd.Start(); err != nil {
			return fmt.Errorf("failed to start command: %w", err)
		}

		// 7. Wait for the process to finish
		if err := execCmd.Wait(); err != nil {
			// If the command exited with a non-zero code, return that specific code
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("command failed: %w", err)
		}
		_ = history.Record("Run", envFilePath, algorithm)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
