package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/spf13/cobra"
)

var (
	receiveImport string
	receiveOutput bool
)

var receiveCmd = &cobra.Command{
	Use:   "receive <evlt://...>",
	Short: "Decrypt a shared variable string",
	Long: `Decrypt variables that were shared with you using envvault share.

The shared string will be in the format: evlt://eyJhbGciOi...

You can:
- Display as shell exports: envvault receive <string>
- Import into .env file: envvault receive <string> --import .env.local
- Output for piping: envvault receive <string> --output | source /dev/stdin`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sharedString := args[0]

		// Decrypt the shared variables
		variables, err := crypto.DecodeShare(sharedString)
		if err != nil {
			return err
		}

		fmt.Printf("✅ Decrypted %d variable(s)\n\n", len(variables))

		if receiveImport != "" {
			// Import mode: merge into target file
			return importVariables(variables, receiveImport)
		}

		// Display mode: show as shell exports
		displayVariables(variables, receiveOutput)
		return nil
	},
}

func importVariables(variables map[string]string, targetFile string) error {
	var existingVars map[string]string

	// Read existing file if it exists
	if _, err := os.Stat(targetFile); err == nil {
		data, err := os.ReadFile(targetFile)
		if err != nil {
			return fmt.Errorf("reading %s: %w", targetFile, err)
		}

		parsedVars, err := envfile.Parse(string(data))
		if err != nil {
			return fmt.Errorf("parsing %s: %w", targetFile, err)
		}

		existingVars = make(map[string]string)
		for _, v := range parsedVars {
			existingVars[v.Key] = v.Value
		}
	} else {
		existingVars = make(map[string]string)
	}

	// Merge new variables (new vars override existing)
	var updated int
	var added int
	for key, value := range variables {
		if _, exists := existingVars[key]; exists {
			updated++
		} else {
			added++
		}
		existingVars[key] = value
	}

	// Write back to file
	content := formatEnvFile(existingVars)
	if err := os.WriteFile(targetFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", targetFile, err)
	}

	// Ensure directory exists
	dir := filepath.Dir(targetFile)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	fmt.Printf("📝 Imported into %s\n", targetFile)
	fmt.Printf("   Added: %d, Updated: %d\n", added, updated)

	return nil
}

func displayVariables(variables map[string]string, shellFormat bool) {
	// Sort keys for consistent output
	keys := make([]string, 0, len(variables))
	for k := range variables {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if shellFormat {
		// Shell export format
		for _, key := range keys {
			value := variables[key]
			// Escape single quotes in value
			escapedValue := strings.ReplaceAll(value, "'", "'\\''")
			fmt.Printf("export %s='%s'\n", key, escapedValue)
		}
	} else {
		// KEY=VALUE format
		fmt.Println("Variables:")
		for _, key := range keys {
			fmt.Printf("  %s=%s\n", key, variables[key])
		}
		fmt.Println()
		fmt.Println("To use as shell exports:")
		fmt.Println("  eval \"$(envvault receive '<evlt://...>' --output)\"")
		fmt.Println()
		fmt.Println("To import into .env file:")
		fmt.Println("  envvault receive '<evlt://...>' --import .env.local")
	}
}

func formatEnvFile(variables map[string]string) string {
	var lines []string

	// Sort keys for consistent output
	keys := make([]string, 0, len(variables))
	for k := range variables {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := variables[key]
		// Quote values if they contain spaces or special chars
		if strings.ContainsAny(value, " \t\n\"'\\") {
			value = `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
		}
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	}

	return strings.Join(lines, "\n") + "\n"
}

func init() {
	receiveCmd.Flags().StringVar(&receiveImport, "import", "", "Import variables into this file")
	receiveCmd.Flags().BoolVar(&receiveOutput, "output", false, "Output as shell export statements (for piping to source)")

	rootCmd.AddCommand(receiveCmd)
}
