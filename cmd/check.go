package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/spf13/cobra"
)

var schemaFilePath string

var checkCmd = &cobra.Command{
	Use:   "check [schemafile] [envfile / vaultfile]",
	Short: "Check envfile against schema",
	Long:  "Check envfile or a vaultfile against a schema",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		schemaFilePath = args[0]
		envFilePath := args[1]

		schema, err := envfile.ParseSchema(schemaFilePath)
		if err != nil {
			fmt.Printf("Error parsing schema: %v\n", err)
			return
		}

		// Loader function
		loadVars := func(filePath string) ([]envfile.EnvVar, error) {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", filePath, err)
			}

			// Detect if it's a vault file
			if isVaultFile(filePath, data) {
				password, err := getVaultCredentials(data, filePath)
				if err != nil {
					return nil, err
				}
				defer crypto.SecureWipe(password)

				// Try to decrypt
				var p crypto.Provider
				if algorithm != "" {
					var err error
					p, err = crypto.GetProvider(algorithm)
					if err != nil {
						return nil, fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
					}
				}
				lockedPlaintext, err := crypto.DecryptSecure(data, password, p)
				if err != nil {
					return nil, fmt.Errorf("decrypting failed for %s: %w", filePath, err)
				}
				defer lockedPlaintext.Unlock()

				return envfile.Parse(string(lockedPlaintext.Bytes()))
			}

			return envfile.Parse(string(data))
		}

		envVars, err := loadVars(envFilePath)
		if err != nil {
			fmt.Printf("Error loading envfile: %v\n", err)
			return
		}

		errors := schema.Validate(envVars)
		if len(errors) > 0 {
			fmt.Println("Validation errors:")
			for _, e := range errors {
				fmt.Printf("- %s\n", e)
			}
		} else {
			fmt.Println("Envfile is valid according to the schema.")
		}
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
