package cmd

import (
	"fmt"

	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/spf13/cobra"
)

var checkStrict bool

var checkCmd = &cobra.Command{
	Use:   "check [schemafile] [envfile / vaultfile]",
	Short: "Check envfile against schema",
	Long:  "Check envfile or a vaultfile against a schema",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSchemaCheck(args[0], args[1], checkStrict)
	},
}

func runSchemaCheck(schemaFilePath, envFilePath string, strict bool) error {
	schema, err := envfile.ParseSchema(schemaFilePath)
	if err != nil {
		return fmt.Errorf("parsing schema: %w", err)
	}

	envVars, err := loadEnvVarsForSchema(envFilePath)
	if err != nil {
		return fmt.Errorf("loading envfile: %w", err)
	}

	errors := schema.ValidateWithOptions(envVars, envfile.ValidateOptions{Strict: strict})
	if len(errors) > 0 {
		fmt.Println("Validation errors:")
		for _, e := range errors {
			fmt.Printf("- %s\n", e)
		}
		return fmt.Errorf("schema validation failed")
	}

	fmt.Println("Envfile is valid according to the schema.")
	return nil
}

func init() {
	checkCmd.Flags().BoolVar(&checkStrict, "strict", false, "fail if the env file contains keys not defined in the schema")
	rootCmd.AddCommand(checkCmd)
}
