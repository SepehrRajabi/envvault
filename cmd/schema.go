package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/spf13/cobra"
)

const defaultSchemaTemplate = `# envvault schema
#
# Format:
# KEY = required, type, optional-constraints
#
# Types:
# - str / string
# - number
# - int / integer
# - uint / unsigned
# - float
# - bool / boolean
#
# Constraints:
# - len<N>          minimum string length, for example len8
# - len<N-M>        string length range, for example len8-64
# - min-max         numeric range, for example 1-65535
# - enum(a,b,c)     value must be one of the listed values
# - regex(pattern)  value must match a Go regular expression

DATABASE_URL = required, str, len8
PORT = required, uint, 1-65535
NODE_ENV = required, str, enum(development,staging,production)
DEBUG = bool
`

var (
	schemaOutputPath  string
	schemaForce       bool
	schemaOptional    bool
	schemaCheckStrict bool
)

var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Create and generate envvault schema files",
	Long:  "Create schema templates and generate .envschema files from existing .env or .env.vault files.",
}

var schemaInitCmd = &cobra.Command{
	Use:   "init [envfile / vaultfile]",
	Short: "Create a starter .envschema file",
	Long:  "Create a starter .envschema file, or infer one from an existing .env or .env.vault file when an input file is provided.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		output := schemaOutputPath
		if output == "" {
			output = ".envschema"
		}
		if err := ensureSchemaOutputWritable(output, schemaForce); err != nil {
			return err
		}

		content := defaultSchemaTemplate
		message := "Created schema template"
		if len(args) == 1 {
			envVars, err := loadEnvVarsForSchema(args[0])
			if err != nil {
				return err
			}
			content = envfile.GenerateSchema(envVars, !schemaOptional)
			message = "Generated schema"
		}

		if err := os.WriteFile(output, []byte(content), 0600); err != nil {
			return fmt.Errorf("writing schema file: %w", err)
		}
		fmt.Printf("%s: %s\n", message, output)
		return nil
	},
}

var schemaCheckCmd = &cobra.Command{
	Use:   "check [schemafile] [envfile / vaultfile]",
	Short: "Check envfile against schema",
	Long:  "Check envfile or a vaultfile against a schema. This is equivalent to the top-level check command.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSchemaCheck(args[0], args[1], schemaCheckStrict)
	},
}

var schemaGenerateCmd = &cobra.Command{
	Use:   "generate [envfile / vaultfile]",
	Short: "Generate a .envschema file from an existing env file or vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		envVars, err := loadEnvVarsForSchema(args[0])
		if err != nil {
			return err
		}

		output := schemaOutputPath
		if output == "" {
			output = ".envschema"
		}
		if err := ensureSchemaOutputWritable(output, schemaForce); err != nil {
			return err
		}

		content := envfile.GenerateSchema(envVars, !schemaOptional)
		if err := os.WriteFile(output, []byte(content), 0600); err != nil {
			return fmt.Errorf("writing schema file: %w", err)
		}
		fmt.Printf("Generated schema: %s\n", output)
		return nil
	},
}

func ensureSchemaOutputWritable(path string, force bool) error {
	if !envfile.IsSchemaPath(path) {
		return fmt.Errorf("schema output must use .envschema or .env.schema extension: %s", path)
	}
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("schema file already exists: %s (use --force to overwrite)", path)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("checking schema output: %w", err)
	}
	return nil
}

func loadEnvVarsForSchema(filePath string) ([]envfile.EnvVar, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filePath, err)
	}

	if !isVaultFile(filePath, data) {
		return envfile.Parse(string(data))
	}

	password, err := getVaultCredentials(data, filePath)
	if err != nil {
		return nil, err
	}
	defer crypto.SecureWipe(password)

	var provider crypto.Provider
	if algorithm != "" {
		provider, err = crypto.GetProvider(algorithm)
		if err != nil {
			return nil, fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
		}
	}

	lockedPlaintext, err := crypto.DecryptSecure(data, password, provider)
	if err != nil {
		return nil, fmt.Errorf("decrypting failed for %s: %w", filePath, err)
	}
	defer lockedPlaintext.Unlock()

	return envfile.Parse(string(lockedPlaintext.Bytes()))
}

func init() {
	schemaInitCmd.Flags().StringVarP(&schemaOutputPath, "output", "o", ".envschema", "schema file to write")
	schemaInitCmd.Flags().BoolVarP(&schemaForce, "force", "f", false, "overwrite an existing schema file")
	schemaInitCmd.Flags().BoolVar(&schemaOptional, "optional", false, "when an input file is provided, generate optional rules instead of marking each key as required")
	schemaInitCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "", "encryption algorithm override for vault input")

	schemaCheckCmd.Flags().BoolVar(&schemaCheckStrict, "strict", false, "fail if the env file contains keys not defined in the schema")

	schemaGenerateCmd.Flags().StringVarP(&schemaOutputPath, "output", "o", ".envschema", "schema file to write")
	schemaGenerateCmd.Flags().BoolVarP(&schemaForce, "force", "f", false, "overwrite an existing schema file")
	schemaGenerateCmd.Flags().BoolVar(&schemaOptional, "optional", false, "generate optional rules instead of marking each key as required")
	schemaGenerateCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "", "encryption algorithm override for vault input")

	schemaCmd.AddCommand(schemaInitCmd)
	schemaCmd.AddCommand(schemaCheckCmd)
	schemaCmd.AddCommand(schemaGenerateCmd)
	rootCmd.AddCommand(schemaCmd)
}
