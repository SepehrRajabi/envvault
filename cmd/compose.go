package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var (
	composeService string
	composeImage   string
	composeOutput  string
)

var composeCmd = &cobra.Command{
	Use:   "compose [envfile / vaultfile]",
	Short: "Generate a Docker Compose service snippet with environment variables",
	Long: "Loads a plain .env file or decrypts a .env.vault file and outputs a Docker Compose YAML service snippet. " +
		"Secrets are written into the generated YAML under services.<service>.environment.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		doc, err := loadEnvDocument(filePath)
		if err != nil {
			return err
		}
		defer doc.Close()

		vars, err := envfile.Parse(string(doc.Plaintext()))
		if err != nil {
			return fmt.Errorf("parsing env file: %w", err)
		}

		content := formatComposeYAML(composeService, composeImage, vars)
		if composeOutput == "" {
			fmt.Print(content)
		} else {
			if err := os.WriteFile(composeOutput, []byte(content), 0600); err != nil {
				return fmt.Errorf("writing %s: %w", composeOutput, err)
			}
			fmt.Fprintf(os.Stderr, "Wrote Docker Compose snippet to %s\n", composeOutput)
		}

		_ = history.Record("Compose", filePath, doc.Algorithm)
		return nil
	},
}

func formatComposeYAML(serviceName, image string, vars []envfile.EnvVar) string {
	if strings.TrimSpace(serviceName) == "" {
		serviceName = "app"
	}

	var b strings.Builder
	b.WriteString("services:\n")
	fmt.Fprintf(&b, "  %s:\n", yamlKey(serviceName))
	if strings.TrimSpace(image) != "" {
		fmt.Fprintf(&b, "    image: %s\n", yamlScalar(image))
	}
	b.WriteString("    environment:\n")
	for _, envVar := range vars {
		fmt.Fprintf(&b, "      %s: %s\n", yamlKey(envVar.Key), yamlScalar(envVar.Value))
	}
	return b.String()
}

func yamlKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return `""`
	}
	for _, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return yamlScalar(value)
		}
	}
	return value
}

func yamlScalar(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return `""`
	}

	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, "\n", `\n`)
	return `"` + escaped + `"`
}

func init() {
	composeCmd.Flags().StringVarP(&composeService, "service", "s", "app", "Docker Compose service name")
	composeCmd.Flags().StringVarP(&composeImage, "image", "i", "", "Optional image to include in the generated service")
	composeCmd.Flags().StringVarP(&composeOutput, "output", "o", "", "Write YAML to a file instead of stdout")

	rootCmd.AddCommand(composeCmd)
}
