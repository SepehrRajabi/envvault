package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"text/template"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var (
	k8sName      string
	k8sNamespace string
	k8sType      string
	k8sOutput    string
)

var k8sCmd = &cobra.Command{
	Use:   "k8s [vault-file]",
	Short: "Generate a Kubernetes Secret YAML from an encrypted vault",
	Long:  "Decrypts a .env.vault file and outputs it as a Kubernetes Secret manifest. Supports ENVVAULT_PASSWORD and Age public keys for non-interactive use.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Read the vault file
		filePath := args[0]

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		// 2. Get credentials (handles password prompt OR age-pubkey automatically)
		password, err := getVaultCredentials(data, filePath)
		if err != nil {
			return err
		}
		defer crypto.SecureWipe(password)

		// 3. Decrypt to locked memory
		var p crypto.Provider
		if algorithm != "" {
			p, err = crypto.GetProvider(algorithm)
			if err != nil {
				return fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
			}
		}
		lockedPlaintext, err := crypto.DecryptSecure(data, password, p)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
		defer lockedPlaintext.Unlock()

		decrypted := lockedPlaintext.Bytes()

		// 4. Parse .env contents
		vars, err := envfile.Parse(string(decrypted))
		if err != nil {
			return fmt.Errorf("parsing env file: %w", err)
		}

		// 5. Base64 encode values for K8s 'data' field
		type secretEntry struct {
			Key   string
			Value string
		}

		var entries []secretEntry
		for _, v := range vars {
			entries = append(entries, secretEntry{
				Key:   v.Key,
				Value: base64.StdEncoding.EncodeToString([]byte(v.Value)),
			})
		}

		// 6. Prepare template data
		tmplData := struct {
			Name      string
			Namespace string
			Type      string
			Data      []secretEntry
		}{
			Name:      k8sName,
			Namespace: k8sNamespace,
			Type:      k8sType,
			Data:      entries,
		}

		// 7. Define and parse the YAML template
		const k8sTmpl = `apiVersion: v1
kind: Secret
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
type: {{.Type}}
data:
{{- range .Data }}
  {{.Key}}: {{.Value}}
{{- end }}
`

		t, err := template.New("secret").Parse(k8sTmpl)
		if err != nil {
			return fmt.Errorf("parsing template: %w", err)
		}

		// 8. Write output (file or stdout)
		var out *os.File
		if k8sOutput != "" {
			out, err = os.Create(k8sOutput)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer out.Close()
		} else {
			out = os.Stdout
		}

		if err := t.Execute(out, tmplData); err != nil {
			return fmt.Errorf("generating yaml: %w", err)
		}

		_ = history.Record("K8s", filePath, p.AlgorithmID())
		return nil
	},
}

func init() {
	k8sCmd.Flags().StringVarP(&k8sName, "name", "n", "my-app-secret", "Name of the Kubernetes Secret")
	k8sCmd.Flags().StringVarP(&k8sNamespace, "namespace", "s", "default", "Namespace of the Kubernetes Secret")
	k8sCmd.Flags().StringVarP(&k8sType, "type", "t", "Opaque", "Type of the Kubernetes Secret (e.g., Opaque, kubernetes.io/tls)")
	k8sCmd.Flags().StringVarP(&k8sOutput, "output", "o", "", "Output file path (defaults to stdout)")

	rootCmd.AddCommand(k8sCmd)
}
