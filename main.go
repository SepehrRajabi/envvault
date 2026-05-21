package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/SepehrRajabi/envvault/cmd"
	"github.com/SepehrRajabi/envvault/crypto"
)

func main() {
	// Check if a debuger or tracer is attached, but only if DEBUG is not explicitly disabled.
	debugMode := strings.ToLower(os.Getenv("DEBUG"))
	if debugMode == "0" || debugMode == "false" {
		if isDebugging, _ := crypto.IsBeingTraced(); isDebugging {
			fmt.Println("Security Error: Tracer detected. Exiting for safety.")
			os.Exit(1)
		}
	}

	// Load the default provider from environment variable or use a secure default.
	defaultProvider := os.Getenv("ENVVAULT_DEFAULT_PROVIDER")
	if defaultProvider == "" {
		defaultProvider = "aes256gcm-argon2id"
	}
	if p, err := crypto.GetProvider(defaultProvider); err == nil {
		if !p.Description().Secure {
			if debugMode == "1" || debugMode == "true" {
				fmt.Printf("⚠️ Warning: The default provider %q is not secure. Consider switching to a more secure provider.\n", defaultProvider)
			} else {
				fmt.Printf("⚠️ Warning: The default provider %q is not secure. Set DEBUG=1 for more details.\n", defaultProvider)
				os.Exit(1)
			}
		}
		crypto.SetDefault(defaultProvider)
	}

	cmd.Execute()
}
