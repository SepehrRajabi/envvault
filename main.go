package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/SepehrRajabi/envvault/cmd"
	"github.com/SepehrRajabi/envvault/crypto"
)

func main() {
	// Check if a debugger or tracer is attached, unless the user explicitly
	// enabled debug mode (DEBUG=1/true), which is meant to allow debugging.
	debugMode := strings.ToLower(os.Getenv("DEBUG"))
	debugEnabled := debugMode == "1" || debugMode == "true"
	if !debugEnabled {
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
			// An insecure default can't be selected through the environment,
			// DEBUG or not: it would silently weaken every command that
			// falls back to the default. Use `lock --allow-insecure -a ...`
			// per vault instead.
			fmt.Fprintf(os.Stderr, "Error: ENVVAULT_DEFAULT_PROVIDER=%q is not a secure algorithm and cannot be the default.\n", defaultProvider)
			os.Exit(1)
		}
		crypto.SetDefault(defaultProvider)
	}

	cmd.Execute()
}
