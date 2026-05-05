package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/SepehrRajabi/envvault/cmd"
	"github.com/SepehrRajabi/envvault/crypto"
)

func main() {
	debugMode := strings.ToLower(os.Getenv("DEBUG"))
	if debugMode == "0" || debugMode == "false" {
		if isDebugging, _ := crypto.IsBeingTraced(); isDebugging {
			fmt.Println("Security Error: Tracer detected. Exiting for safety.")
			os.Exit(1)
		}
	}

	defaultProvider := os.Getenv("ENVVAULT_DEFAULT_PROVIDER")
	if defaultProvider == "" {
		defaultProvider = "aes256gcm-argon2id"
	}
	crypto.SetDefault(defaultProvider)

	cmd.Execute()
}
