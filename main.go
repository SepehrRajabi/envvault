package main

import (
	"os"

	"github.com/SepehrRajabi/envvault/cmd"
	"github.com/SepehrRajabi/envvault/crypto"
)

func main() {
	defaultProvider := os.Getenv("ENVVAULT_DEFAULT_PROVIDER")
	if defaultProvider == "" {
		defaultProvider = "aes256gcm-argon2id"
	}
	crypto.SetDefault(defaultProvider)

	cmd.Execute()
}
