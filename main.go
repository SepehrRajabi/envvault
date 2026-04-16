package main

import (
	"github.com/SepehrRajabi/envvault/cmd"
	"github.com/SepehrRajabi/envvault/crypto"
)

func main() {
	crypto.SetDefault("aes256gcm-argon2id")
	cmd.Execute()
}
