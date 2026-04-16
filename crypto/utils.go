package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

func DeriveKey(password, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, 32)
}

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

func readPassword(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())

	// If stdin isn't a terminal (e.g., piped), read it normally
	if !term.IsTerminal(fd) {
		var line string
		_, err := fmt.Fscanln(os.Stdin, &line)
		if err != nil && err.Error() != "unexpected newline" {
			return nil, err
		}
		return []byte(line), nil
	}

	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)

	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}

	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	return password, nil
}

func GetPassword(prompt string) ([]byte, error) {
	if envPass := os.Getenv("ENVVAULT_PASSWORD"); envPass != "" {
		return []byte(envPass), nil
	}
	return readPassword(prompt)
}
