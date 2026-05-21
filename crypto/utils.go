package crypto

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nbutton23/zxcvbn-go"
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

func CheckPasswordStrength(password []byte, allowWeak bool) error {
	result := zxcvbn.PasswordStrength(string(password), nil)

	// Score is 0-4. We require at least 3 (strong) by default.
	if result.Score < 3 {
		if allowWeak {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: Password is weak (score %d/4, crack time: %s). Proceeding anyway.\n",
				result.Score, result.CrackTimeDisplay)
			return nil
		}

		return fmt.Errorf(
			"password is too weak (score %d/4, crack time: %s). Use a longer passphrase or add complexity. Use --allow-weak to bypass",
			result.Score,
			result.CrackTimeDisplay,
		)
	}

	return nil
}

func GetPassword(prompt string) ([]byte, error) {
	if envPass := os.Getenv("ENVVAULT_PASSWORD"); envPass != "" {
		return []byte(envPass), nil
	}
	return readPassword(prompt)
}

func IsBeingTraced() (bool, error) {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) > 1 && fields[1] != "0" {
				return true, nil
			}
		}
	}
	return false, scanner.Err()
}
