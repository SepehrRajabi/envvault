// Package homedir resolves the current user's home directory consistently
// across platforms and test environments.
package homedir

import "os"

// Dir returns the current user's home directory. It prefers the HOME
// environment variable when set, then falls back to os.UserHomeDir().
// os.UserHomeDir() ignores HOME on Windows (it reads USERPROFILE
// instead), which breaks tests that isolate themselves with
// t.Setenv("HOME", ...); checking HOME first keeps that override working
// on every platform.
func Dir() (string, error) {
	if home := os.Getenv("HOME"); home != "" {
		return home, nil
	}
	return os.UserHomeDir()
}
