package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const (
	// appVersion is the current envvault release version (major.minor.patch).
	appVersion = "0.0.3"

	// appVersionTag is an optional pre-release label appended to appVersion,
	// e.g. "beta" or "rc1". Leave it empty for a stable release.
	appVersionTag = "beta"
)

// fullVersion returns the human-readable version string, including
// appVersionTag when set (e.g. "0.0.3 beta"). Falls back to just
// appVersion for a stable release.
func fullVersion() string {
	return joinVersion(appVersion, appVersionTag)
}

func joinVersion(version, tag string) string {
	if tag == "" {
		return version
	}
	return version + " " + tag
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the envvault version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("envvault version %s\n", fullVersion())
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
