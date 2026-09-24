package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

const (
	// appVersion is the current envvault release version (major.minor.patch).
	appVersion = "0.0.3"

	// appVersionTag is an optional pre-release label appended to appVersion,
	// e.g. "beta" or "rc1". Leave it empty for a stable release.
	appVersionTag = "beta"
)

// gitCommit is the commit hash the binary was built from. Release builds
// set it via -ldflags "-X github.com/SepehrRajabi/envvault/cmd.gitCommit=...";
// see .goreleaser.yaml. Left empty for `go run`/`go build` without ldflags,
// in which case commitHash() falls back to the module's embedded VCS info.
var gitCommit = ""

// commitHash returns the short commit hash the running binary was built
// from, or "unknown" if it can't be determined (e.g. `go run` from a
// working tree with VCS stamping disabled).
func commitHash() string {
	if gitCommit != "" {
		return gitCommit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				if len(s.Value) > 12 {
					return s.Value[:12]
				}
				return s.Value
			}
		}
	}
	return "unknown"
}

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
		fmt.Printf("envvault version %s (%s)\n", fullVersion(), commitHash())
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
