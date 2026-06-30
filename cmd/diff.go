package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/spf13/cobra"
)

var (
	diffKeysOnly bool
	diffValues   bool
	diffRedacted bool
	diffJSON     bool
)

type diffChange struct {
	Key      string `json:"key"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

type diffEntry struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

type diffResult struct {
	File1   string       `json:"file1"`
	File2   string       `json:"file2"`
	Added   []diffEntry  `json:"added"`
	Removed []diffEntry  `json:"removed"`
	Changed []diffChange `json:"changed"`
	Counts  diffCounts   `json:"counts"`
}

type diffCounts struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Changed int `json:"changed"`
}

var diffCmd = &cobra.Command{
	Use:   "diff [file1] [file2]",
	Short: "Compare two .env or .env.vault files by key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if diffKeysOnly && diffValues {
			return fmt.Errorf("--keys-only and --values cannot be used together")
		}

		varsA, err := loadVarsForDiff(args[0])
		if err != nil {
			return err
		}
		varsB, err := loadVarsForDiff(args[1])
		if err != nil {
			return err
		}

		showValues := !diffKeysOnly && (diffValues || !diffRedacted)

		added, removed, changed := envfile.Diff(varsA, varsB)
		result := buildDiffResult(args[0], args[1], added, removed, changed, showValues)

		if diffJSON {
			encoded, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("encoding diff json: %w", err)
			}
			fmt.Println(string(encoded))
			return nil
		}

		output := formatDiffResult(result, diffFormatOptions{
			KeysOnly:   diffKeysOnly,
			ShowValues: showValues,
			Redacted:   diffRedacted,
		})
		if output == "" {
			fmt.Println("✅ No differences found")
			return nil
		}

		fmt.Printf("Comparing %s ↔ %s:\n\n", args[0], args[1])
		fmt.Print(output)
		fmt.Printf("\n%d added, %d removed, %d changed\n",
			result.Counts.Added, result.Counts.Removed, result.Counts.Changed)
		return nil
	},
}

func loadVarsForDiff(filePath string) ([]envfile.EnvVar, error) {
	doc, err := loadEnvDocument(filePath)
	if err != nil {
		return nil, err
	}
	defer doc.Close()

	vars, err := envfile.Parse(string(doc.Plaintext()))
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filePath, err)
	}
	return vars, nil
}

func buildDiffResult(
	file1, file2 string,
	added []envfile.EnvVar,
	removed []envfile.EnvVar,
	changed []struct{ Old, New envfile.EnvVar },
	includeValues bool,
) diffResult {
	result := diffResult{
		File1: file1,
		File2: file2,
		Counts: diffCounts{
			Added:   len(added),
			Removed: len(removed),
			Changed: len(changed),
		},
	}

	for _, item := range added {
		entry := diffEntry{Key: item.Key}
		if includeValues {
			entry.Value = item.Value
		}
		result.Added = append(result.Added, entry)
	}
	for _, item := range removed {
		entry := diffEntry{Key: item.Key}
		if includeValues {
			entry.Value = item.Value
		}
		result.Removed = append(result.Removed, entry)
	}
	for _, item := range changed {
		entry := diffChange{Key: item.Old.Key}
		if includeValues {
			entry.OldValue = item.Old.Value
			entry.NewValue = item.New.Value
		}
		result.Changed = append(result.Changed, entry)
	}

	return result
}

type diffFormatOptions struct {
	KeysOnly   bool
	ShowValues bool
	Redacted   bool
}

func formatDiffResult(result diffResult, opts diffFormatOptions) string {
	var b strings.Builder

	for _, item := range result.Removed {
		fmt.Fprintf(&b, "\033[31m- %s%s\033[0m\n", item.Key, formatDiffValue(item.Value, opts))
	}
	for _, item := range result.Added {
		fmt.Fprintf(&b, "\033[32m+ %s%s\033[0m\n", item.Key, formatDiffValue(item.Value, opts))
	}
	for _, item := range result.Changed {
		if opts.KeysOnly {
			fmt.Fprintf(&b, "\033[33m~ %s\033[0m\n", item.Key)
			continue
		}
		if opts.ShowValues {
			fmt.Fprintf(&b, "\033[31m- %s=%s\033[0m\n", item.Key, item.OldValue)
			fmt.Fprintf(&b, "\033[32m+ %s=%s\033[0m\n", item.Key, item.NewValue)
			continue
		}
		fmt.Fprintf(&b, "\033[33m~ %s=<redacted>\033[0m\n", item.Key)
	}

	return b.String()
}

func formatDiffValue(value string, opts diffFormatOptions) string {
	if opts.KeysOnly {
		return ""
	}
	if opts.ShowValues {
		return "=" + value
	}
	if opts.Redacted {
		return "=<redacted>"
	}
	return "=<redacted>"
}

func init() {
	diffCmd.Flags().BoolVar(&diffKeysOnly, "keys-only", false, "show only changed key names")
	diffCmd.Flags().BoolVar(&diffValues, "values", false, "show plaintext values in diff output")
	diffCmd.Flags().BoolVar(&diffRedacted, "redacted", true, "redact values in diff output")
	diffCmd.Flags().BoolVar(&diffJSON, "json", false, "output diff as JSON")

	rootCmd.AddCommand(diffCmd)
}
