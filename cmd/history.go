package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var (
	historyLimit int
	historyClear bool
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "View audit log of vault operations",
	Long:  "Displays a log of lock, unlock, and k8s operations performed on your vaults.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Handle --clear flag
		if historyClear {
			path, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			path = fmt.Sprintf("%s/.envvault/history.json", path)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("clearing history: %w", err)
			}
			fmt.Println("🗑️  History cleared.")
			return nil
		}

		// Get events
		events, err := history.List(historyLimit)
		if err != nil {
			return err
		}

		if len(events) == 0 {
			fmt.Println("No history found. Use some commands to create entries.")
			return nil
		}

		// Print formatted table
		fmt.Printf("%-20s %-8s %-8s %s\n", "TIMESTAMP", "ACTION", "ALGO", "FILE")
		fmt.Println(strings.Repeat("─", 70))

		for _, e := range events {
			actionIcon := "🔧"
			switch e.Action {
			case "Lock":
				actionIcon = "🔒"
			case "Unlock":
				actionIcon = "🔓"
			case "K8s":
				actionIcon = "☸️"
			case "Edit":
				actionIcon = "✏️"
			case "Rotate":
				actionIcon = "🔄"
			case "Docker":
				actionIcon = "🐳"
			case "Export":
				actionIcon = "📤"
			case "Run":
				actionIcon = "▶️"
			case "Login":
				actionIcon = "🔑"
			case "Logout":
				actionIcon = "🚪"
			}

			algo := "-"
			if e.Algorithm != "" {
				algo = e.Algorithm
			}

			// Format timestamp for readability
			ts := e.Timestamp.Format(time.RFC3339)

			// Truncate file path if too long
			file := e.File
			if len(file) > 40 {
				file = "..." + file[len(file)-37:]
			}

			fmt.Printf("%-20s %s %-6s %-8s %s\n", ts, actionIcon, e.Action, algo, file)
		}

		fmt.Printf("\nShowing %d most recent events (use --limit to change)\n", len(events))
		return nil
	},
}

func init() {
	historyCmd.Flags().IntVarP(&historyLimit, "limit", "l", 10, "Number of events to show")
	historyCmd.Flags().BoolVar(&historyClear, "clear", false, "Clear all history")
	rootCmd.AddCommand(historyCmd)
}
