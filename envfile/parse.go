package envfile

import (
	"bufio"
	"fmt"
	"strings"
)

type EnvVar struct {
	Key     string
	Value   string
	Comment string
	Line    int
}

type ParseError struct {
	Line    int
	Message string
}

func (p *ParseError) Error() string {
	return "Parse error on line " + string(rune(p.Line)) + ": " + p.Message
}

func Parse(content string) ([]EnvVar, error) {
	var EnvVars []EnvVar
	lineNumber := 0

	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		lineNumber += 1
		line := scanner.Text()

		// Skip empty lines and comments
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// Split the line into key and value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, &ParseError{Line: lineNumber, Message: "Invalid format"}
		}
		EnvVars = append(EnvVars, EnvVar{
			Key:   strings.TrimSpace(parts[0]),
			Value: strings.TrimSpace(parts[1]),
		})
	}

	return EnvVars, scanner.Err()
}

func unqoute(value string) string {
	if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		return strings.Trim(value, "\"")
	}
	if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
		return strings.Trim(value, "'")
	}
	return value
}

func Diff(a, b []EnvVar) (added, removed []EnvVar, changed []struct{ Old, New EnvVar }) {
	mapA := make(map[string]EnvVar)
	mapB := make(map[string]EnvVar)

	for _, v := range a {
		mapA[v.Key] = v
	}
	for _, v := range b {
		mapB[v.Key] = v
	}

	// Removed: in a but not in b
	for _, v := range a {
		if _, ok := mapB[v.Key]; !ok {
			removed = append(removed, v)
		}
	}

	// Added: in b but not in a
	for _, v := range b {
		if _, ok := mapA[v.Key]; !ok {
			added = append(added, v)
		}
	}

	// Changed: in both but different values
	for _, v := range b {
		if old, ok := mapA[v.Key]; ok && old.Value != v.Value {
			changed = append(changed, struct{ Old, New EnvVar }{old, v})
		}
	}

	return
}

func FormatDiff(added, removed []EnvVar, changed []struct{ Old, New EnvVar }) string {
	var b strings.Builder

	for _, v := range removed {
		fmt.Fprintf(&b, "\033[31m- %s=%s\033[0m\n", v.Key, v.Value)
	}
	for _, v := range added {
		fmt.Fprintf(&b, "\033[32m+ %s=%s\033[0m\n", v.Key, v.Value)
	}
	for _, c := range changed {
		fmt.Fprintf(&b, "\033[31m- %s=%s\033[0m\n", c.Old.Key, c.Old.Value)
		fmt.Fprintf(&b, "\033[32m+ %s=%s\033[0m\n", c.New.Key, c.New.Value)
	}

	return b.String()
}
