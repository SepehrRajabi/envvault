package envfile

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Rule struct {
	Key      string
	Required bool
	Types    []string
}

type Schema struct {
	Rules []Rule
}

func ParseSchema(filePath string) (*Schema, error) {
	if !strings.HasSuffix(filePath, ".envschema") {
		return nil, fmt.Errorf("invalid schema file: %s", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []Rule
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		before, after, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("invalid schema line: %s", line)
		}
		key := strings.TrimSpace(before)
		after = strings.ToLower(strings.TrimSpace(after))
		types := []string{}
		if strings.Contains(after, ",") {
			types = strings.Split(strings.Split(after, ",")[1], ":")
		}

		rule := Rule{
			Key:      key,
			Required: after == "required", // TODO: change later to support multiple rules
			Types:    types,
		}

		rules = append(rules, rule)
	}

	return &Schema{Rules: rules}, scanner.Err()
}

func (s *Schema) Validate(envVars []EnvVar) []string {
	var errors []string
	envMap := make(map[string]string)

	for _, envVar := range envVars {
		envMap[envVar.Key] = envVar.Value
	}

	for _, rule := range s.Rules {
		value, exists := envMap[rule.Key]
		if rule.Required && !exists {
			errors = append(errors, "Missing required key: "+rule.Key)
			continue
		}
		if exists && len(rule.Types) > 0 {
			validType := false
			for _, t := range rule.Types {
				t = strings.ToLower(t)
				switch t {
				case "string", "str":
					validType = true
				case "number":
					if _, err := strconv.Atoi(value); err == nil {
						validType = true
					}
					if _, err := strconv.ParseFloat(value, 64); err == nil {
						validType = true
					}
					if _, err := strconv.ParseInt(value, 10, 64); err == nil {
						validType = true
					}
					if _, err := strconv.ParseUint(value, 10, 64); err == nil {
						validType = true
					}
				case "integer", "int":
					if _, err := strconv.Atoi(value); err == nil {
						validType = true
					}
					if _, err := strconv.ParseInt(value, 10, 64); err == nil {
						validType = true
					}
					if _, err := strconv.ParseUint(value, 10, 64); err == nil {
						validType = true
					}
				case "unsigned", "uint":
					if _, err := strconv.ParseUint(value, 10, 64); err == nil {
						validType = true
					}
					if _, err := strconv.Atoi(value); err == nil {
						if i, _ := strconv.Atoi(value); i >= 0 {
							validType = true
						}
					}
				case "float":
					if _, err := strconv.ParseFloat(value, 64); err == nil {
						validType = true
					}
				case "boolean", "bool":
					value = strings.ToLower(value)
					if value == "true" || value == "false" || value == "1" || value == "0" {
						validType = true
					}
				}
			}
			if !validType {
				errors = append(errors, "Invalid type for key: "+rule.Key)
			}
		}
	}

	return errors
}
