package envfile

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Rule struct {
	Key        string
	Required   bool
	Constrains []string
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
		rule := Rule{Key: key, Required: false, Constrains: []string{}}

		for _, token := range strings.FieldsFunc(after, func(r rune) bool {
			return r == ',' || r == ':'
		}) {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			if token == "required" {
				rule.Required = true
				continue
			}
			rule.Constrains = append(rule.Constrains, token)
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
		if exists && len(rule.Constrains) > 0 {
			typeToken := ""
			var extraTokens []string
			for _, c := range rule.Constrains {
				c = strings.ToLower(strings.TrimSpace(c))
				if c == "" {
					continue
				}
				switch c {
				case "string", "str", "number", "integer", "int", "unsigned", "uint", "float", "boolean", "bool":
					typeToken = c
				default:
					extraTokens = append(extraTokens, c)
				}
			}

			validType := false
			switch typeToken {
			case "string", "str":
				validType = validateString(value, extraTokens)
			case "number":
				validType = validateNumber(value, extraTokens)
			case "integer", "int":
				validType = validateInteger(value, extraTokens)
			case "unsigned", "uint":
				validType = validateUnsigned(value, extraTokens)
			case "float":
				validType = validateFloat(value, extraTokens)
			case "boolean", "bool":
				validType = validateBoolean(value)
			}

			if !validType {
				errors = append(errors, "Validation failed for key: "+rule.Key)
			}
		}
	}

	return errors
}

func validateString(value string, constraints []string) bool {
	if len(constraints) == 0 {
		return true
	}

	for _, c := range constraints {
		if after, ok := strings.CutPrefix(c, "len"); ok {
			bounds := after
			if bounds == "" {
				return true
			}

			parts := strings.SplitN(bounds, "-", 2)
			length := len(value)
			if len(parts) == 2 {
				min, errMin := strconv.Atoi(parts[0])
				max, errMax := strconv.Atoi(parts[1])
				if errMin != nil || errMax != nil {
					return false
				}
				return length >= min && length <= max
			}

			min, errMin := strconv.Atoi(parts[0])
			if errMin != nil {
				return false
			}
			return length >= min
		}
	}

	return true
}

func validateNumber(value string, constraints []string) bool {
	val, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}
	if len(constraints) == 0 {
		return true
	}
	return checkBounds(val, constraints)
}

func validateInteger(value string, constraints []string) bool {
	val, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return false
	}
	if len(constraints) == 0 {
		return true
	}
	return checkBounds(val, constraints)
}

func validateUnsigned(value string, constraints []string) bool {
	val, err := strconv.ParseUint(value, 10, 64)
	if err == nil {
		if len(constraints) == 0 {
			return true
		}
		return checkBounds(val, constraints)
	}

	if signed, err := strconv.Atoi(value); err == nil && signed >= 0 {
		if len(constraints) == 0 {
			return true
		}
		return checkBounds(signed, constraints)
	}

	return false
}

func validateFloat(value string, constraints []string) bool {
	val, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}
	if len(constraints) == 0 {
		return true
	}
	return checkBounds(val, constraints)
}

func validateBoolean(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "true" || value == "false" || value == "1" || value == "0"
}

type Number interface {
	int | int8 | int16 | int32 | int64 |
		uint | uint8 | uint16 | uint32 | uint64 |
		float32 | float64
}

func checkBounds[T Number](value T, boundsPattern []string) bool {
	if len(boundsPattern) == 0 {
		return true
	}

	if len(boundsPattern) == 2 {
		min, errMin := strconv.ParseFloat(strings.TrimSpace(boundsPattern[0]), 64)
		max, errMax := strconv.ParseFloat(strings.TrimSpace(boundsPattern[1]), 64)
		if errMin == nil && errMax == nil {
			return float64(value) >= min && float64(value) <= max
		}
		return false
	}

	if len(boundsPattern) == 1 {
		pattern := strings.TrimSpace(boundsPattern[0])
		if strings.Contains(pattern, "-") {
			parts := strings.SplitN(pattern, "-", 2)
			min, errMin := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			max, errMax := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if errMin == nil && errMax == nil {
				return float64(value) >= min && float64(value) <= max
			}
			return false
		}

		min, errMin := strconv.ParseFloat(pattern, 64)
		if errMin == nil {
			return float64(value) >= min
		}
	}

	return false
}
