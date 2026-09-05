package envfile

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"slices"
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

type ValidateOptions struct {
	Strict bool
}

func IsSchemaPath(filePath string) bool {
	return strings.HasSuffix(filePath, ".envschema") || strings.HasSuffix(filePath, ".env.schema")
}

func ParseSchema(filePath string) (*Schema, error) {
	if !IsSchemaPath(filePath) {
		return nil, fmt.Errorf("invalid schema file: %s", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []Rule
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		before, after, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("invalid schema line %d: %s", lineNumber, line)
		}
		key := strings.TrimSpace(before)
		if key == "" {
			return nil, fmt.Errorf("invalid schema line %d: key cannot be empty", lineNumber)
		}

		rule := Rule{Key: key, Required: false, Constrains: []string{}}
		for _, token := range splitSchemaTokens(after) {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			if strings.EqualFold(token, "required") {
				rule.Required = true
				continue
			}
			rule.Constrains = append(rule.Constrains, token)
		}

		rules = append(rules, rule)
	}

	return &Schema{Rules: rules}, scanner.Err()
}

func splitSchemaTokens(value string) []string {
	var tokens []string
	var current strings.Builder
	depth := 0

	for _, r := range value {
		switch r {
		case '(':
			depth++
			current.WriteRune(r)
		case ')':
			if depth > 0 {
				depth--
			}
			current.WriteRune(r)
		case ',', ':':
			if depth == 0 {
				tokens = append(tokens, current.String())
				current.Reset()
				continue
			}
			current.WriteRune(r)
		default:
			current.WriteRune(r)
		}
	}

	tokens = append(tokens, current.String())
	return tokens
}

func (s *Schema) Validate(envVars []EnvVar) []string {
	return s.ValidateWithOptions(envVars, ValidateOptions{})
}

func (s *Schema) ValidateWithOptions(envVars []EnvVar, opts ValidateOptions) []string {
	var errors []string
	envMap := make(map[string]string)
	ruleMap := make(map[string]Rule)

	for _, rule := range s.Rules {
		ruleMap[rule.Key] = rule
	}

	for _, envVar := range envVars {
		envMap[envVar.Key] = envVar.Value
		if opts.Strict {
			if _, ok := ruleMap[envVar.Key]; !ok {
				errors = append(errors, "Unknown key not allowed by schema: "+envVar.Key)
			}
		}
	}

	for _, rule := range s.Rules {
		value, exists := envMap[rule.Key]
		if rule.Required && !exists {
			errors = append(errors, "Missing required key: "+rule.Key)
			continue
		}
		if !exists {
			continue
		}

		for _, err := range validateRule(rule, unqoute(strings.TrimSpace(value))) {
			errors = append(errors, err)
		}
	}

	return errors
}

func validateRule(rule Rule, value string) []string {
	var errors []string
	var stringConstraints []string
	var numericConstraints []string
	var enumValues []string
	var regexPatterns []string
	typeToken := ""

	for _, constraint := range rule.Constrains {
		constraint = strings.TrimSpace(constraint)
		if constraint == "" {
			continue
		}

		lower := strings.ToLower(constraint)
		switch lower {
		case "string", "str", "number", "integer", "int", "unsigned", "uint", "float", "boolean", "bool":
			typeToken = lower
			continue
		}

		if strings.HasPrefix(lower, "len") {
			stringConstraints = append(stringConstraints, lower)
			continue
		}
		if values, ok := parseFunctionConstraint(constraint, "enum"); ok {
			enumValues = append(enumValues, splitEnumValues(values)...)
			continue
		}
		if pattern, ok := parseFunctionConstraint(constraint, "regex"); ok {
			regexPatterns = append(regexPatterns, pattern)
			continue
		}
		if isBoundsConstraint(constraint) {
			numericConstraints = append(numericConstraints, constraint)
			continue
		}

		errors = append(errors, fmt.Sprintf("Unsupported constraint for key %s: %s", rule.Key, constraint))
	}

	if typeToken != "" && !validateType(typeToken, value, stringConstraints, numericConstraints) {
		errors = append(errors, fmt.Sprintf("Validation failed for key %s: expected %s", rule.Key, typeToken))
	}

	if len(enumValues) > 0 && !validateEnum(value, enumValues) {
		errors = append(errors, fmt.Sprintf("Validation failed for key %s: value must be one of %s", rule.Key, strings.Join(enumValues, ", ")))
	}

	for _, pattern := range regexPatterns {
		matched, err := regexp.MatchString(pattern, value)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Invalid regex for key %s: %s", rule.Key, err))
			continue
		}
		if !matched {
			errors = append(errors, fmt.Sprintf("Validation failed for key %s: value does not match regex(%s)", rule.Key, pattern))
		}
	}

	return errors
}

func parseFunctionConstraint(token, name string) (string, bool) {
	prefix := strings.ToLower(name) + "("
	lower := strings.ToLower(token)
	if !strings.HasPrefix(lower, prefix) || !strings.HasSuffix(token, ")") {
		return "", false
	}
	return strings.TrimSpace(token[len(prefix) : len(token)-1]), true
}

func splitEnumValues(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = unqoute(strings.TrimSpace(part))
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func validateEnum(value string, allowed []string) bool {
	return slices.Contains(allowed, value)
}

func validateType(typeToken, value string, stringConstraints, numericConstraints []string) bool {
	switch typeToken {
	case "string", "str":
		return validateString(value, stringConstraints)
	case "number":
		return validateNumber(value, numericConstraints)
	case "integer", "int":
		return validateInteger(value, numericConstraints)
	case "unsigned", "uint":
		return validateUnsigned(value, numericConstraints)
	case "float":
		return validateFloat(value, numericConstraints)
	case "boolean", "bool":
		return validateBoolean(value)
	default:
		return true
	}
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
				if length < min || length > max {
					return false
				}
				continue
			}

			min, errMin := strconv.Atoi(parts[0])
			if errMin != nil {
				return false
			}
			if length < min {
				return false
			}
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

	for _, pattern := range boundsPattern {
		pattern = strings.TrimSpace(pattern)
		if strings.Contains(pattern, "-") {
			parts := strings.SplitN(pattern, "-", 2)
			min, errMin := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			max, errMax := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if errMin != nil || errMax != nil {
				return false
			}
			if float64(value) < min || float64(value) > max {
				return false
			}
			continue
		}

		min, errMin := strconv.ParseFloat(pattern, 64)
		if errMin != nil {
			return false
		}
		if float64(value) < min {
			return false
		}
	}

	return true
}

func isBoundsConstraint(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.Contains(value, "-") {
		parts := strings.SplitN(value, "-", 2)
		if len(parts) != 2 {
			return false
		}
		_, errMin := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		_, errMax := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		return errMin == nil && errMax == nil
	}
	_, err := strconv.ParseFloat(value, 64)
	return err == nil
}

func GenerateSchema(envVars []EnvVar, required bool) string {
	var b strings.Builder
	seen := make(map[string]bool)

	b.WriteString("# envvault schema\n")
	b.WriteString("# Supported tokens: required, str, number, int, uint, float, bool, len<N>, len<N-M>, min-max, enum(a,b), regex(pattern)\n\n")

	for _, envVar := range envVars {
		if seen[envVar.Key] {
			continue
		}
		seen[envVar.Key] = true

		constraints := []string{}
		if required {
			constraints = append(constraints, "required")
		}
		constraints = append(constraints, InferSchemaType(envVar.Value))
		fmt.Fprintf(&b, "%s = %s\n", envVar.Key, strings.Join(constraints, ", "))
	}

	return b.String()
}

func InferSchemaType(value string) string {
	value = unqoute(strings.TrimSpace(value))
	if value == "" {
		return "str"
	}
	if validateBoolean(value) {
		return "bool"
	}
	if _, err := strconv.ParseUint(value, 10, 64); err == nil {
		return "uint"
	}
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return "int"
	}
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return "float"
	}
	return "str"
}
