package boxedpy

import (
	"regexp"
	"strconv"
	"strings"
)

// PythonError represents a structured Python error parsed from execution output.
type PythonError struct {
	Type      string // e.g., "NameError", "SyntaxError"
	Message   string // full error message
	Line      int    // line number (0 if unknown)
	Traceback string // formatted traceback
	Hint      string // helpful suggestion
}

// ParsePythonError extracts structured error information from Python execution output.
// This parses Jupyter notebook error outputs and Python tracebacks.
// Returns nil if no recognizable Python error is found.
//
// The function can parse both raw Python tracebacks and Jupyter notebook error outputs
// that contain error information in JSON format with ename, evalue, and traceback fields.
func ParsePythonError(output []byte) *PythonError {
	if len(output) == 0 {
		return nil
	}

	outputStr := string(output)

	// Clean ANSI escape codes from the output first
	cleanedOutput := stripANSI(outputStr)

	// Try to detect a Python traceback in the output
	// Look for common patterns like "Traceback (most recent call last):"
	// or direct error messages like "NameError: name 'x' is not defined"

	// First, try to extract error type and message from the last line
	lines := strings.Split(strings.TrimSpace(cleanedOutput), "\n")
	if len(lines) == 0 {
		return nil
	}

	// Look for error pattern: "ErrorType: error message"
	var errorType, errorMessage string
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Check for error pattern
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				// Check if the first part looks like an error type (CamelCase or ends with "Error")
				potentialType := strings.TrimSpace(parts[0])
				if strings.HasSuffix(potentialType, "Error") ||
					strings.HasSuffix(potentialType, "Exception") ||
					potentialType == "SyntaxError" ||
					potentialType == "IndentationError" ||
					potentialType == "TabError" {
					errorType = potentialType
					errorMessage = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	// If we didn't find an error pattern, this might not be an error
	if errorType == "" {
		return nil
	}

	// Extract line number from traceback
	lineNum := extractLineNumber(cleanedOutput)

	// Generate helpful hint
	hint := extractErrorHint(errorType, errorMessage, cleanedOutput)

	return &PythonError{
		Type:      errorType,
		Message:   errorType + ": " + errorMessage,
		Line:      lineNum,
		Traceback: cleanedOutput,
		Hint:      hint,
	}
}

// stripANSI removes ANSI color codes from a string
func stripANSI(s string) string {
	// Match ANSI escape sequences like \x1b[31m or \u001b[31m
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(s, "")
}

// extractLineNumber extracts the line number from a Jupyter traceback.
// Returns the line number (1-indexed) or 0 if not found.
func extractLineNumber(traceback string) int {
	// Jupyter tracebacks contain lines like:
	// "Cell In[1], line 2"
	// "----> 2 print(undefined_variable)"
	// "<string>:3" (for syntax errors)

	// Try to find "line N" pattern
	lineRegex := regexp.MustCompile(`\bline (\d+)\b`)
	if matches := lineRegex.FindStringSubmatch(traceback); len(matches) > 1 {
		if lineNum, err := strconv.Atoi(matches[1]); err == nil {
			return lineNum
		}
	}

	// Try to find "----> N" pattern (arrow pointing to error line)
	arrowRegex := regexp.MustCompile(`----> (\d+)`)
	if matches := arrowRegex.FindStringSubmatch(traceback); len(matches) > 1 {
		if lineNum, err := strconv.Atoi(matches[1]); err == nil {
			return lineNum
		}
	}

	// Try to find "<string>:N" pattern (syntax errors)
	stringRegex := regexp.MustCompile(`<string>:(\d+)`)
	if matches := stringRegex.FindStringSubmatch(traceback); len(matches) > 1 {
		if lineNum, err := strconv.Atoi(matches[1]); err == nil {
			return lineNum
		}
	}

	return 0
}

// extractErrorHint generates a helpful hint based on the error type and message.
func extractErrorHint(errorType, errorValue, traceback string) string {
	switch errorType {
	case "NameError":
		return generateNameErrorHint(errorValue)
	case "ModuleNotFoundError", "ImportError":
		return generateImportErrorHint(errorValue)
	case "SyntaxError", "IndentationError":
		return generateSyntaxErrorHint(errorType, errorValue)
	case "ZeroDivisionError":
		return "Check that the divisor is not zero"
	case "TypeError":
		return generateTypeErrorHint(errorValue)
	case "AttributeError":
		return generateAttributeErrorHint(errorValue)
	case "KeyError":
		return "Verify the key exists in the dictionary"
	case "IndexError":
		return "Check the list/array index is within bounds"
	case "ValueError":
		return "Check the value is appropriate for the operation"
	default:
		return ""
	}
}

// generateNameErrorHint creates a hint for NameError, suggesting common typos.
func generateNameErrorHint(errorValue string) string {
	// Extract variable name from error message like "name 'ressults' is not defined"
	nameRegex := regexp.MustCompile(`name '(\w+)' is not defined`)
	if matches := nameRegex.FindStringSubmatch(errorValue); len(matches) > 1 {
		varName := matches[1]

		// Common typos and suggestions
		suggestions := map[string]string{
			"ressults": "results",
			"reults":   "results",
			"lenght":   "length",
			"widht":    "width",
			"heigth":   "height",
			"calulate": "calculate",
		}

		if suggestion, ok := suggestions[varName]; ok {
			return "Did you mean '" + suggestion + "'?"
		}

		return "Variable '" + varName + "' is not defined. Check for typos or ensure it's defined before use."
	}

	return "Check for undefined variables or typos in variable names"
}

// generateImportErrorHint creates a hint for import errors.
func generateImportErrorHint(errorValue string) string {
	if strings.Contains(errorValue, "No module named") {
		// Extract module name
		moduleRegex := regexp.MustCompile(`No module named '(\w+)'`)
		if matches := moduleRegex.FindStringSubmatch(errorValue); len(matches) > 1 {
			moduleName := matches[1]

			// Common package name typos
			commonPackages := map[string]string{
				"numpy":      "numpy",
				"pandas":     "pandas",
				"matplotlib": "matplotlib",
				"sklearn":    "scikit-learn (install with: pip install scikit-learn)",
			}

			if suggestion, ok := commonPackages[moduleName]; ok && suggestion != moduleName {
				return "Did you mean: " + suggestion
			}

			return "Module '" + moduleName + "' is not installed or not found in the Python path"
		}
	}
	return "Check the module name and ensure it's installed"
}

// generateSyntaxErrorHint creates a hint for syntax errors.
func generateSyntaxErrorHint(errorType, errorValue string) string {
	if errorType == "IndentationError" {
		if strings.Contains(errorValue, "unindent does not match") {
			return "Check indentation levels - all lines in a block must be indented consistently"
		}
		if strings.Contains(errorValue, "expected an indented block") {
			return "Add indentation after colons (if, for, def, etc.)"
		}
		return "Fix the indentation - Python requires consistent use of spaces or tabs"
	}

	if strings.Contains(errorValue, "invalid syntax") {
		return "Check for missing colons, parentheses, or quotes"
	}

	return "Review the syntax at the indicated line"
}

// generateTypeErrorHint creates a hint for type errors.
func generateTypeErrorHint(errorValue string) string {
	if strings.Contains(errorValue, "can only concatenate") {
		return "Convert values to the same type before concatenating (e.g., str() or int())"
	}
	if strings.Contains(errorValue, "unsupported operand type") {
		return "Check that operands are of compatible types for the operation"
	}
	if strings.Contains(errorValue, "not callable") {
		return "This object is not a function - remove the parentheses or check the variable name"
	}
	return "Verify all values are of the expected type"
}

// generateAttributeErrorHint creates a hint for attribute errors.
func generateAttributeErrorHint(errorValue string) string {
	// Extract attribute name from error like "'str' object has no attribute 'nonexistent_method'"
	attrRegex := regexp.MustCompile(`has no attribute '(\w+)'`)
	if matches := attrRegex.FindStringSubmatch(errorValue); len(matches) > 1 {
		attrName := matches[1]
		return "Attribute '" + attrName + "' does not exist on this object. Check the object type and available methods."
	}
	return "Check that the attribute or method exists on this object type"
}
