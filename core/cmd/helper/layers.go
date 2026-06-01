package helper

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func InstallLayerPackages(templatesDir, reqFile string) error {
	layerBaseDir := fmt.Sprintf("%s/layers", templatesDir)
	err := os.MkdirAll(layerBaseDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create layer directory: %w", err)
	}
	debugMode := os.Getenv("DEBUG") == "true"

	// Open requirements.txt
	file, err := os.Open(reqFile)
	if err != nil {
		return fmt.Errorf("failed to open requirements file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		packageName := scanner.Text()
		if packageName == "" || packageName[0] == '#' {
			continue
		}

		// Extract package name (remove version if specified)
		extractedPackageName := extractPackageName(packageName)

		// Define target directory for this package
		packageDir := filepath.Join(layerBaseDir, extractedPackageName, "python")

		// Ensure the package directory exists
		err := os.MkdirAll(packageDir, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create package directory: %w", err)
		}

		// Install the package into the target directory
		cmd := exec.Command("python3", "-m", "pip", "install", packageName, "-t", packageDir)
		if !debugMode {
			cmd.Stdout = nil
			cmd.Stderr = nil
		} else {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}

		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to install package %s: %w", packageName, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading requirements file: %w", err)
	}

	return nil
}

func extractPackageName(packageName string) string {
	// Split at any special character used for versioning
	splitFunc := func(r rune) bool {
		return strings.ContainsRune("=<>!~", r) // Check for special characters
	}
	parts := strings.FieldsFunc(packageName, splitFunc)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0]) // Return only the package name
	}
	return packageName // Fallback (unlikely case)
}
