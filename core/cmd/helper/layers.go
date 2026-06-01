package helper

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type layerRequirement struct {
	PackageSpec string
	PackageName string
	LayerName   string
}

func InstallLayerPackages(templatesDir, reqFile string) error {
	layerBaseDir := fmt.Sprintf("%s/layers", templatesDir)
	err := os.MkdirAll(layerBaseDir, 0o750)
	if err != nil {
		return fmt.Errorf("failed to create layer directory: %w", err)
	}
	debugMode := os.Getenv("DEBUG") == "true"

	lockFile := requirementsLockPath(reqFile)
	if _, err := os.Stat(lockFile); err != nil {
		return fmt.Errorf("hash-locked requirements file %s is required: %w", lockFile, err)
	}

	requirements, err := readLayerRequirements(reqFile)
	if err != nil {
		return err
	}

	wheelhouseDir, err := os.MkdirTemp("", "rapidradar-layer-wheels-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary wheelhouse: %w", err)
	}
	defer os.RemoveAll(wheelhouseDir)

	// #nosec G204 -- fixed executable with argv-only arguments; lockFile is repo-controlled and hash-enforced.
	downloadCmd := exec.Command("python3", "-m", "pip", "download", "--require-hashes", "--dest", wheelhouseDir, "-r", lockFile)
	if err := runPipCommand(downloadCmd, debugMode); err != nil {
		return fmt.Errorf("failed to download hash-verified layer packages: %w", err)
	}

	clearedLayerDirs := map[string]bool{}
	for _, requirement := range requirements {
		packageDir := filepath.Join(layerBaseDir, requirement.LayerName, "python")

		if !clearedLayerDirs[packageDir] {
			if err := os.RemoveAll(packageDir); err != nil {
				return fmt.Errorf("failed to clear package directory %s: %w", packageDir, err)
			}
			clearedLayerDirs[packageDir] = true
		}
		if err := os.MkdirAll(packageDir, 0o750); err != nil {
			return fmt.Errorf("failed to create package directory: %w", err)
		}

		// #nosec G204 -- fixed executable with argv-only arguments; packages are installed offline from a hash-verified wheelhouse.
		cmd := exec.Command(
			"python3", "-m", "pip", "install",
			"--no-index",
			"--find-links", wheelhouseDir,
			requirement.PackageSpec,
			"-t", packageDir,
		)
		if err := runPipCommand(cmd, debugMode); err != nil {
			return fmt.Errorf("failed to install package %s: %w", requirement.PackageSpec, err)
		}
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

func requirementsLockPath(reqFile string) string {
	ext := filepath.Ext(reqFile)
	return strings.TrimSuffix(reqFile, ext) + ".lock"
}

func readLayerRequirements(reqFile string) ([]layerRequirement, error) {
	file, err := os.Open(reqFile) // #nosec G304 -- reqFile is a deployment requirements file inside the repository.
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements file: %w", err)
	}
	defer file.Close()

	requirements := []layerRequirement{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		packageSpec := strings.TrimSpace(scanner.Text())
		if packageSpec == "" || strings.HasPrefix(packageSpec, "#") {
			continue
		}
		if strings.HasPrefix(packageSpec, "-") {
			return nil, fmt.Errorf("unsupported pip option in layer requirements: %s", packageSpec)
		}
		packageName := extractPackageName(packageSpec)
		requirements = append(requirements, layerRequirement{
			PackageSpec: packageSpec,
			PackageName: packageName,
			LayerName:   layerNameForPackage(packageName),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading requirements file: %w", err)
	}
	return requirements, nil
}

func layerNameForPackage(packageName string) string {
	normalizedName := strings.ToLower(strings.ReplaceAll(packageName, "_", "-"))
	if normalizedName == "openpyxl" || normalizedName == "xlsxwriter" {
		return "openpyxl_xlsx"
	}
	return strings.ReplaceAll(normalizedName, "-", "_")
}

func runPipCommand(cmd *exec.Cmd, debugMode bool) error {
	if debugMode {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return cmd.Run()
}
