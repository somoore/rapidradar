package yamlenv

import (
	"fmt"
	"os"
	"rrcore/cmd/logger"
)

func UpdateYAML(filePath, key, value string) error {
	newEntry := fmt.Sprintf("\n%s: \"%s\"", key, value)

	// Read existing YAML if the file exists
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) // #nosec G304 -- callers pass fixed repository env files.
	if err != nil {
		return fmt.Errorf("failed to open YAML file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(newEntry); err != nil {
		return fmt.Errorf("failed to write to YAML file: %w", err)
	}

	logger.Debugf("Successfully added %s: %s to %s\n", key, value, filePath)
	return nil
}
