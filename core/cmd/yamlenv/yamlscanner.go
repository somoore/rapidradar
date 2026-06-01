package yamlenv

import (
	"os"
	"path/filepath"
	"strings"
)

func getYAMLFilesInDir(dirPath string) ([]string, error) {
	var yamlFiles []string

	// Walk through the directory
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Check if the file has a .yml or .yaml extension
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yml") || strings.HasSuffix(info.Name(), ".yaml")) {
			yamlFiles = append(yamlFiles, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return yamlFiles, nil
}
