package helper

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLayerNameForPackage(t *testing.T) {
	tests := map[string]string{
		"boto3":      "boto3",
		"httplib2":   "httplib2",
		"pdpyras":    "pdpyras",
		"openpyxl":   "openpyxl_xlsx",
		"XlsxWriter": "openpyxl_xlsx",
	}

	for input, expected := range tests {
		if actual := layerNameForPackage(input); actual != expected {
			t.Fatalf("layerNameForPackage(%q) = %q, expected %q", input, actual, expected)
		}
	}
}

func TestReadLayerRequirementsRejectsPipOptions(t *testing.T) {
	reqFile := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(reqFile, []byte("--index-url https://example.invalid/simple\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readLayerRequirements(reqFile); err == nil {
		t.Fatal("expected readLayerRequirements to reject pip options")
	}
}

func TestRequirementsLockPath(t *testing.T) {
	if actual := requirementsLockPath("cf/deployment/requirements.txt"); actual != "cf/deployment/requirements.lock" {
		t.Fatalf("requirementsLockPath returned %q", actual)
	}
}
