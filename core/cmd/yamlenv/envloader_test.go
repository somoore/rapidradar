package yamlenv

import "testing"

func TestRedactDebugValue(t *testing.T) {
	if got := redactDebugValue("SlackBotToken", "xoxb-secret"); got != "[REDACTED]" {
		t.Fatalf("expected token to be redacted, got %q", got)
	}
	if got := redactDebugValue("ProjectName", "rapidradar"); got != "rapidradar" {
		t.Fatalf("expected non-sensitive value to pass through, got %q", got)
	}
}
