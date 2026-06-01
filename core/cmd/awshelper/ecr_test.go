package awshelper

import "testing"

func TestValidateEcrBuildInputsRejectsInvalidImageURI(t *testing.T) {
	err := validateEcrBuildInputs(
		"default",
		"rapidradar-slack-socket-app",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:latest;touch /tmp/pwned",
		"cf/deployment/slack_socket_app",
		"123456789012",
		"us-east-1",
	)
	if err == nil {
		t.Fatal("expected invalid image URI to be rejected")
	}
}

func TestValidateEcrBuildInputsAcceptsExpectedInputs(t *testing.T) {
	err := validateEcrBuildInputs(
		"default",
		"rapidradar-slack-socket-app",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/rapidradar-slack-socket-app:latest",
		"cf/deployment/slack_socket_app",
		"123456789012",
		"us-east-1",
	)
	if err != nil {
		t.Fatalf("expected valid inputs, got %v", err)
	}
}

func TestEcrRegistryURL(t *testing.T) {
	expected := "123456789012.dkr.ecr.us-west-2.amazonaws.com"
	if actual := ecrRegistryURL("123456789012", "us-west-2"); actual != expected {
		t.Fatalf("ecrRegistryURL returned %q", actual)
	}
}
