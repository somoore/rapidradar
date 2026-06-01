package awshelper

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"rrcore/cmd/logger"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrTypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

var (
	awsAccountIDPattern = regexp.MustCompile(`^\d{12}$`)
	awsRegionPattern    = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-\d$`)
	ecrImageURIPattern  = regexp.MustCompile(`^\d{12}\.dkr\.ecr\.[a-z]{2}(?:-[a-z]+)+-\d\.amazonaws\.com/[a-z0-9]+(?:[._/-][a-z0-9]+)*:[A-Za-z0-9_.-]+$`)
	ecrRepoNamePattern  = regexp.MustCompile(`^[a-z0-9]+(?:[._/-][a-z0-9]+)*$`)
)

func checkIfEcrRepoExists(client *ecr.Client, repoName string) (bool, error) {
	resp, err := client.DescribeRepositories(context.TODO(), &ecr.DescribeRepositoriesInput{})
	if err != nil {
		return false, fmt.Errorf("failed to describe repositories: %v", err)
	}
	for _, repo := range resp.Repositories {
		if repo.RepositoryName != nil && *repo.RepositoryName == repoName {
			return true, nil
		}
	}
	return false, nil
}

func CreateEcrRepoIfNotExists(profile, repoName string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	client := ecr.NewFromConfig(cfg)

	exists, err := checkIfEcrRepoExists(client, repoName)
	if err != nil {
		return err
	}
	if exists {
		logger.Debugf("✅ ECR Repository '%s' already exists.", repoName)
		return nil
	}
	logger.Debugf("🚀 Creating ECR Repository '%s'...", repoName)

	_, err = client.CreateRepository(context.TODO(), &ecr.CreateRepositoryInput{
		RepositoryName: &repoName,
	})
	if err != nil {
		return fmt.Errorf("failed to create ECR Repository '%s': %w", repoName, err)
	}
	logger.Debugf("✅ ECR Repository '%s' created successfully.", repoName)
	return nil
}

func DeleteEcrRepoIfExists(client *ecr.Client, repoName string) error {
	exists, err := checkIfEcrRepoExists(client, repoName)
	if err != nil {
		return err
	}
	if !exists {
		logger.Debugf("✅ ECR Repo '%s' does not exist.", repoName)
	} else {
		logger.Debugf("🚀 ECR Repo '%s' exists. Deleting it...", repoName)
		_, err = client.DeleteRepository(context.TODO(), &ecr.DeleteRepositoryInput{
			RepositoryName: &repoName,
			Force:          true,
		})
		if err != nil {
			return fmt.Errorf("failed to delete ECR Repository: %w", err)
		}
		logger.Debugf("🗑️ ECR Repository '%s' deleted successfully.", repoName)
	}
	return nil
}

func BuildAndPushDockerImage(profile, repoName, imageUri, contextDir, automationAccountId, region string) error {
	if err := validateEcrBuildInputs(profile, repoName, imageUri, contextDir, automationAccountId, region); err != nil {
		return err
	}

	logger.Debugln("...Checking if docker is running")
	dockerInfoCmd := exec.Command("docker", "info")
	err := dockerInfoCmd.Run()
	if err != nil {
		return fmt.Errorf("Docker does not appear to be running: %w", err)
	}
	logger.Debugln("🐳 Docker is running.")

	logger.Debugln("🔑 Logging in to AWS ECR...")
	debugMode := os.Getenv("DEBUG") == "true"

	var password bytes.Buffer
	passwordCmd := exec.Command("aws", "ecr", "get-login-password", "--profile", profile, "--region", region)
	passwordCmd.Stdout = &password
	if debugMode {
		passwordCmd.Stderr = os.Stderr
	}
	if err = passwordCmd.Run(); err != nil {
		return fmt.Errorf("failed to get AWS ECR login password: %w", err)
	}

	// #nosec G204 -- fixed executable with argv-only arguments; account and region are validated before use.
	loginCmd := exec.Command("docker", "login", "--username", "AWS", "--password-stdin", ecrRegistryURL(automationAccountId, region))
	loginCmd.Stdin = &password
	if err = runCommand(loginCmd, debugMode); err != nil {
		return fmt.Errorf("failed to login to AWS ECR: %w", err)
	}
	logger.Debugln("✅ Logged in successfully!")

	logger.Debugf("🐳 Building and Pushing Image to AWS ECR '%s'...", repoName)
	buildCmd := exec.Command("docker", "build", "--platform=linux/amd64", "-t", imageUri, contextDir)
	if err = runCommand(buildCmd, debugMode); err != nil {
		return fmt.Errorf("failed to build Docker image: %w", err)
	}
	pushCmd := exec.Command("docker", "push", imageUri)
	if err = runCommand(pushCmd, debugMode); err != nil {
		return fmt.Errorf("failed to push Docker image: %w", err)
	}
	logger.Debugf("✅ Docker Image built and pushed to AWS ECR %s successfully!", repoName)
	return nil
}

func runCommand(cmd *exec.Cmd, debugMode bool) error {
	if debugMode {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errText := strings.TrimSpace(stderr.String())
		if errText != "" {
			return fmt.Errorf("%w: %s", err, errText)
		}
		return err
	}
	return nil
}

func validateEcrBuildInputs(profile, repoName, imageUri, contextDir, automationAccountId, region string) error {
	for name, value := range map[string]string{
		"profile":             profile,
		"repoName":            repoName,
		"imageUri":            imageUri,
		"contextDir":          contextDir,
		"automationAccountId": automationAccountId,
		"region":              region,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s cannot be empty", name)
		}
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%s cannot contain NUL bytes", name)
		}
	}
	if !awsAccountIDPattern.MatchString(automationAccountId) {
		return fmt.Errorf("invalid automation account ID %q", automationAccountId)
	}
	if !awsRegionPattern.MatchString(region) {
		return fmt.Errorf("invalid AWS region %q", region)
	}
	if !ecrRepoNamePattern.MatchString(repoName) {
		return fmt.Errorf("invalid ECR repository name %q", repoName)
	}
	if !ecrImageURIPattern.MatchString(imageUri) {
		return fmt.Errorf("invalid ECR image URI %q", imageUri)
	}
	return nil
}

func ecrRegistryURL(accountID, region string) string {
	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region)
}

func ImageExistsInECR(profile, repoName, imageUri string) (bool, error) {
	re := regexp.MustCompile(`^(?P<account_id>\d+)\.dkr\.ecr\.(?P<region>[^\.]+)\.amazonaws\.com/(?P<repository>[^:]+):(?P<tag>.+)$`)
	matches := re.FindStringSubmatch(imageUri)
	if matches == nil {
		return false, fmt.Errorf("invalid ECR image URI format")
	}
	subexpNames := re.SubexpNames()
	params := make(map[string]string)
	for i, name := range subexpNames {
		if i != 0 && name != "" {
			params[name] = matches[i]
		}
	}
	imageTag := params["tag"]

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return false, fmt.Errorf("failed to load AWS config: %w", err)
	}
	client := ecr.NewFromConfig(cfg)

	logger.Debugf("...Checking if Image with tag %s exists in ECR Repo %s", imageTag, repoName)
	response, err := client.ListImages(context.TODO(), &ecr.ListImagesInput{
		RepositoryName: &repoName,
		Filter: &ecrTypes.ListImagesFilter{
			TagStatus: ecrTypes.TagStatusTagged,
		},
	})
	if err != nil {
		return false, fmt.Errorf("failed to list tagged images in ECR repo %s: %w", repoName, err)
	}
	for _, imageDetail := range response.ImageIds {
		if *imageDetail.ImageTag == imageTag {
			logger.Debugf("✅ Image with tag %s found in ECR Repo %s", imageTag, repoName)
			return true, nil
		}
	}
	logger.Debugf("❌ Image with tag %s not found in ECR Repo %s", imageTag, repoName)
	return false, nil
}
