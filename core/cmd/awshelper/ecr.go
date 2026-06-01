package awshelper

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"rrcore/cmd/logger"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrTypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
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
	logger.Debugln("...Checking if docker is running")
	dockerInfoCmd := exec.Command("docker", "info")
	err := dockerInfoCmd.Run()
	if err != nil {
		return fmt.Errorf("Docker does not appear to be running: %w", err)
	}
	logger.Debugln("🐳 Docker is running.")

	logger.Debugln("🔑 Logging in to AWS ECR...")
	debugMode := os.Getenv("DEBUG") == "true"

	loginCmdStr := fmt.Sprintf("aws ecr get-login-password --profile %s | docker login --username AWS --password-stdin %s.dkr.ecr.%s.amazonaws.com", profile, automationAccountId, region)
	loginCmd := exec.Command("sh", "-c", loginCmdStr)
	if !debugMode {
		loginCmd.Stdout = nil
		loginCmd.Stderr = nil
	} else {
		loginCmd.Stdout = os.Stdout
		loginCmd.Stderr = os.Stderr
	}
	err = loginCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to login to AWS ECR: %w", err)
	}
	logger.Debugln("✅ Logged in successfully!")

	logger.Debugf("🐳 Building and Pushing Image to AWS ECR '%s'...", repoName)
	buildPushCmdStr := fmt.Sprintf("docker build --platform=linux/amd64 -t %s %s && docker push %s", imageUri, contextDir, imageUri)
	buildPushCmd := exec.Command("sh", "-c", buildPushCmdStr)
	if !debugMode {
		buildPushCmd.Stdout = nil
		buildPushCmd.Stderr = nil
	} else {
		buildPushCmd.Stdout = os.Stdout
		buildPushCmd.Stderr = os.Stderr
	}
	err = buildPushCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to build and Push Docker Image: %w", err)
	}
	logger.Debugf("✅ Docker Image built and pushed to AWS ECR %s successfully!", repoName)
	return nil
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
