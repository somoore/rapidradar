package awshelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"rrcore/cmd/spinner"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretTypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

func SecretsHandler(profile, secretCfKey, secretName, secretDesc string, secretDependentKeys map[string]string) (bool, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return false, fmt.Errorf("failed to load AWS config: %w", err)
	}

	secretsClient := secretsmanager.NewFromConfig(cfg)
	secretExists, err := checkSecretExists(secretsClient, secretName)
	if err != nil {
		logger.Fatalf("failed to check existence of SecretsManager Secret %s: %v", secretName, err)
		return false, err
	}
	if !secretExists {
		spinner.Pause()
		create := helper.Confirm(true, fmt.Sprintf("SecretsManager Secret named %s does not exist. Do you want to create it?", secretName))
		if create {
			secretString := make(map[string]string)
			for dependentKey, dependentKeyDesc := range secretDependentKeys {
				dependentKeyVal := helper.Ask(fmt.Sprintf("Please provide value for %s: ", dependentKeyDesc))
				secretString[dependentKey] = dependentKeyVal
			}
			secretStringJson, err := json.Marshal(secretString)
			if err != nil {
				logger.Fatalf("failed to marshal %s: %v", secretString, err)
				return false, err
			}
			err = createSecret(secretsClient, secretName, secretDesc, string(secretStringJson))
			if err != nil {
				logger.Fatalf("failed to create SecretsManager secret: %v", err)
				return false, err
			}
			logger.Debugf("SecretsManager Secret '%s' created successfully!", secretName)
			spinner.Resume()
			return true, nil
		} else {
			spinner.Resume()
			return false, nil
		}
	} else {
		// if secret exists, check if required keys exist or not
		currentSecretJson, err := getSecretString(secretsClient, secretName)
		if err != nil {
			return false, fmt.Errorf("failed to retrieve existing secret: %w", err)
		}
		var secretMap map[string]string
		err = json.Unmarshal([]byte(currentSecretJson), &secretMap)
		if err != nil {
			return false, fmt.Errorf("failed to unmarshal existing secret: %w", err)
		}
		updated := false
		// Check for each required key; if missing or empty, prompt for its value.
		for dependentKey, dependentKeyDesc := range secretDependentKeys {
			if val, ok := secretMap[dependentKey]; !ok || val == "" {
				spinner.Pause()
				newVal := helper.Ask(fmt.Sprintf("Please provide value for %s: ", dependentKeyDesc))
				spinner.Resume()
				secretMap[dependentKey] = newVal
				updated = true
			}
		}
		if updated {
			newSecretJson, err := json.Marshal(secretMap)
			if err != nil {
				return false, fmt.Errorf("failed to marshal updated secret: %w", err)
			}
			err = updateSecret(secretsClient, secretName, string(newSecretJson))
			if err != nil {
				return false, fmt.Errorf("failed to update secret: %w", err)
			}
			logger.Debugf("SecretsManager Secret '%s' updated successfully!", secretName)
		}
	}
	return true, nil
}

func NotificationsConfigSecretsHandler(profile, secretName, notificationType, notificationsAppCfKey string, notificationDependentKeys map[string]map[string]string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	secretsClient := secretsmanager.NewFromConfig(cfg)
	notificationsApp := os.Getenv(notificationsAppCfKey)

	secretExists, err := checkSecretExists(secretsClient, secretName)
	if err != nil {
		logger.Fatalf("failed to check existence of SecretsManager Secret %s: %v", secretName, err)
		return err
	}
	if secretExists {
		spinner.Resume()
		return nil
	}

	spinner.Pause()
	fmt.Println()
	create := helper.Confirm(true, fmt.Sprintf("SecretsManager Secret named %s does not exist. Do you want to create it?", secretName))
	if !create {
		logger.Fatalln("Exiting... Please start the rrcore deployment again after creating the SecretsManager secret manually.")
	}
	secretString := make(map[string]string)
	secretString["NOTIFICATION_APP"] = notificationsApp
	configTypes := []string{}
	for notifSupport := range notificationDependentKeys {
		configTypes = append(configTypes, notifSupport)
	}

	var notifSupportType string
	if len(configTypes) > 1 {
		notifSupportType = helper.AskWithSelection(fmt.Sprintf("How do you prefer setting up %s notifications?", notificationType), configTypes)
	} else {
		notifSupportType = configTypes[0]
	}

	notifSupportTypeSecrets := notificationDependentKeys[notifSupportType]

	if notifSupportType == "APP BASED" {
		var configValue []string
		for {
			oauthToken := helper.Ask(fmt.Sprintf("Please provide value for %s: ", notifSupportTypeSecrets["BOT_OAUTH_TOKEN"]))
			channelID := helper.Ask(fmt.Sprintf("Please provide value for %s: ", notifSupportTypeSecrets["CHANNEL_ID"]))
			configValue = append(configValue, fmt.Sprintf("%s:%s", oauthToken, channelID))
			addAnotherValue := helper.Confirm(false, fmt.Sprintf("Do you want to provide another %s config?", notificationsApp))
			if !addAnotherValue {
				break
			}
		}
		secretString["APP_CONFIG"] = strings.Join(configValue, ",")
	} else {
		var configValue []string
		for {
			for _, desc := range notifSupportTypeSecrets {
				value := helper.Ask(fmt.Sprintf("Please provide value for %s: ", desc))
				configValue = append(configValue, value)
			}
			addAnotherValue := helper.Confirm(false, fmt.Sprintf("Do you want to provide another %s config?", notificationsApp))
			if !addAnotherValue {
				break
			}
		}
		secretString["WEBHOOK_URL"] = strings.Join(configValue, ",")
	}
	secretStringJson, err := json.Marshal(secretString)
	if err != nil {
		logger.Fatalf("failed to marshal %s: %v", secretString, err)
		return err
	}
	err = createSecret(secretsClient, secretName, fmt.Sprintf("Notification Configurations for %s alerts", notificationType), string(secretStringJson))
	if err != nil {
		logger.Fatalf("failed to create SecretsManager secret: %v", err)
		return err
	}
	logger.Debugf("SecretsManager Secret '%s' created successfully!", secretName)
	spinner.Resume()
	return nil
}

func checkSecretExists(client *secretsmanager.Client, secretName string) (bool, error) {
	_, err := client.DescribeSecret(context.TODO(), &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		var notFoundErr *secretTypes.ResourceNotFoundException
		if ok := errors.As(err, &notFoundErr); ok {
			return false, nil
		}
		return false, fmt.Errorf("failed to check SecretsManager secret: %w", err)
	}

	return true, nil
}

func getSecretString(client *secretsmanager.Client, secretName string) (string, error) {
	response, err := client.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		var notFoundErr *secretTypes.ResourceNotFoundException
		if ok := errors.As(err, &notFoundErr); ok {
			return "", nil
		}
		return "", fmt.Errorf("failed to get value of SecretsManager secret: %w", err)
	}
	return *response.SecretString, nil
}

func createSecret(client *secretsmanager.Client, secretName, secretDesc, secretString string) error {
	_, err := client.CreateSecret(context.TODO(), &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretName),
		Description:  aws.String(secretDesc),
		SecretString: &secretString,
	})
	if err != nil {
		return fmt.Errorf("failed to create SecretsManager secret %s: %w", secretName, err)
	}
	return nil
}

func updateSecret(client *secretsmanager.Client, secretName, secretString string) error {
	_, err := client.UpdateSecret(context.TODO(), &secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(secretName),
		SecretString: &secretString,
	})
	if err != nil {
		return fmt.Errorf("failed to update secretString of SecretsManager secret %s: %w", secretName, err)
	}
	return nil
}

func DeleteSecretIfExists(client *secretsmanager.Client, secretName string) error {
	secretExists, err := checkSecretExists(client, secretName)
	if err != nil {
		return fmt.Errorf("failed to check existence of SecretsManager secret %s: %v", secretName, err)
	}

	if secretExists {
		_, err = client.DeleteSecret(context.TODO(), &secretsmanager.DeleteSecretInput{
			SecretId:                   aws.String(secretName),
			ForceDeleteWithoutRecovery: aws.Bool(true),
		})
		if err != nil {
			return fmt.Errorf("failed to delete SecretsManager secret %s: %v", secretName, err)
		}
	}
	return nil
}
