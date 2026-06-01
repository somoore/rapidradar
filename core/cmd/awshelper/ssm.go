package awshelper

import (
	"context"
	"errors"
	"fmt"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"rrcore/cmd/spinner"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go/aws"
)

func SSMParameterHandler(profile, parameterName, ssmLong string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	ssmClient := ssm.NewFromConfig(cfg)
	parameterExists, err := checkSSMParameterExists(ssmClient, parameterName)
	if err != nil {
		logger.Fatalf("failed to check existence of SSM Parameter %s: %v", parameterName, err)
		return err
	}
	if !parameterExists {
		spinner.Pause()
		create := helper.Confirm(true, fmt.Sprintf("SSM Parameter named %s does not exist. Do you want to create it?", parameterName))
		if create {
			parameterValue := helper.Ask(fmt.Sprintf("Please provide value for %s: ", ssmLong))
			err = createSSMParameter(ssmClient, parameterName, parameterValue, ssmLong, ssmTypes.ParameterTypeSecureString)
			if err != nil {
				logger.Fatalf("failed to create SSM Parameter: %v", err)
				return err
			}
			logger.Debugf("SSM Parameter '%s' created successfully!", parameterName)
		} else {
			logger.Fatalln("Exiting... Please start the rrcore deployment again after creating the SSM Parameter manually.")
		}
		spinner.Resume()
	}
	return nil
}

func checkSSMParameterExists(client *ssm.Client, parameterName string) (bool, error) {
	_, err := client.GetParameter(context.TODO(), &ssm.GetParameterInput{
		Name: aws.String(parameterName),
	})
	if err != nil {
		var notFoundErr *ssmTypes.ParameterNotFound
		if ok := errors.As(err, &notFoundErr); ok {
			return false, nil
		}
		return false, fmt.Errorf("failed to check SSM parameter: %w", err)
	}

	return true, nil
}

func createSSMParameter(client *ssm.Client, parameterName, parameterValue, ssmLong string, parameterType ssmTypes.ParameterType) error {
	_, err := client.PutParameter(context.TODO(), &ssm.PutParameterInput{
		Name:        aws.String(parameterName),
		Value:       aws.String(parameterValue),
		Type:        parameterType,
		Overwrite:   aws.Bool(true),
		Description: &ssmLong,
	})
	if err != nil {
		return fmt.Errorf("failed to create SSM parameter %s: %w", parameterName, err)
	}
	return nil
}

func DeleteSSMParameterIfExists(client *ssm.Client, parameterName string) error {
	parameterExists, err := checkSSMParameterExists(client, parameterName)
	if err != nil {
		return fmt.Errorf("failed to check existence of SSM Parameter %s: %v", parameterName, err)
	}

	if parameterExists {
		_, err = client.DeleteParameter(context.TODO(), &ssm.DeleteParameterInput{
			Name: aws.String(parameterName),
		})
		if err != nil {
			return fmt.Errorf("failed to delete SSM Parameter %s: %v", parameterName, err)
		}
	}
	return nil
}
