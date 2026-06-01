package awshelper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/smithy-go"
)

type StackSetProps struct {
	StackSetName           string
	TemplateFile           string
	TemplateUrl            string
	IsMainRegionDeployment bool
	IsServiceManaged       bool
	CallAs                 cfTypes.CallAs
	PermissionModel        cfTypes.PermissionModels
	DeploymentTargets      *cfTypes.DeploymentTargets
	AutoDeployment         *cfTypes.AutoDeployment
}

type StackSetInstanceStateInfo struct {
	FailedOrCanceled bool
	AccountsToAdd    []string
	AccountsToRemove []string
	RegionsToAdd     []string
	RegionsToRemove  []string
}

func getCfStackSetDelegatedAdmin(profile string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	orgClient := organizations.NewFromConfig(cfg)

	// Call ListDelegatedAdministrators
	output, err := orgClient.ListDelegatedAdministrators(context.TODO(), &organizations.ListDelegatedAdministratorsInput{
		ServicePrincipal: aws.String("member.org.stacksets.cloudformation.amazonaws.com"),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get delegated administrators: %w", err)
	}

	// Extract the first delegated admin ID
	if len(output.DelegatedAdministrators) > 0 {
		return *output.DelegatedAdministrators[0].Id, nil
	}

	return "", fmt.Errorf("no delegated administrators found")
}

func checkIfStackExists(client *cloudformation.Client, stackName string) (bool, cfTypes.StackStatus, error) {
	input := &cloudformation.DescribeStacksInput{
		StackName: &stackName,
	}
	output, err := client.DescribeStacks(context.TODO(), input)
	if err != nil {
		var notFoundErr smithy.APIError
		if ok := errors.As(err, &notFoundErr); ok && notFoundErr.ErrorCode() == "ValidationError" {
			return false, "", nil
		}
		return false, "", fmt.Errorf("failed to describe CloudFormation stacks: %w", err)
	}

	if output.Stacks[0].StackStatus != cfTypes.StackStatusDeleteComplete {
		return true, output.Stacks[0].StackStatus, nil
	}

	return false, "", nil
}

func deleteRollBackCompleteStackIfExists(client *cloudformation.Client, stackName string) error {
	stackExists, stackStatus, err := checkIfStackExists(client, stackName)
	if err != nil {
		return err
	}
	if stackExists && stackStatus == cfTypes.StackStatusRollbackComplete {
		err = deleteCloudFormationStack(client, stackName)
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteCloudFormationStack(client *cloudformation.Client, stackName string) error {
	_, err := client.DeleteStack(context.TODO(), &cloudformation.DeleteStackInput{
		StackName: aws.String(stackName),
	})
	if err != nil {
		return fmt.Errorf("failed to delete stack '%s': %w", stackName, err)
	}
	logger.Debugf("🚀 Deletion of stack '%s' initiated.", stackName)

	err = waitForStackDeletion(client, stackName)
	if err != nil {
		return fmt.Errorf("failed while waiting for stack deletion: %w", err)
	}
	return nil
}

func waitForStackDeletion(client *cloudformation.Client, stackName string) error {
	logger.Debugf("⏳ Waiting for stack '%s' to be deleted...", stackName)
	for {
		_, err := client.DescribeStacks(context.TODO(), &cloudformation.DescribeStacksInput{
			StackName: aws.String(stackName),
		})
		if err != nil {
			if strings.Contains(err.Error(), "does not exist") {
				logger.Debugf("✅ Stack '%s' deleted successfully.", stackName)
				return nil
			}
			return fmt.Errorf("error checking stack deletion: %w", err)
		}
		time.Sleep(10 * time.Second)
	}
}

func DeleteCloudFormationStackIfExists(client *cloudformation.Client, stackName string) error {
	stackExists, _, err := checkIfStackExists(client, stackName)
	if err != nil {
		return fmt.Errorf("failed to check existence of CloudFormation Stack %s: %w", stackName, err)
	}
	if stackExists {
		err = deleteCloudFormationStack(client, stackName)
		if err != nil {
			return fmt.Errorf("failed to delete CloudFormation Stack %s: %w", stackName, err)
		}
	}
	return nil
}

func createCloudFormationStack(client *cloudformation.Client, stackName, templateFile, templateUrl string, params map[string]string) error {
	var templateBody *string
	var templateURL *string

	if templateFile != "" {
		logger.Debugf("📂 Using local template file: %s", templateFile)
		body, err := helper.ReadTemplateFile(templateFile)
		if err != nil {
			return err
		}
		templateBody = aws.String(body)
	} else if templateUrl != "" {
		logger.Debugf("🌐 Using S3 template URL: %s", templateUrl)
		templateURL = aws.String(templateUrl)
	} else {
		return fmt.Errorf("either templateFile or templateUrl must be provided")
	}
	err := deleteRollBackCompleteStackIfExists(client, stackName)
	if err != nil {
		return fmt.Errorf("failed to delete stack in rolledback state: %w", err)
	}

	awsParams := mapToCFParams(params)

	_, err = client.CreateStack(context.TODO(), &cloudformation.CreateStackInput{
		StackName:    aws.String(stackName),
		TemplateBody: templateBody,
		TemplateURL:  templateURL,
		Capabilities: []cfTypes.Capability{
			cfTypes.CapabilityCapabilityIam,
			cfTypes.CapabilityCapabilityNamedIam,
		},
		Parameters: awsParams,
	})
	if err != nil {
		return fmt.Errorf("failed to create CloudFormation stack: %w", err)
	}
	logger.Debugf("🚀 CloudFormation Stack '%s' creation initiated.", stackName)

	// Wait for stack creation to complete
	err = waitForStackCompletion(client, stackName, "CREATE_COMPLETE")
	if err != nil {
		return fmt.Errorf("stack creation failed: %w", err)
	}
	return nil
}

func updateCloudFormationStack(client *cloudformation.Client, stackName, templateFile, templateUrl string, params map[string]string) error {
	var templateBody *string
	var templateURL *string

	if templateFile != "" {
		logger.Debugf("📂 Using local template file: %s", templateFile)
		body, err := helper.ReadTemplateFile(templateFile)
		if err != nil {
			return err
		}
		templateBody = aws.String(body)
	} else if templateUrl != "" {
		logger.Debugf("🌐 Using S3 template URL: %s", templateUrl)
		templateURL = aws.String(templateUrl)
	} else {
		return fmt.Errorf("either templateFile or templateUrl must be provided")
	}

	awsParams := mapToCFParams(params)

	_, err := client.UpdateStack(context.TODO(), &cloudformation.UpdateStackInput{
		StackName:    aws.String(stackName),
		TemplateBody: templateBody,
		TemplateURL:  templateURL,
		Capabilities: []cfTypes.Capability{
			cfTypes.CapabilityCapabilityIam,
			cfTypes.CapabilityCapabilityNamedIam,
		},
		Parameters: awsParams,
	})
	if err != nil {
		if strings.Contains(err.Error(), "No updates are to be performed") {
			logger.Debugf("No updates needed for CloudFormation Stack '%s'.", stackName)
			return nil
		}
		return fmt.Errorf("failed to update CloudFormation stack: %w", err)
	}
	logger.Debugf("🚀 CloudFormation Stack '%s' update initiated.", stackName)

	// Wait for stack update to complete
	err = waitForStackCompletion(client, stackName, "UPDATE_COMPLETE")
	if err != nil {
		return fmt.Errorf("stack update failed: %w", err)
	}
	return nil
}

func deployCloudFormationStack(client *cloudformation.Client, stackName, templateFile, templateUrl string, params map[string]string) error {
	err := deleteRollBackCompleteStackIfExists(client, stackName)
	if err != nil {
		return fmt.Errorf("failed to delete stack %s if in ROLLBACK_COMPLETE state", stackName)
	}
	stackExists, _, err := checkIfStackExists(client, stackName)
	if err != nil {
		return fmt.Errorf("failed to check status of Stack %s: %w", stackName, err)
	}
	if !stackExists {
		logger.Debugf("🚀 Creating stack '%s'", stackName)
		err = createCloudFormationStack(client, stackName, templateFile, templateUrl, params)
		if err != nil {
			return err
		}
	} else {
		logger.Debugf("🔄 Updating stack '%s'...", stackName)

		err = updateCloudFormationStack(client, stackName, templateFile, templateUrl, params)
		if err != nil {
			return err
		}
	}
	return nil
}

func waitForStackCompletion(client *cloudformation.Client, stackName, targetStatus string) error {
	logger.Debugf("⏳ Waiting for stack '%s' to reach status: %s...", stackName, targetStatus)
	for {
		time.Sleep(10 * time.Second) // Wait 10s before checking the status

		output, err := client.DescribeStacks(context.TODO(), &cloudformation.DescribeStacksInput{
			StackName: aws.String(stackName),
		})
		if err != nil {
			return fmt.Errorf("failed to describe stack: %w", err)
		}

		currentStatus := output.Stacks[0].StackStatus
		logger.Debugf("🔄 Current Stack Status: %s", currentStatus)
		if string(currentStatus) == targetStatus {
			return nil
		}

		stackFailedStatuses := []string{
			"ROLLBACK_COMPLETE",
			"ROLLBACK_FAILED",
			"UPDATE_ROLLBACK_FAILED",
			"UPDATE_ROLLBACK_COMPLETE",
			"DELETE_COMPLETE",
		}
		if contains(stackFailedStatuses, string(currentStatus)) {
			return fmt.Errorf("stack creation failed with status: %s", currentStatus)
		}
	}
}

func mapToCFParams(params map[string]string) []cfTypes.Parameter {
	var awsParams []cfTypes.Parameter
	for key, value := range params {
		awsParams = append(awsParams, cfTypes.Parameter{
			ParameterKey:   aws.String(key),
			ParameterValue: aws.String(value),
		})
	}
	return awsParams
}

func packageTemplate(templatePath, s3Bucket, packagedTemplatePath, profile, region string) error {
	logger.Debugln("📦 Packaging CloudFormation template...")
	debugMode := os.Getenv("DEBUG") == "true"

	cmd := exec.Command("aws", "cloudformation", "package",
		"--template-file", templatePath,
		"--s3-bucket", s3Bucket,
		"--output-template-file", packagedTemplatePath,
		"--profile", profile,
		"--region", region,
	)
	if !debugMode {
		cmd.Stdout = nil
		cmd.Stderr = nil
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to package CloudFormation template: %w", err)
	}
	logger.Debugf("✅ Template packaged successfully: %s", packagedTemplatePath)
	return nil
}

func GetStackOutput(profile, stackName, outputKey string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)

	resp, err := client.DescribeStacks(context.TODO(), &cloudformation.DescribeStacksInput{StackName: &stackName})
	if err != nil {
		return "", fmt.Errorf("failed to describe CloudFormation stack %s: %w", stackName, err)
	}
	if strings.Contains(*resp.Stacks[0].StackName, stackName) {
		for _, output := range resp.Stacks[0].Outputs {
			if *output.OutputKey == outputKey {
				return *output.OutputValue, nil
			}
		}
	}
	return "", fmt.Errorf("%s output not found in stack outputs for stack '%s'", outputKey, stackName)
}

func checkIfStackSetExists(client *cloudformation.Client, stackSetName string, callAs cfTypes.CallAs) (bool, error) {
	_, err := client.DescribeStackSet(context.TODO(), &cloudformation.DescribeStackSetInput{
		StackSetName: aws.String(stackSetName),
		CallAs:       callAs,
	})

	if err != nil {
		var notFoundErr *cfTypes.StackSetNotFoundException
		if ok := errors.As(err, &notFoundErr); ok {
			return false, nil
		}
		return false, fmt.Errorf("failed to describe StackSet: %w", err)
	}

	return true, nil
}

func createCloudFormationStackSet(automationAccountId string, client *cloudformation.Client, stackSetProps *StackSetProps, params map[string]string) error {
	var templateBody *string
	var templateURL *string

	if stackSetProps.TemplateFile != "" {
		logger.Debugf("📂 Using local template file: %s", stackSetProps.TemplateFile)
		body, err := helper.ReadTemplateFile(stackSetProps.TemplateFile)
		if err != nil {
			return err
		}
		templateBody = aws.String(body)
	} else if stackSetProps.TemplateUrl != "" {
		logger.Debugf("🌐 Using S3 template URL: %s", stackSetProps.TemplateUrl)
		templateURL = aws.String(stackSetProps.TemplateUrl)
	} else {
		return fmt.Errorf("either templateFile or templateUrl must be provided")
	}

	awsParams := mapToCFParams(params)
	input := &cloudformation.CreateStackSetInput{
		StackSetName: aws.String(stackSetProps.StackSetName),
		TemplateBody: templateBody,
		TemplateURL:  templateURL,
		Parameters:   awsParams,
		Capabilities: []cfTypes.Capability{
			cfTypes.CapabilityCapabilityIam,
			cfTypes.CapabilityCapabilityNamedIam,
		},
		PermissionModel: stackSetProps.PermissionModel,
		CallAs:          stackSetProps.CallAs,
		AutoDeployment:  stackSetProps.AutoDeployment,
	}

	if stackSetProps.PermissionModel == cfTypes.PermissionModelsSelfManaged {
		input.AdministrationRoleARN = aws.String(fmt.Sprintf("arn:aws:iam::%s:role/%s", automationAccountId, os.Getenv("CloudFormationStackSetAdministrationRoleStackName")))
		input.ExecutionRoleName = aws.String(os.Getenv("CloudFormationStackSetExecutionRoleStackSetName"))
	}

	_, err := client.CreateStackSet(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to create StackSet %s: %w", stackSetProps.StackSetName, err)
	}

	logger.Debugf("🚀 CloudFormation StackSet '%s' creation initiated.", stackSetProps.StackSetName)
	return nil
}

func deleteCloudFormationStackSet(client *cloudformation.Client, stackSetName string) error {
	_, err := client.DeleteStackSet(context.TODO(), &cloudformation.DeleteStackSetInput{
		StackSetName: aws.String(stackSetName),
	})
	if err != nil {
		return fmt.Errorf("failed to delete StackSet '%s': %w", stackSetName, err)
	}

	logger.Debugf("🚀 Deletion of StackSet '%s' initiated.\n", stackSetName)
	return nil
}

func updateCloudFormationStackSet(client *cloudformation.Client, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences, params map[string]string, automationAccountId string) error {
	var templateBody *string
	var templateURL *string

	if stackSetProps.TemplateFile != "" {
		logger.Debugf("📂 Using local template file: %s", stackSetProps.TemplateFile)
		body, err := helper.ReadTemplateFile(stackSetProps.TemplateFile)
		if err != nil {
			return err
		}
		templateBody = aws.String(body)
	} else if stackSetProps.TemplateUrl != "" {
		logger.Debugf("🌐 Using S3 template URL: %s", stackSetProps.TemplateUrl)
		templateURL = aws.String(stackSetProps.TemplateUrl)
	} else {
		return fmt.Errorf("either templateFile or templateUrl must be provided")
	}

	awsParams := mapToCFParams(params)

	updateStackSetInput := &cloudformation.UpdateStackSetInput{
		StackSetName: aws.String(stackSetProps.StackSetName),
		TemplateBody: templateBody,
		TemplateURL:  templateURL,
		Parameters:   awsParams,
		Capabilities: []cfTypes.Capability{
			cfTypes.CapabilityCapabilityIam,
			cfTypes.CapabilityCapabilityNamedIam,
		},
		OperationPreferences: stackSetOpsPreferences,
		CallAs:               stackSetProps.CallAs,
		AutoDeployment:       stackSetProps.AutoDeployment,
	}
	if stackSetProps.PermissionModel == cfTypes.PermissionModelsSelfManaged {
		updateStackSetInput.AdministrationRoleARN = aws.String(fmt.Sprintf("arn:aws:iam::%s:role/%s", automationAccountId, os.Getenv("CloudFormationStackSetAdministrationRoleStackName")))
		updateStackSetInput.ExecutionRoleName = aws.String(os.Getenv("CloudFormationStackSetExecutionRoleStackSetName"))
	}

	resp, err := client.UpdateStackSet(context.TODO(), updateStackSetInput)
	if err != nil {
		return fmt.Errorf("failed to update StackSet %s: %w", stackSetProps.StackSetName, err)
	}
	logger.Debugf("🚀 CloudFormation StackSet '%s' update initiated.", stackSetProps.StackSetName)

	err = waitForStackSetOperation(client, stackSetProps.StackSetName, *resp.OperationId, stackSetProps.CallAs)
	if err != nil {
		return fmt.Errorf("stack creation failed: %w", err)
	}
	return nil
}

func getAllStackInstanceAccountsAndRegions(client *cloudformation.Client, stackSetName string, callAs cfTypes.CallAs) ([]string, []string, error) {
	instanceAccounts, instanceRegions := []string{}, []string{}
	var nextToken *string
	for {
		resp, err := client.ListStackInstances(context.TODO(), &cloudformation.ListStackInstancesInput{
			StackSetName: aws.String(stackSetName),
			CallAs:       callAs,
			NextToken:    nextToken,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list StackSet instances: %w", err)
		}

		for _, instance := range resp.Summaries {
			instanceAccounts = append(instanceAccounts, *instance.Account)
			instanceRegions = append(instanceRegions, *instance.Region)
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return unique(instanceAccounts), unique(instanceRegions), nil
}

func getFailedorCanceledorMissingStackSetInstances(client *cloudformation.Client, managementAccountId, stackSetName string, callAs cfTypes.CallAs, newDeploymentAccounts, newDeploymentRegions []string) (*StackSetInstanceStateInfo, error) {
	var failedOrCanceled bool
	var missingInstanceAccounts []string
	var missingInstanceRegions []string
	var nextToken *string
	var allDeploymentTargets []string
	var allDeploymentRegions []string

	for {
		resp, err := client.ListStackInstances(context.TODO(), &cloudformation.ListStackInstancesInput{
			StackSetName: aws.String(stackSetName),
			CallAs:       callAs,
			NextToken:    nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list StackSet instances: %w", err)
		}

		for _, instance := range resp.Summaries {
			status := string(instance.Status)
			accountID := aws.StringValue(instance.Account)
			region := aws.StringValue(instance.Region)
			allDeploymentTargets = append(allDeploymentTargets, accountID)
			allDeploymentRegions = append(allDeploymentRegions, region)

			logger.Debugf("🔹 Instance in Account: %s, Region: %s, Status: %s", accountID, region, status)
			if strings.Contains(status, "FAILED") || strings.Contains(status, "CANCELED") {
				failedOrCanceled = true
			}
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	missingInstanceAccounts = getMissingDeploymentTargets(managementAccountId, unique(allDeploymentTargets), newDeploymentAccounts)
	missingInstanceRegions = getMissingDeploymentRegions(unique(allDeploymentRegions), newDeploymentRegions)

	return &StackSetInstanceStateInfo{
		FailedOrCanceled: failedOrCanceled,
		AccountsToAdd:    missingInstanceAccounts,
		AccountsToRemove: getDeploymentTargetToRemove(managementAccountId, unique(allDeploymentTargets), newDeploymentAccounts),
		RegionsToAdd:     missingInstanceRegions,
		RegionsToRemove:  getDeploymentRegionsToRemove(unique(allDeploymentRegions), newDeploymentRegions),
	}, nil
}

func getMissingDeploymentTargets(managementAccountId string, stackSetInstanceAccounts, deploymentTargetAccounts []string) []string {
	var missingAccounts []string
	for _, target := range deploymentTargetAccounts {
		if !contains(stackSetInstanceAccounts, target) && target != managementAccountId {
			missingAccounts = append(missingAccounts, target)
		}
	}
	return missingAccounts
}
func getDeploymentTargetToRemove(managementAccountId string, stackSetInstanceAccounts, deploymentTargetAccounts []string) []string {
	var accountsToRemove []string
	for _, target := range stackSetInstanceAccounts {
		if !contains(deploymentTargetAccounts, target) && target != managementAccountId {
			accountsToRemove = append(accountsToRemove, target)
		}
	}
	return accountsToRemove
}
func getMissingDeploymentRegions(stackSetInstanceRegions, deploymentRegions []string) []string {
	var missingRegions []string
	for _, region := range deploymentRegions {
		if !contains(stackSetInstanceRegions, region) {
			missingRegions = append(missingRegions, region)
		}
	}
	return missingRegions
}
func getDeploymentRegionsToRemove(stackSetInstanceRegions, deploymentRegions []string) []string {
	var regionsToRemove []string
	for _, region := range stackSetInstanceRegions {
		if !contains(deploymentRegions, region) {
			regionsToRemove = append(regionsToRemove, region)
		}
	}
	return regionsToRemove
}

func waitForStackSetOperation(client *cloudformation.Client, stackSetName, operationID string, callAs cfTypes.CallAs) error {
	logger.Debugf("⏳ Waiting for StackSet '%s' operation '%s' to complete...", stackSetName, operationID)

	for {
		resp, err := client.DescribeStackSetOperation(context.TODO(), &cloudformation.DescribeStackSetOperationInput{
			StackSetName: aws.String(stackSetName),
			OperationId:  aws.String(operationID),
			CallAs:       callAs,
		})
		if err != nil {
			return fmt.Errorf("failed to get StackSet operation status: %w", err)
		}

		status := string(resp.StackSetOperation.Status)
		logger.Debugf("🔄 Current StackSet Operation Status: %s", status)

		// Exit loop if operation is complete
		if strings.EqualFold(status, "SUCCEEDED") {
			logger.Debugf("✅ StackSet Operation '%s' succeeded.", operationID)
			return nil
		} else if strings.EqualFold(status, "FAILED") {
			logger.Debugf("❌ StackSet Instance failed for StackSet %s.", stackSetName)
			return fmt.Errorf("stackset operation failed for StackSet %s. Please check the AWS CloudFormation logs for more details", stackSetName)
		}

		// Sleep before checking again
		time.Sleep(10 * time.Second)
	}
}

func createStackSetInstances(client *cloudformation.Client, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences, deploymentAccounts, deploymentRegions []string) error {
	deploymentTargetOUs := &cfTypes.DeploymentTargets{}
	var deploymentTargetAccounts []string
	if stackSetProps.PermissionModel == cfTypes.PermissionModelsSelfManaged {
		deploymentTargetAccounts = deploymentAccounts
	} else if stackSetProps.PermissionModel == cfTypes.PermissionModelsServiceManaged {
		deploymentTargetOUs = stackSetProps.DeploymentTargets
	}
	resp, err := client.CreateStackInstances(context.TODO(), &cloudformation.CreateStackInstancesInput{
		StackSetName:         aws.String(stackSetProps.StackSetName),
		Regions:              deploymentRegions,
		DeploymentTargets:    deploymentTargetOUs,
		Accounts:             deploymentTargetAccounts,
		OperationPreferences: stackSetOpsPreferences,
		CallAs:               stackSetProps.CallAs,
	})
	if err != nil {
		return fmt.Errorf("failed to create StackSet instances: %w", err)
	}
	logger.Debugf("🚀 StackSet instances for '%s' creation initiated.", stackSetProps.StackSetName)

	err = waitForStackSetOperation(client, stackSetProps.StackSetName, *resp.OperationId, stackSetProps.CallAs)
	if err != nil {
		return fmt.Errorf("stack instances creation failed: %w", err)
	}
	return nil
}

func deployStackSet(client *cloudformation.Client, automationAccountId, managementAccountId, cfgRegion string, params map[string]string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	var initialDeployment bool
	stackSetExists, err := checkIfStackSetExists(client, stackSetProps.StackSetName, stackSetProps.CallAs)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existence of CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
	}
	if !stackSetExists {
		err = createCloudFormationStackSet(automationAccountId, client, stackSetProps, params)
		if err != nil {
			return nil, fmt.Errorf("failed to create CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
		}
		initialDeployment = true
	}
	if !initialDeployment {
		err = updateCloudFormationStackSet(client, stackSetProps, stackSetOpsPreferences, params, automationAccountId)
		if err != nil {
			return nil, fmt.Errorf("failed to update CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
		}
	}
	var stackSetDeploymentRegions []string
	if !stackSetProps.IsMainRegionDeployment {
		stackSetDeploymentRegions = deploymentRegions
	} else {
		stackSetDeploymentRegions = append(stackSetDeploymentRegions, cfgRegion)
	}

	// only do the deployment if any account or region is missing or is in FAILED or CANCELLED state
	stackSetInstanceStateInfo, err := getFailedorCanceledorMissingStackSetInstances(client, managementAccountId, stackSetProps.StackSetName, stackSetProps.CallAs, deploymentTargetOUAccounts, stackSetDeploymentRegions)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existence of failed or cancelled or missing Instance for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
	}
	if stackSetInstanceStateInfo.FailedOrCanceled || len(stackSetInstanceStateInfo.AccountsToAdd) > 0 || len(stackSetInstanceStateInfo.RegionsToAdd) > 0 {
		err = createStackSetInstances(client, stackSetProps, stackSetOpsPreferences, deploymentAccounts, stackSetDeploymentRegions)
		if err != nil {
			return nil, fmt.Errorf("failed to create Instances for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
		}
	}
	return stackSetInstanceStateInfo, nil
}

func deleteStackSetInstances(cfClient *cloudformation.Client, stackSetName string, callAs cfTypes.CallAs, deploymentTargets *cfTypes.DeploymentTargets, deploymentRegions, deploymentAccounts []string, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) error {
	resp, err := cfClient.DeleteStackInstances(context.TODO(), &cloudformation.DeleteStackInstancesInput{
		StackSetName:         aws.String(stackSetName),
		Regions:              deploymentRegions,
		DeploymentTargets:    deploymentTargets,
		Accounts:             deploymentAccounts,
		OperationPreferences: stackSetOpsPreferences,
		CallAs:               callAs,
		RetainStacks:         aws.Bool(false), // Set to true to retain stacks, false to delete them
	})
	if err != nil {
		return fmt.Errorf("failed to delete StackSet instances: %w", err)
	}
	logger.Debugf("🚀 Deletion of StackSet instances for '%s' initiated.", stackSetName)

	err = waitForStackSetOperation(cfClient, stackSetName, *resp.OperationId, callAs)
	if err != nil {
		return fmt.Errorf("stack instances deletion failed: %w", err)
	}
	return nil
}

func getStackSetOUsAndRegions(client *cloudformation.Client, stackSetName string, callAs cfTypes.CallAs) ([]string, []string, error) {
	resp, err := client.DescribeStackSet(context.TODO(), &cloudformation.DescribeStackSetInput{
		StackSetName: aws.String(stackSetName),
		CallAs:       callAs,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to describe StackSet: %w", err)
	}
	if resp.StackSet == nil {
		return nil, nil, fmt.Errorf("StackSet %s does not have deployment targets", stackSetName)
	}
	return resp.StackSet.OrganizationalUnitIds, resp.StackSet.Regions, nil
}

func unique(input []string) []string {
	u := make(map[string]bool)
	var uniqueList []string
	for _, entry := range input {
		if _, ok := u[entry]; !ok {
			u[entry] = true
			uniqueList = append(uniqueList, entry)
		}
	}
	return uniqueList
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
