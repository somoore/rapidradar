package deploy

import (
	"fmt"
	"os"
	"rrcore/cmd/awshelper"
	"rrcore/cmd/awshelper/stacksets"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"rrcore/cmd/spinner"
	"rrcore/cmd/validator"
	"rrcore/cmd/yamlenv"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	cfTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"

	"github.com/spf13/cobra"
)

var yes bool
var envDirPath string
var configStackNamesPath string
var buildImage bool
var deployAllStacks bool
var deployLambdaLayers bool
var deployManagementAccountStack bool
var deployAutomationAccountStack bool
var deployOrgChildStackSet bool
var deploySSMDocumentStacks bool
var deployGuardDutyStackSets bool
var deployInspectorStackSets bool
var deploySecurityHubStackSets bool

var Cmd = &cobra.Command{
	Use:                   "deploy [flags]",
	Short:                 "Create/Update rapidradar deployment",
	Long:                  `Creates or updates RapidRadar deployment`,
	Args:                  cobra.NoArgs,
	DisableFlagsInUseLine: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if deployLambdaLayers || deployManagementAccountStack || deployAutomationAccountStack ||
			deployOrgChildStackSet || deploySSMDocumentStacks || deployGuardDutyStackSets ||
			deployInspectorStackSets || deploySecurityHubStackSets {
			deployAllStacks = false
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		workingDir := "cf"
		templatesDir := fmt.Sprintf("%s/templates", workingDir)
		packagedTemplatesDir := fmt.Sprintf("%s/.cloudformation", workingDir)
		lambdaLayersStackTemplatePath := fmt.Sprintf("%s/lambda-layers.yml", templatesDir)
		managementAccountStackTemplatePath := fmt.Sprintf("%s/management-account-stack.yml", templatesDir)
		ssmDocumentStackTemplatePath := fmt.Sprintf("%s/ssm-document.yml", templatesDir)
		automationDynamoDbTablesStackTemplatePath := fmt.Sprintf("%s/automation-dynamodb.yml", templatesDir)
		automationSecretsStackTemplatePath := fmt.Sprintf("%s/automation-secrets.yml", templatesDir)
		automationAccountStackTemplatePath := fmt.Sprintf("%s/main-stack.yml", templatesDir)
		vpcFlowLogsDeliveryKmsKeyStackSetTemplatePath := fmt.Sprintf("%s/stacksets/vpc-flowlogs/delivery-kms-key.yml", templatesDir)
		vpcFlowLogsDeliveryBucketStackSetTemplatePath := fmt.Sprintf("%s/stacksets/vpc-flowlogs/delivery-bucket.yml", templatesDir)
		cfStackSetAdministrationRoleTemplatePath := fmt.Sprintf("%s/stacksets/cloudformation/administration-role.yml", templatesDir)
		cfStackSetExecutionRoleTemplatePath := fmt.Sprintf("%s/stacksets/cloudformation/execution-role.yml", templatesDir)
		guardDutyDeliveryKmsKeyStackSetTemplatePath := fmt.Sprintf("%s/stacksets/guardduty/delivery-kms-key.yml", templatesDir)
		guardDutyDeliveryBucketStackSetTemplatePath := fmt.Sprintf("%s/stacksets/guardduty/delivery-bucket.yml", templatesDir)
		guardDutyAdminDelegationStackSetTemplatePath := fmt.Sprintf("%s/stacksets/guardduty/admin-delegation.yml", templatesDir)
		guardDutyEnablerStackSetTemplatePath := fmt.Sprintf("%s/stacksets/guardduty/enabler.yml", templatesDir)
		inspectorAdminDelegationStackSetTemplatePath := fmt.Sprintf("%s/stacksets/inspector/admin-delegation.yml", templatesDir)
		inspectorEnablerStackSetTemplatePath := fmt.Sprintf("%s/stacksets/inspector/enabler.yml", templatesDir)
		securityHubAdminDelegationStackSetTemplatePath := fmt.Sprintf("%s/stacksets/securityhub/admin-delegation.yml", templatesDir)
		securityHubEnablerStackSetTemplatePath := fmt.Sprintf("%s/stacksets/securityhub/enabler.yml", templatesDir)
		orgChildStackSetTemplatePath := fmt.Sprintf("%s/stacksets/child-accounts-stackset.yml", templatesDir)
		stackSetOperationPreferences := &cfTypes.StackSetOperationPreferences{
			RegionConcurrencyType:      cfTypes.RegionConcurrencyTypeParallel,
			MaxConcurrentPercentage:    aws.Int32(100),
			FailureTolerancePercentage: aws.Int32(10),
		}

		spinner.Push("🚀 Starting Deployment...")
		logger.Debugf("...Loading all env vars from %s yml files\n", envDirPath)

		// Loads all env vars from yaml files
		ssmNamesMap, secretNamesMap, notificationsConfigSecretNamesMap, err := yamlenv.LoadAllEnvVars(envDirPath)
		if err != nil {
			logger.Fatalf("Failed to load all env vars from %s*.yml files: %v", envDirPath, err)
			panic(err)
		}
		deploymentTargets := strings.Split(os.Getenv("DeploymentTargets"), ",")
		excludedAccounts := strings.Split(os.Getenv("ExcludeAccounts"), ",")
		deploymentRegions := strings.Split(os.Getenv("ActiveRegions"), ",")

		// Validate parameters
		spinner.Pause()
		validator.ValidateParameters(deploymentTargets)
		spinner.Resume()
		deploymentTargetsType, isStandaloneDeployment := helper.GetDeploymentTargetsType(deploymentTargets)

		// Panic if ProjectName does not exist
		projectName := os.Getenv("ProjectName")
		if helper.IsValEmpty(projectName) {
			helper.GetNonEmptyInput("ProjectName", projectName)
		}
		projectName = os.Getenv("ProjectName")

		// Loads all stacks names from config/yml file
		stackNames, err := yamlenv.LoadAllStackNames(configStackNamesPath)
		if err != nil {
			logger.Fatalf("Failed to load all Stacks and StackSets names from %s file: %v", configStackNamesPath, err)
			panic(err)
		}

		// Ask if we should proceed deployment with the given ProjectName
		spinner.Stop()
		logger.Warnf("NOTE: Prefix for all the resources will be %s", projectName)
		var proceed bool
		if yes {
			proceed = true
		} else {
			proceed = helper.Confirm(true, "Do you want to proceed and start deployment?")
		}
		if proceed {
			spinner.Push("...Checking AWS Profiles")
			orgMetadata, err := awshelper.GetAWSAccountDetails(stackNames.AutomationAccountStackName)
			if err != nil {
				logger.Fatalf("Failed to get metadata from current Organization: %v", err)
				panic(err)
			}
			// Get AccountsOUs if DeploymentTargets are standalone accounts
			var standaloneAcountsOUIds []string
			if isStandaloneDeployment {
				standaloneAcountsOUIds, err = awshelper.GetOUIdsforAccounts(orgMetadata.ManagementAccountProfileName, deploymentTargets)
				if err != nil {
					logger.Fatalf("Failed to get OU IDs of AWS accounts in DeploymentTargets: %v", err)
					panic(err)
				}
			}

			// Get all active AWS accounts and OU Ids from deployment targets OUs
			allOUActiveAccounts, err := awshelper.GetAllOUActiveAccounts(orgMetadata.ManagementAccountProfileName, deploymentTargetsType, orgMetadata.ManagementAccountId, deploymentTargets, excludedAccounts)
			if err != nil {
				logger.Fatalf("Failed to get all active AWS accounts of DeploymentTargets: %v", err)
				panic(err)
			}
			ssoRolePermissionAccounts := awshelper.GetSSORolePermissionAccounts(allOUActiveAccounts, orgMetadata)
			deploymentAccountsOUIds, err := awshelper.GetOUIdsforAccounts(orgMetadata.ManagementAccountProfileName, ssoRolePermissionAccounts)
			if err != nil {
				logger.Fatalf("Failed to get OU IDs of AWS accounts in DeploymentTargets: %v", err)
				panic(err)
			}
			spinner.Stop()

			// Setting deployment targets and accounts for VPC flow logs StackSets
			flowLogsAdminAccountId := ""
			if !helper.IsValEmpty(orgMetadata.LogArchiveAccountId) {
				flowLogsAdminAccountId = orgMetadata.AutomationAccountId
			}

			// Variables to store state info of All CloudFormation StackSets and other information
			automationEventBusName := fmt.Sprintf("%s-eventbus", projectName)
			crossAccountRole := fmt.Sprintf("%s-cross-account-role", projectName)
			slackActionsCrossAccountRole := fmt.Sprintf("%s-slack-cross-account-role", projectName)
			userOffboardingWorkflowEcrRepoName := fmt.Sprintf("%s-sso-user-generate-reports", projectName)
			slackSocketAppEcrRepoName := fmt.Sprintf("%s-slack-socket-app", projectName)
			policyDocumentSSMParameterName := fmt.Sprintf("/%s/post-deploy/POLICY_JSON", projectName)
			ssmDocumentSSMParameterName := fmt.Sprintf("/%s/ssm-document/JSON_CONTENT", projectName)
			templatesS3BucketName := fmt.Sprintf("%s-artifacts-%s", projectName, orgMetadata.AutomationAccountId)
			managementAccountTemplatesS3BucketName := fmt.Sprintf("%s-artifacts-%s", projectName, orgMetadata.ManagementAccountId)
			userOffboardingWorkflowEcrImageURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:latest", orgMetadata.AutomationAccountId, orgMetadata.AutomationAccountRegion, userOffboardingWorkflowEcrRepoName)
			slackSocketAppEcrImageURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:latest", orgMetadata.AutomationAccountId, orgMetadata.AutomationAccountRegion, slackSocketAppEcrRepoName)
			requireGuardDutyCentralLoggingBucket := helper.RequireGuardDutyCentralLoggingBucket(deploymentRegions)
			cfStackSetExecutionRoleStackSetProps := stacksets.GetCfStackSetExecutionRoleStackSetConfig(orgMetadata, stackNames.CfStackSetExecutionRoleStackSetName, cfStackSetExecutionRoleTemplatePath, "", flowLogsAdminAccountId, isStandaloneDeployment, deploymentTargets, excludedAccounts, standaloneAcountsOUIds, deploymentAccountsOUIds)
			cfStackSetExecutionRoleStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			vpcFlowLogsDeliveryKmsKeyStackSetProps := stacksets.GetVpcFlowLogsStackSetsConfig(orgMetadata, stackNames.VpcFlowLogsDeliveryKmsKeyStackSetName, vpcFlowLogsDeliveryKmsKeyStackSetTemplatePath, "", isStandaloneDeployment, true, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			vpcFlowLogsDeliveryKmsKeyStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			vpcFlowLogsDeliveryBucketStackSetProps := stacksets.GetVpcFlowLogsStackSetsConfig(orgMetadata, stackNames.VpcFlowLogsDeliveryBucketStackSetName, vpcFlowLogsDeliveryBucketStackSetTemplatePath, "", isStandaloneDeployment, true, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			vpcFlowLogsDeliveryBucketStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			guardDutyDeliveryKmsKeyStackSetProps := stacksets.GetGuardDutyKmsKeyStackSetConfig(orgMetadata, stackNames.GuardDutyDeliveryKmsKeyStackSetName, guardDutyDeliveryKmsKeyStackSetTemplatePath, "", isStandaloneDeployment, true, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			guardDutyDeliveryKmsKeyStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			guardDutyDeliveryBucketStackSetProps := stacksets.GetGuardDutyBucketStackSetConfig(orgMetadata, stackNames.GuardDutyDeliveryBucketStackSetName, guardDutyDeliveryBucketStackSetTemplatePath, "", isStandaloneDeployment, true, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			guardDutyDeliveryBucketStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			guardDutyAdminDelegationStackSetProps := stacksets.GetGuardDutyAdminDelegationStackSetConfig(orgMetadata, stackNames.GuardDutyAdminDelegationStackSetName, guardDutyAdminDelegationStackSetTemplatePath, "", isStandaloneDeployment, false, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			guardDutyAdminDelegationStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			guardDutyEnablerStackSetProps := stacksets.GetGuardDutyEnablerStackSetConfig(orgMetadata, stackNames.GuardDutyEnablerStackSetName, guardDutyEnablerStackSetTemplatePath, "", isStandaloneDeployment, false, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			guardDutyEnablerStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			inspectorAdminDelegationStackSetProps := stacksets.GetInspectorAdminDelegationStackSetConfig(orgMetadata, stackNames.InspectorAdminDelegationStackSetName, inspectorAdminDelegationStackSetTemplatePath, "", isStandaloneDeployment, false, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			inspectorAdminDelegationStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			inspectorEnablerStackSetProps := stacksets.GetInspectorEnablerStackSetConfig(orgMetadata, stackNames.InspectorEnablerStackSetName, inspectorEnablerStackSetTemplatePath, "", isStandaloneDeployment, false, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			inspectorEnablerStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			securityHubAdminDelegationStackSetProps := stacksets.GetSecurityHubAdminDelegationStackSetConfig(orgMetadata, stackNames.SecurityHubAdminDelegationStackSetName, securityHubAdminDelegationStackSetTemplatePath, "", isStandaloneDeployment, false, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			securityHubAdminDelegationStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			securityHubEnablerStackSetProps := stacksets.GetSecurityHubEnablerStackSetConfig(orgMetadata, stackNames.SecurityHubEnablerStackSetName, securityHubEnablerStackSetTemplatePath, "", isStandaloneDeployment, false, deploymentTargets, excludedAccounts, standaloneAcountsOUIds)
			securityHubEnablerStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			orgChildStackSetProps := stacksets.GetOrgChildStackSetConfig(orgMetadata, stackNames.OrgChildStackSetName, orgChildStackSetTemplatePath, "", isStandaloneDeployment, false, deploymentTargets, excludedAccounts)
			orgChildStackSetInfo := &awshelper.StackSetInstanceStateInfo{}
			var ssmDocumentName string

			// Check if provided email addresses are added as SES Identities
			spinner.Push("...Checking if emails are added as SES Identities")
			awshelper.EmailsAddedAsSESIdentity(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId)
			spinner.Stop()

			// Creates required SecretsManager secrets if chosen to
			spinner.Push("...Checking if required SecretsManager secrets exist")
			for secretName, configSecretDetails := range notificationsConfigSecretNamesMap {
				logger.Debugf("...Handling Notification Configuration secret named '%s'", secretName)
				configSecretDetailsMap := configSecretDetails.(map[string]any)
				notificationType := configSecretDetailsMap["NotificationType"].(string)
				notificationsAppCfKey := configSecretDetailsMap["NotificationAppCfKey"].(string)
				notificationsConfigDependentKeys := configSecretDetailsMap["DependentSecrets"].(map[string]map[string]string)

				err = awshelper.NotificationsConfigSecretsHandler(orgMetadata.AutomationAccountProfileName, secretName, notificationType, notificationsAppCfKey, notificationsConfigDependentKeys)
				if err != nil {
					logger.Fatalf("Failed to create SecretsManager Secret %s: %v", secretName, err)
					panic(err)
				}
			}
			for secretName, secretDetails := range secretNamesMap {
				logger.Debugf("...Handling SecretsManager secret named '%s'", secretName)
				secretDetailsMap := secretDetails.(map[string]any)
				secretCfKey := secretDetailsMap["CfKey"].(string)
				for secretDesc, secretDependentKeys := range secretDetailsMap["DependentSecrets"].(map[string]map[string]string) {
					secretCreated, err := awshelper.SecretsHandler(orgMetadata.AutomationAccountProfileName, secretCfKey, secretName, secretDesc, secretDependentKeys)
					if err != nil {
						logger.Fatalf("Failed to create SecretsManager Secret %s: %v", secretName, err)
						panic(err)
					}
					// #nosec G101 -- CloudFormation secret logical key, not a credential value.
					if !secretCreated && secretCfKey == "SlackBotConfigSecretName" {
						spinner.Pause()
						logger.Warnf("You chose not to create SecretsManager secret '%s'. Slack Interactive alerts will be disabled.", secretName)
						if err := os.Setenv(secretCfKey, ""); err != nil {
							logger.Fatalf("Failed to clear Slack bot config env var: %v", err)
						}
						spinner.Resume()
					}
				}
			}
			spinner.Stop()

			// Creates required SSM secrets if chosen to
			spinner.Push("...Checking if required secrets exist as SSM Parameters")
			for ssmName, ssmLong := range ssmNamesMap {
				logger.Debugf("...Handling SSM parameter named '%s'", ssmName)
				err = awshelper.SSMParameterHandler(orgMetadata.AutomationAccountProfileName, ssmName, ssmLong)
				if err != nil {
					logger.Fatalf("Failed to create SSM Parameter %s: %v", ssmName, err)
					panic(err)
				}
			}
			spinner.Stop()

			// Install lambda layer packages
			if deployAllStacks || deployLambdaLayers {
				spinner.Push("...Installing lambda layers packages")
				err = helper.InstallLayerPackages(packagedTemplatesDir, fmt.Sprintf("%s/deployment/requirements.txt", workingDir))
				if err != nil {
					logger.Fatalf("Failed to install lambda layers packages: %v", err)
				}
				spinner.Stop()
			}

			// Create CfStackSetAdministrationRoleStack if not exists
			if deployAllStacks {
				spinner.Push(fmt.Sprintf("...Deploying %s CloudFormation Stack", stackNames.CfStackSetAdministrationRoleStackName))
				err = awshelper.DeployCfStackSetAdministrationRoleStack(orgMetadata.AutomationAccountProfileName, stackNames.CfStackSetAdministrationRoleStackName, cfStackSetAdministrationRoleTemplatePath)
				if err != nil {
					logger.Fatalf("failed to deploy Cloudformation Stack %s: %v", stackNames.CfStackSetAdministrationRoleStackName, err)
				}
				spinner.Stop()
				logger.SuccessMessagef("%s Stack deployed ✅", stackNames.CfStackSetAdministrationRoleStackName)
			}

			// Create CfStackSetExecutionRoleStackSet if asked to
			cfStackSetExecutionRoleCreation, err := strconv.ParseBool(os.Getenv("CfStackSetExecutionRoleCreation"))
			if err != nil {
				logger.Fatalf("failed to parse boolean CfStackSetExecutionRoleCreation: %v", err)
			}
			if cfStackSetExecutionRoleCreation && deployAllStacks {
				spinner.Push(fmt.Sprintf("...Deploying %s CloudFormation StackSet", stackNames.CfStackSetExecutionRoleStackSetName))
				cfStackSetExecutionRoleStackSetInfo, err = awshelper.DeployCfStackSetExecutionRoleStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, deploymentRegions, ssoRolePermissionAccounts, ssoRolePermissionAccounts, cfStackSetExecutionRoleStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", cfStackSetExecutionRoleStackSetProps.StackSetName, err)
				}
				spinner.Stop()
				logger.SuccessMessagef("%s StackSet deployed ✅", stackNames.CfStackSetExecutionRoleStackSetName)
			}

			// Deploys Lambda layers
			if deployAllStacks || deployLambdaLayers {
				spinner.Push("...Deploying Stacks for Lambda Layers in each region")
				err = awshelper.DeployLambdaLayersStack(deploymentRegions, orgMetadata.AutomationAccountProfileName, stackNames.LambdaLayersStackName, templatesS3BucketName, lambdaLayersStackTemplatePath, packagedTemplatesDir, orgMetadata.OrganizationId)
				if err != nil {
					logger.Fatalf("failed to deploy Cloudformation Stack %s: %v", stackNames.LambdaLayersStackName, err)
				}
				spinner.Stop()
				logger.SuccessMessageln("Stacks for Lambda Layers deployed ✅")
			}

			// Deploys Management Account stack
			if deployAllStacks || deployManagementAccountStack {
				spinner.Push(fmt.Sprintf("...Deploying %s CloudFormation Stack", stackNames.ManagementAccountStackName))
				err = awshelper.DeployManagementAccountStack(orgMetadata.ManagementAccountProfileName, stackNames.ManagementAccountStackName, managementAccountTemplatesS3BucketName, managementAccountStackTemplatePath, orgMetadata.OrganizationId, orgMetadata.AutomationAccountId, automationEventBusName, ssoRolePermissionAccounts)
				if err != nil {
					logger.Fatalf("failed to deploy Cloudformation Stack %s: %v", stackNames.ManagementAccountStackName, err)
				}
				spinner.Stop()
				logger.SuccessMessagef("%s Stack deployed ✅", stackNames.ManagementAccountStackName)
			}

			// Create resources needed for User Offboarding Workflow
			addSupportforUserOffboardingWorkflow, err := strconv.ParseBool(os.Getenv("AddSupportforUserOffboardingWorkflow"))
			if err != nil {
				logger.Fatalf("failed to parse boolean AddSupportforUserOffboardingWorkflow: %v", err)
			}
			if addSupportforUserOffboardingWorkflow {
				err = awshelper.CreateEcrRepoIfNotExists(orgMetadata.AutomationAccountProfileName, userOffboardingWorkflowEcrRepoName)
				if err != nil {
					logger.Fatalf("failed to create ECR Repo for User Offboarding Workflow: %v", err)
				}
				imageExistsInECR, err := awshelper.ImageExistsInECR(orgMetadata.AutomationAccountProfileName, userOffboardingWorkflowEcrRepoName, userOffboardingWorkflowEcrImageURI)
				if err != nil {
					logger.Fatalf("failed to check if image already exists in ECR Repo for User Offboarding Workflow: %v", err)
				}
				if buildImage || !imageExistsInECR {
					spinner.Push(fmt.Sprintf("...Building and Pushing Image to AWS ECR Repository %s", userOffboardingWorkflowEcrRepoName))
					err = awshelper.BuildAndPushDockerImage(orgMetadata.AutomationAccountProfileName, userOffboardingWorkflowEcrRepoName, userOffboardingWorkflowEcrImageURI, fmt.Sprintf("%s/deployment/sfn/sso_manager/build/", workingDir), orgMetadata.AutomationAccountId, orgMetadata.AutomationAccountRegion)
					if err != nil {
						logger.Fatalf("failed to build and push docker image to AWS ECR: %v", err)
					}
					spinner.Stop()
				}
			}

			// Create resources needed for Slack app socket mode (if enabled)
			enableSlackSocketMode, err := strconv.ParseBool(os.Getenv("EnableSlackSocketMode"))
			if err != nil {
				logger.Fatalf("failed to parse boolean EnableSlackSocketMode: %v", err)
			}
			if enableSlackSocketMode {
				err = awshelper.CreateEcrRepoIfNotExists(orgMetadata.AutomationAccountProfileName, slackSocketAppEcrRepoName)
				if err != nil {
					logger.Fatalf("failed to create ECR Repo for Slack Socket App: %v", err)
				}
				imageExistsInECR, err := awshelper.ImageExistsInECR(orgMetadata.AutomationAccountProfileName, slackSocketAppEcrRepoName, slackSocketAppEcrImageURI)
				if err != nil {
					logger.Fatalf("failed to check if image already exists in ECR Repo for Slack Socket App: %v", err)
				}
				if buildImage || !imageExistsInECR {
					spinner.Push(fmt.Sprintf("...Building and Pushing Image to AWS ECR Repository %s", slackSocketAppEcrRepoName))
					err = awshelper.BuildAndPushDockerImage(orgMetadata.AutomationAccountProfileName, slackSocketAppEcrRepoName, slackSocketAppEcrImageURI, fmt.Sprintf("%s/deployment/slack_socket_app/", workingDir), orgMetadata.AutomationAccountId, orgMetadata.AutomationAccountRegion)
					if err != nil {
						logger.Fatalf("failed to build and push docker image to AWS ECR: %v", err)
					}
					spinner.Stop()
				}
			}

			// Deploys VPC Flow Logs StackSets if enabled
			enableVpcFlowLogs, err := strconv.ParseBool(os.Getenv("EnableVpcFlowLogs"))
			if err != nil {
				logger.Fatalf("failed to parse boolean EnableVpcFlowLogs: %v", err)
			}
			if deployAllStacks {
				if enableVpcFlowLogs {
					spinner.Push("...Deploying CloudFormation StackSets required to enable VPC Flow Logs")
					vpcFlowLogsDeliveryKmsKeyStackSetInfo, err = awshelper.DeployVpcFlowLogsDeliveryKmsKeyStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, deploymentRegions, []string{flowLogsAdminAccountId}, allOUActiveAccounts, vpcFlowLogsDeliveryKmsKeyStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.VpcFlowLogsDeliveryKmsKeyStackSetName, err)
					}
					vpcFlowLogsDeliveryBucketStackSetInfo, err = awshelper.DeployVpcFlowLogsDeliveryBucketStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, flowLogsAdminAccountId, deploymentRegions, []string{orgMetadata.LogArchiveAccountId}, allOUActiveAccounts, vpcFlowLogsDeliveryBucketStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.VpcFlowLogsDeliveryBucketStackSetName, err)
					}
					spinner.Stop()
					logger.SuccessMessageln("VPC Flow Logs StackSets deployed ✅")
				} else {
					spinner.Push("...Cleaning up CloudFormation StackSets for VPC Flow Logs if was enabled in previous deployment")
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, vpcFlowLogsDeliveryBucketStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.VpcFlowLogsDeliveryBucketStackSetName, err)
					}
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, vpcFlowLogsDeliveryKmsKeyStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.VpcFlowLogsDeliveryKmsKeyStackSetName, err)
					}
					spinner.Stop()
				}
			}

			// Deploys GuardDuty StackSets if enabled
			enableGuardDuty, err := strconv.ParseBool(os.Getenv("EnableGuardDuty"))
			if err != nil {
				logger.Fatalf("failed to parse boolean EnableGuardDuty: %v", err)
			}
			if deployAllStacks || deployGuardDutyStackSets {
				if enableGuardDuty {
					spinner.Push("...Deploying CloudFormation StackSets required to enable GuardDuty")
					var guardDutyDeliveryKmsKeyStackSetDeploymentTargetOUAccounts []string
					if !helper.IsValEmpty(orgMetadata.GuardDutyAdminAccountId) {
						guardDutyDeliveryKmsKeyStackSetDeploymentTargetOUAccounts = []string{orgMetadata.GuardDutyAdminAccountId}
					} else {
						guardDutyDeliveryKmsKeyStackSetDeploymentTargetOUAccounts = allOUActiveAccounts
					}
					guardDutyDeliveryKmsKeyStackSetInfo, err = awshelper.DeployGuardDutyDeliveryKmsKeyStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, deploymentRegions, []string{orgMetadata.GuardDutyAdminAccountId}, guardDutyDeliveryKmsKeyStackSetDeploymentTargetOUAccounts, guardDutyDeliveryKmsKeyStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.GuardDutyDeliveryKmsKeyStackSetName, err)
					}
					var guardDutyDeliveryBucketStackSetTargetAccount string
					if !helper.IsValEmpty(orgMetadata.LogArchiveAccountId) {
						guardDutyDeliveryBucketStackSetTargetAccount = orgMetadata.LogArchiveAccountId
					} else {
						guardDutyDeliveryBucketStackSetTargetAccount = orgMetadata.GuardDutyAdminAccountId
					}
					guardDutyDeliveryBucketStackSetInfo, err = awshelper.DeployGuardDutyDeliveryBucketStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, deploymentRegions, []string{guardDutyDeliveryBucketStackSetTargetAccount}, []string{guardDutyDeliveryBucketStackSetTargetAccount}, guardDutyDeliveryBucketStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.GuardDutyDeliveryBucketStackSetName, err)
					}
					var guardDutyEnablerStackSetDeploymentTargetOUAccounts []string
					if !helper.IsValEmpty(orgMetadata.GuardDutyAdminAccountId) {
						guardDutyEnablerStackSetDeploymentTargetOUAccounts = []string{orgMetadata.GuardDutyAdminAccountId}
						guardDutyAdminDelegationStackSetInfo, err = awshelper.DeployGuardDutyAdminDelegationStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, deploymentRegions, []string{orgMetadata.ManagementAccountId}, []string{orgMetadata.ManagementAccountId}, guardDutyAdminDelegationStackSetProps, stackSetOperationPreferences)
						if err != nil {
							logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.GuardDutyAdminDelegationStackSetName, err)
						}
					} else {
						guardDutyEnablerStackSetDeploymentTargetOUAccounts = allOUActiveAccounts
					}
					guardDutyEnablerStackSetInfo, err = awshelper.DeployGuardDutyEnablerStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, automationEventBusName, requireGuardDutyCentralLoggingBucket, deploymentRegions, []string{orgMetadata.GuardDutyAdminAccountId}, guardDutyEnablerStackSetDeploymentTargetOUAccounts, guardDutyEnablerStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.GuardDutyEnablerStackSetName, err)
					}
					spinner.Stop()
					logger.SuccessMessageln("GuardDuty StackSets deployed ✅")
				} else {
					spinner.Push("...Cleaning up CloudFormation StackSets for GuardDuty if was enabled in previous deployment")
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, guardDutyEnablerStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.GuardDutyEnablerStackSetName, err)
					}
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, guardDutyAdminDelegationStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.GuardDutyAdminDelegationStackSetName, err)
					}
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, guardDutyDeliveryBucketStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.GuardDutyDeliveryBucketStackSetName, err)
					}
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, guardDutyDeliveryKmsKeyStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.GuardDutyDeliveryKmsKeyStackSetName, err)
					}
					spinner.Stop()
				}
			}

			// Deploys Inspector StackSets if enabled
			enableInspector, err := strconv.ParseBool(os.Getenv("EnableInspector2"))
			if err != nil {
				logger.Fatalf("failed to parse boolean EnableInspector2: %v", err)
			}
			if deployAllStacks || deployInspectorStackSets {
				if enableInspector {
					spinner.Push("...Deploying CloudFormation StackSets required to enable Inspector")
					var inspectorEnablerStackSetDeploymentTargetOUAccounts []string
					if !helper.IsValEmpty(orgMetadata.InspectorAdminAccountId) {
						inspectorEnablerStackSetDeploymentTargetOUAccounts = []string{orgMetadata.GuardDutyAdminAccountId}
						inspectorAdminDelegationStackSetInfo, err = awshelper.DeployInspectorAdminDelegationStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, deploymentRegions, []string{orgMetadata.ManagementAccountId}, []string{orgMetadata.ManagementAccountId}, inspectorAdminDelegationStackSetProps, stackSetOperationPreferences)
						if err != nil {
							logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.InspectorAdminDelegationStackSetName, err)
						}
					} else {
						inspectorEnablerStackSetDeploymentTargetOUAccounts = allOUActiveAccounts
					}
					inspectorEnablerStackSetInfo, err = awshelper.DeployInspectorEnablerStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, deploymentRegions, []string{orgMetadata.GuardDutyAdminAccountId}, inspectorEnablerStackSetDeploymentTargetOUAccounts, inspectorEnablerStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.InspectorEnablerStackSetName, err)
					}
					spinner.Stop()
					logger.SuccessMessageln("Inspector StackSets deployed ✅")
				} else {
					spinner.Push("...Cleaning up CloudFormation StackSets for Inspector if was enabled in previous deployment")
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, inspectorEnablerStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.InspectorEnablerStackSetName, err)
					}
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, inspectorAdminDelegationStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.InspectorAdminDelegationStackSetName, err)
					}
					spinner.Stop()
				}
			}

			// Deploys SecurityHub StackSets if enabled
			enableSecurityHub, err := strconv.ParseBool(os.Getenv("EnableSecurityHub"))
			if err != nil {
				logger.Fatalf("failed to parse boolean EnableSecurityHub: %v", err)
			}
			if deployAllStacks || deploySecurityHubStackSets {
				if enableSecurityHub {
					spinner.Push("...Deploying CloudFormation StackSets required to enable SecurityHub")
					var securityHubEnablerStackSetDeploymentTargetOUAccounts []string
					if !helper.IsValEmpty(orgMetadata.SecurityHubAdminAccountId) {
						securityHubEnablerStackSetDeploymentTargetOUAccounts = []string{orgMetadata.SecurityHubAdminAccountId}
						securityHubAdminDelegationStackSetInfo, err = awshelper.DeploySecurityHubAdminDelegationStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, deploymentRegions, []string{orgMetadata.ManagementAccountId}, []string{orgMetadata.ManagementAccountId}, securityHubAdminDelegationStackSetProps, stackSetOperationPreferences)
						if err != nil {
							logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.SecurityHubAdminDelegationStackSetName, err)
						}
					} else {
						securityHubEnablerStackSetDeploymentTargetOUAccounts = allOUActiveAccounts
					}
					securityHubEnablerStackSetInfo, err = awshelper.DeploySecurityHubEnablerStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, deploymentRegions, []string{orgMetadata.SecurityHubAdminAccountId}, securityHubEnablerStackSetDeploymentTargetOUAccounts, securityHubEnablerStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.SecurityHubEnablerStackSetName, err)
					}
					spinner.Stop()
					logger.SuccessMessageln("SecurityHub StackSets deployed ✅")
				} else {
					spinner.Push("...Cleaning up CloudFormation StackSets for SecurityHub if was enabled in previous deployment")
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, securityHubEnablerStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.SecurityHubEnablerStackSetName, err)
					}
					err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, securityHubAdminDelegationStackSetProps, stackSetOperationPreferences)
					if err != nil {
						logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.SecurityHubAdminDelegationStackSetName, err)
					}
					spinner.Stop()
				}
			}

			// Deploys SSM Document Stacks
			enableEC2InstanceConfigurator, err := strconv.ParseBool(os.Getenv("EnableEC2InstanceConfigurator"))
			if err != nil {
				logger.Fatalf("failed to parse boolean EnableEC2InstanceConfigurator: %v", err)
			}
			if deployAllStacks || deploySSMDocumentStacks {
				if enableEC2InstanceConfigurator {
					spinner.Push("...Deploying Stacks for SSM Document in each region")
					err = awshelper.DeploySSMDocumentStacks(deploymentRegions, orgMetadata.AutomationAccountProfileName, stackNames.SSMDocumentStackName, ssmDocumentStackTemplatePath, orgMetadata.ManagementAccountId, ssmDocumentSSMParameterName)
					if err != nil {
						logger.Fatalf("failed to deploy Cloudformation Stacks for SSM Document: %v", err)
					}
					spinner.Stop()
					logger.SuccessMessageln("Stacks for SSM Document deployed ✅")

					ssmDocumentName, err = awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.SSMDocumentStackName, "SSMDocumentName")
					if err != nil {
						logger.Fatalf("failed to get output of SSMDocumentName from CloudFormation Stack %s: %v", stackNames.SSMDocumentStackName, err)
					}
				}
			}

			// Deploys Automation Account Stack
			if deployAllStacks || deployAutomationAccountStack {
				spinner.Push("...Deploying CloudFormation Stacks for Automation Account")
				err = awshelper.DeployAutomationAccountDynamoDbTablesStack(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, templatesS3BucketName, automationDynamoDbTablesStackTemplatePath)
				if err != nil {
					logger.Fatalf("failed to deploy Cloudformation Stack %s: %v", stackNames.AutomationDynamoDbTablesStackName, err)
				}
				securityGroupTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "SecurityGroupTableName")
				iamUsersTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "IAMUsersTableName")
				s3BucketsTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "S3BucketsTableName")
				rootIAMLoginsTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "RootIAMLoginsTableName")
				unusedEC2InstancesTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "UnusedEC2InstancesTableName")
				unusedSecurityGroupsTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "UnusedSecurityGroupsTableName")
				unusedEBSVolumesTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "UnusedEBSVolumesTableName")
				remediatedResourcesTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "RemediatedResourcesTableName")
				activeResourcesTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "ActiveResourcesTableName")
				deletedResourcesTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "DeletedResourcesTableName")
				dailyUserCostReportsTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "DailyUserCostReportsTableName")
				weeklyUserCostReportsTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "WeeklyUserCostReportsTableName")
				monthlyUserCostReportsTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "MonthlyUserCostReportsTableName")
				ipCorrelationTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "IPCorrelationTableName")
				ssoUserIPHistoryTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "SSOUserIPHistoryTableName")
				iamKeyPairAccessTrackerTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "IAMKeyPairAccessTrackerTableName")
				ssmDocumentAssociationFailureTrackerTableName, _ := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationDynamoDbTablesStackName, "SSMDocumentAssociationFailureTrackerTableName")

				err = awshelper.DeployAutomationAccountSecretsStack(
					orgMetadata.AutomationAccountProfileName,
					stackNames.AutomationAccountSecretsStackName,
					templatesS3BucketName,
					automationSecretsStackTemplatePath,
					orgMetadata.ManagementAccountId,
					ssmDocumentName,
					securityGroupTableName,
					iamUsersTableName,
					s3BucketsTableName,
					rootIAMLoginsTableName,
					unusedEC2InstancesTableName,
					unusedSecurityGroupsTableName,
					unusedEBSVolumesTableName,
					remediatedResourcesTableName,
					activeResourcesTableName,
					deletedResourcesTableName,
					dailyUserCostReportsTableName,
					weeklyUserCostReportsTableName,
					monthlyUserCostReportsTableName,
					ipCorrelationTableName,
					ssoUserIPHistoryTableName,
					iamKeyPairAccessTrackerTableName,
					ssmDocumentAssociationFailureTrackerTableName)
				if err != nil {
					logger.Fatalf("failed to deploy Cloudformation Stack %s: %v", stackNames.AutomationAccountSecretsStackName, err)
				}
				ssoUsersSecretName, err := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationAccountSecretsStackName, "SSOUsersSecretName")
				if err != nil {
					logger.Debugf("SSOUsersSecretName output does not exist in stack outputs of CloudFormation Stack %s: %v", stackNames.AutomationAccountSecretsStackName, err)
				}
				eventsProcessorLambdaEnvVarsSecretName, err := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationAccountSecretsStackName, "EventsProcessorLambdaEnvVarsSecretName")
				if err != nil {
					logger.Debugf("EventsProcessorLambdaEnvVarsSecretName output does not exist in stack outputs of CloudFormation Stack %s: %v", stackNames.AutomationAccountSecretsStackName, err)
				}
				err = awshelper.DeployAutomationAccountStack(
					orgMetadata.AutomationAccountProfileName,
					stackNames.AutomationAccountStackName,
					templatesS3BucketName,
					automationAccountStackTemplatePath,
					packagedTemplatesDir,
					orgMetadata.OrganizationId,
					crossAccountRole,
					slackActionsCrossAccountRole,
					orgMetadata.ManagementAccountId,
					stackNames.OrgChildStackSetName,
					userOffboardingWorkflowEcrImageURI,
					slackSocketAppEcrImageURI,
					policyDocumentSSMParameterName,
					ssoUsersSecretName,
					eventsProcessorLambdaEnvVarsSecretName,
					securityGroupTableName,
					iamUsersTableName,
					s3BucketsTableName,
					rootIAMLoginsTableName,
					unusedEC2InstancesTableName,
					unusedSecurityGroupsTableName,
					unusedEBSVolumesTableName,
					remediatedResourcesTableName,
					activeResourcesTableName,
					deletedResourcesTableName,
					dailyUserCostReportsTableName,
					weeklyUserCostReportsTableName,
					monthlyUserCostReportsTableName,
					ipCorrelationTableName,
					ssoUserIPHistoryTableName,
					iamKeyPairAccessTrackerTableName,
					ssmDocumentAssociationFailureTrackerTableName,
				)
				if err != nil {
					logger.Fatalf("failed to deploy Cloudformation Stack %s: %v", stackNames.AutomationAccountStackName, err)
				}
				spinner.Stop()
				logger.SuccessMessageln("Automation Account Stacks deployed ✅")
			}
			stepFunctionExecutorLambdaARN, err := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationAccountStackName, "StepFunctionExecutorLambdaARN")
			if err != nil {
				logger.Debugf("StepFunctionExecutorLambdaARN output does not exist in stack outputs of CloudFormation Stack %s: %v", stackNames.AutomationAccountStackName, err)
			}
			captureExistingResourcesSfnARN, err := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationAccountStackName, "CaptureExistingResourcesSfnARN")
			if err != nil {
				logger.Debugf("CaptureExistingResourcesSfnARN output does not exist in stack outputs of CloudFormation Stack %s: %v", stackNames.AutomationAccountStackName, err)
			}
			autoTaggerSfnARN, err := awshelper.GetStackOutput(orgMetadata.AutomationAccountProfileName, stackNames.AutomationAccountStackName, "AutoTaggerSfnARN")
			if err != nil {
				logger.Debugf("AutoTaggerSfnARN output does not exist in stack outputs of CloudFormation Stack %s: %v", stackNames.AutomationAccountStackName, err)
			}

			// Deploys Org Child Accounts StackSet
			if deployAllStacks || deployOrgChildStackSet {
				spinner.Push(fmt.Sprintf("...Deploying %s CloudFormation StackSet", stackNames.OrgChildStackSetName))
				orgChildStackSetInfo, err = awshelper.DeployOrgChildStackSet(orgMetadata.AutomationAccountProfileName, orgMetadata.AutomationAccountId, orgMetadata.ManagementAccountId, automationEventBusName, ssmDocumentName, stepFunctionExecutorLambdaARN, captureExistingResourcesSfnARN, autoTaggerSfnARN, deploymentRegions, []string{}, allOUActiveAccounts, orgChildStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to deploy Cloudformation StackSet %s: %v", stackNames.OrgChildStackSetName, err)
				}
				spinner.Stop()
				logger.SuccessMessagef("%s StackSet deployed ✅", stackNames.OrgChildStackSetName)
			}

			// Cleaning up resources
			spinner.Push("...Cleaning up resources")
			if deployAllStacks || deployOrgChildStackSet {
				if len(orgChildStackSetInfo.AccountsToRemove) > 0 || len(orgChildStackSetInfo.RegionsToRemove) > 0 {
					err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, orgChildStackSetProps, isStandaloneDeployment, deploymentRegions, orgChildStackSetInfo.AccountsToRemove, orgChildStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
					if err != nil {
						spinner.Pause()
						logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", stackNames.OrgChildStackSetName, err)
						spinner.Resume()
					}
				}
			}
			if deployAllStacks {
				if !enableEC2InstanceConfigurator {
					spinner.Push("...Deleting Stacks for SSM Document in each region")
					err = awshelper.DeleteRegionalStacks(deploymentRegions, orgMetadata.AutomationAccountProfileName, stackNames.SSMDocumentStackName, "", ssmDocumentSSMParameterName)
					if err != nil {
						logger.Fatalf("failed to deploy Cloudformation Stack %s: %v", stackNames.SSMDocumentStackName, err)
					}
					spinner.Stop()
				}
			}
			if deployAllStacks || deploySecurityHubStackSets {
				if enableSecurityHub {
					if len(securityHubEnablerStackSetInfo.AccountsToRemove) > 0 || len(securityHubEnablerStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, securityHubEnablerStackSetProps, isStandaloneDeployment, deploymentRegions, securityHubEnablerStackSetInfo.AccountsToRemove, securityHubEnablerStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", securityHubEnablerStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
					if len(securityHubAdminDelegationStackSetInfo.AccountsToRemove) > 0 || len(securityHubAdminDelegationStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, securityHubAdminDelegationStackSetProps, isStandaloneDeployment, deploymentRegions, securityHubAdminDelegationStackSetInfo.AccountsToRemove, securityHubAdminDelegationStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", securityHubAdminDelegationStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
				}
			}
			if deployAllStacks || deployInspectorStackSets {
				if enableInspector {
					if len(inspectorEnablerStackSetInfo.AccountsToRemove) > 0 || len(inspectorEnablerStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, inspectorEnablerStackSetProps, isStandaloneDeployment, deploymentRegions, inspectorEnablerStackSetInfo.AccountsToRemove, inspectorEnablerStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", inspectorEnablerStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
					if len(inspectorAdminDelegationStackSetInfo.AccountsToRemove) > 0 || len(inspectorAdminDelegationStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, inspectorAdminDelegationStackSetProps, isStandaloneDeployment, deploymentRegions, inspectorAdminDelegationStackSetInfo.AccountsToRemove, inspectorAdminDelegationStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", inspectorAdminDelegationStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
				}
			}
			if deployAllStacks || deployGuardDutyStackSets {
				if enableGuardDuty {
					if len(guardDutyEnablerStackSetInfo.AccountsToRemove) > 0 || len(guardDutyEnablerStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, guardDutyEnablerStackSetProps, isStandaloneDeployment, deploymentRegions, guardDutyEnablerStackSetInfo.AccountsToRemove, guardDutyEnablerStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", guardDutyEnablerStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
					if len(guardDutyAdminDelegationStackSetInfo.AccountsToRemove) > 0 || len(guardDutyAdminDelegationStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, guardDutyAdminDelegationStackSetProps, isStandaloneDeployment, deploymentRegions, guardDutyAdminDelegationStackSetInfo.AccountsToRemove, guardDutyAdminDelegationStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", guardDutyAdminDelegationStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
					if len(guardDutyDeliveryBucketStackSetInfo.AccountsToRemove) > 0 || len(guardDutyDeliveryBucketStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, guardDutyDeliveryBucketStackSetProps, isStandaloneDeployment, deploymentRegions, guardDutyDeliveryBucketStackSetInfo.AccountsToRemove, guardDutyDeliveryBucketStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", guardDutyDeliveryKmsKeyStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
					if len(guardDutyDeliveryKmsKeyStackSetInfo.AccountsToRemove) > 0 || len(guardDutyDeliveryKmsKeyStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, guardDutyDeliveryKmsKeyStackSetProps, isStandaloneDeployment, deploymentRegions, guardDutyDeliveryKmsKeyStackSetInfo.AccountsToRemove, guardDutyDeliveryKmsKeyStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", guardDutyDeliveryKmsKeyStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
				}
			}
			if deployAllStacks {
				if enableVpcFlowLogs {
					if len(vpcFlowLogsDeliveryBucketStackSetInfo.AccountsToRemove) > 0 || len(vpcFlowLogsDeliveryBucketStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, vpcFlowLogsDeliveryBucketStackSetProps, isStandaloneDeployment, deploymentRegions, vpcFlowLogsDeliveryBucketStackSetInfo.AccountsToRemove, vpcFlowLogsDeliveryBucketStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", vpcFlowLogsDeliveryBucketStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
					if len(vpcFlowLogsDeliveryKmsKeyStackSetInfo.AccountsToRemove) > 0 || len(vpcFlowLogsDeliveryKmsKeyStackSetInfo.RegionsToRemove) > 0 {
						err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, vpcFlowLogsDeliveryKmsKeyStackSetProps, isStandaloneDeployment, deploymentRegions, vpcFlowLogsDeliveryKmsKeyStackSetInfo.AccountsToRemove, vpcFlowLogsDeliveryKmsKeyStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
						if err != nil {
							spinner.Pause()
							logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", vpcFlowLogsDeliveryKmsKeyStackSetProps.StackSetName, err)
							spinner.Resume()
						}
					}
				}
				if len(cfStackSetExecutionRoleStackSetInfo.AccountsToRemove) > 0 || len(cfStackSetExecutionRoleStackSetInfo.RegionsToRemove) > 0 {
					err = awshelper.CleanupStackSetInstances(orgMetadata.AutomationAccountProfileName, cfStackSetExecutionRoleStackSetProps, isStandaloneDeployment, deploymentRegions, cfStackSetExecutionRoleStackSetInfo.AccountsToRemove, cfStackSetExecutionRoleStackSetInfo.RegionsToRemove, stackSetOperationPreferences)
					if err != nil {
						spinner.Pause()
						logger.Errorf("failed to cleanup Instances for Cloudformation StackSet %s: %v", cfStackSetExecutionRoleStackSetProps.StackSetName, err)
						spinner.Resume()
					}
				}
			}
			spinner.Stop()
			logger.SuccessMessageln("Cleanup done ✅")
			logger.SuccessMessageln("\nRapidRadar deployment completed successfully!\n")
		} else {
			logger.Fatalln("You chose not to proceed. Exiting...")
		}
	},
}

func init() {
	Cmd.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask questions; just deploy everything")
	Cmd.Flags().StringVarP(&envDirPath, "env-dir", "", "env/", "Directory to search for YAML files")
	Cmd.Flags().StringVarP(&configStackNamesPath, "config-stack-names-path", "", "config/stacks.yml", "Yaml file to get names of Stacks and StackSets")
	Cmd.Flags().BoolVarP(&buildImage, "build-image", "", false, "Build Docker image")
	Cmd.Flags().BoolVarP(&deployAllStacks, "all", "", true, "Deploy All Stacks")
	Cmd.Flags().BoolVarP(&deployLambdaLayers, "lambda-layers", "", false, "Deploy only Lambda layers")
	Cmd.Flags().BoolVarP(&deployManagementAccountStack, "management-account-stack", "", false, "Deploy only Management Account Stack")
	Cmd.Flags().BoolVarP(&deployAutomationAccountStack, "automation-account-stack", "", false, "Deploy only Automation Account Stack")
	Cmd.Flags().BoolVarP(&deployOrgChildStackSet, "org-child-stackset", "", false, "Deploy only Organization Child StackSet")
	Cmd.Flags().BoolVarP(&deploySSMDocumentStacks, "ssm-documents", "", false, "Deploy only SSM Document Stacks")
	Cmd.Flags().BoolVarP(&deployGuardDutyStackSets, "guardduty", "", false, "Deploy only GuardDuty StackSets")
	Cmd.Flags().BoolVarP(&deployInspectorStackSets, "inspector", "", false, "Deploy only Inspector StackSets")
	Cmd.Flags().BoolVarP(&deploySecurityHubStackSets, "securityhub", "", false, "Deploy only SecurityHub StackSets")
}
