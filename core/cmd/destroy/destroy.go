package destroy

import (
	"context"
	"fmt"
	"os"
	"rrcore/cmd/awshelper"
	"rrcore/cmd/colors"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"rrcore/cmd/spinner"
	"rrcore/cmd/yamlenv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/spf13/cobra"
)

var yes bool
var envDirPath string
var configStackNamesPath string
var destroyAllStacks bool
var skipLambdaLayers bool
var skipManagementAccountStack bool
var skipAutomationAccountStack bool
var skipOrgChildStackSet bool
var skipSSMDocumentStacks bool
var skipGuardDutyStackSets bool
var skipInspectorStackSets bool
var skipSecurityHubStackSets bool

var Cmd = &cobra.Command{
	Use:                   "destroy [flags]",
	Short:                 "Destroy rapidradar deployment",
	Long:                  `Destroy current RapidRadar Deployment`,
	Args:                  cobra.NoArgs,
	DisableFlagsInUseLine: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if skipLambdaLayers || skipManagementAccountStack || skipAutomationAccountStack ||
			skipOrgChildStackSet || skipSSMDocumentStacks || skipGuardDutyStackSets ||
			skipInspectorStackSets || skipSecurityHubStackSets {
			destroyAllStacks = false
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		stackSetOperationPreferences := &cfTypes.StackSetOperationPreferences{
			RegionConcurrencyType:      cfTypes.RegionConcurrencyTypeParallel,
			MaxConcurrentPercentage:    aws.Int32(100),
			FailureTolerancePercentage: aws.Int32(10),
		}

		spinner.Push("🚀 Starting destruction...")
		logger.Debugf("...Loading all env vars from %s yml files\n", envDirPath)

		// Loads all env vars from yaml files
		ssmNamesMap, secretNamesMap, notificationsConfigSecretNamesMap, err := yamlenv.LoadAllEnvVars(envDirPath)
		if err != nil {
			logger.Fatalf("Failed to load all env vars from %s*.yml files: %v", envDirPath, err)
			panic(err)
		}
		deploymentTargets := strings.Split(os.Getenv("DeploymentTargets"), ",")
		deploymentRegions := strings.Split(os.Getenv("ActiveRegions"), ",")

		// Validate parameters
		_, isStandaloneDeployment := helper.GetDeploymentTargetsType(deploymentTargets)

		// Panic if ProjectName does not exist
		projectName := os.Getenv("ProjectName")
		if helper.IsValEmpty(projectName) {
			err = fmt.Errorf("ProjectName env var is empty")
			logger.Fatalf("ProjectName cannot be empty in %scommon.yml file: %v", envDirPath, err)
			panic(err)
		}
		userOffboardingWorkflowEcrRepoName := fmt.Sprintf("%s-sso-user-generate-reports", projectName)
		slackSocketAppEcrRepoName := fmt.Sprintf("%s-slack-socket-app", projectName)

		// Loads all stacks names from config/yml file
		stackNames, err := yamlenv.LoadAllStackNames(configStackNamesPath)
		if err != nil {
			logger.Fatalf("Failed to load all Stacks and StackSets names from %s file: %v", configStackNamesPath, err)
			panic(err)
		}

		// Ask if we should proceed deployment with the given ProjectName
		spinner.Stop()
		var proceed bool
		if yes {
			proceed = true
		} else {
			proceed = helper.Confirm(false, colors.Red("Are you sure you want to permanently destroy the deployment? THIS ACTION IS IRREVERSIBLE!"))
		}
		if proceed {
			spinner.Push("...Checking AWS Profiles")
			orgMetadata, err := awshelper.GetAWSAccountDetails(stackNames.AutomationAccountStackName)
			if err != nil {
				logger.Fatalf("Failed to get metadata from current Organization: %v", err)
				panic(err)
			}
			// Get AccountsOUs if DeploymentTargets are standalone accounts
			orgChildStackSetCallAs := cfTypes.CallAsDelegatedAdmin
			orgChildStackSetPermissionModel := cfTypes.PermissionModelsServiceManaged
			if isStandaloneDeployment {
				orgChildStackSetCallAs = cfTypes.CallAsSelf
				orgChildStackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
			}
			spinner.Stop()

			// Variables to store some other information
			policyDocumentSSMParameterName := fmt.Sprintf("/%s/post-deploy/POLICY_JSON", projectName)
			ssmDocumentSSMParameterName := fmt.Sprintf("/%s/ssm-document/JSON_CONTENT", projectName)
			templatesS3BucketName := fmt.Sprintf("%s-artifacts-%s", projectName, orgMetadata.AutomationAccountId)

			// Setting CallAs value for CloudFormation StackSets
			var cfStackSetExecutionRoleStackSetCallAs cfTypes.CallAs
			if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
				cfStackSetExecutionRoleStackSetCallAs = cfTypes.CallAsSelf
			} else {
				cfStackSetExecutionRoleStackSetCallAs = cfTypes.CallAsDelegatedAdmin
			}

			// Setup AWS Credentials for Automation Account
			automationCfg, err := config.LoadDefaultConfig(context.TODO(),
				config.WithSharedConfigProfile(orgMetadata.AutomationAccountProfileName),
			)
			if err != nil {
				logger.Fatalf("failed to load AWS config: %v", err)
			}
			automationCfClient := cloudformation.NewFromConfig(automationCfg)
			automationSsmClient := ssm.NewFromConfig(automationCfg)
			automationSecretsManagerClient := secretsmanager.NewFromConfig(automationCfg)
			automationS3Client := s3.NewFromConfig(automationCfg)
			automationEcrClient := ecr.NewFromConfig(automationCfg)

			// Setup AWS Credentials for Management Account
			managementCfg, err := config.LoadDefaultConfig(context.TODO(),
				config.WithSharedConfigProfile(orgMetadata.AutomationAccountProfileName),
			)
			if err != nil {
				logger.Fatalf("failed to load AWS config: %v", err)
			}
			managementCfClient := cloudformation.NewFromConfig(managementCfg)

			// Deletes Org Child Accounts StackSet
			if destroyAllStacks && !skipOrgChildStackSet {
				spinner.Push(fmt.Sprintf("...Deleting %s CloudFormation StackSet", stackNames.OrgChildStackSetName))
				orgChildStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.OrgChildStackSetName,
					IsServiceManaged: true,
					CallAs:           orgChildStackSetCallAs,
					PermissionModel:  orgChildStackSetPermissionModel,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, orgChildStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.OrgChildStackSetName, err)
				}
				spinner.Stop()
			}

			// Deletes SSM Document Stacks
			if destroyAllStacks && !skipSSMDocumentStacks {
				spinner.Push("...Deleting Stacks for SSM Document in each region")
				err = awshelper.DeleteRegionalStacks(deploymentRegions, orgMetadata.AutomationAccountProfileName, stackNames.SSMDocumentStackName, "", ssmDocumentSSMParameterName)
				if err != nil {
					logger.Fatalf("failed to deploy Cloudformation Stack %s: %v", stackNames.SSMDocumentStackName, err)
				}
				spinner.Stop()
			}

			// Deletes Automation Account Stack
			if destroyAllStacks && !skipAutomationAccountStack {
				spinner.Push(fmt.Sprintf("...Deleting %s CloudFormation Stack", stackNames.AutomationAccountStackName))
				ssoUsersIpDataS3Bucket := fmt.Sprintf("%s-%s-sso-users-ip-data", projectName, orgMetadata.AutomationAccountId)
				err = awshelper.DeleteS3BucketIfExists(automationS3Client, ssoUsersIpDataS3Bucket)
				if err != nil {
					logger.Fatalf("failed to delete S3 Bucket %s: %v", ssoUsersIpDataS3Bucket, err)
				}
				err = awshelper.DeleteCloudFormationStackIfExists(automationCfClient, stackNames.AutomationAccountStackName)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation Stack %s: %v", stackNames.AutomationAccountStackName, err)
				}
				err = awshelper.DeleteCloudFormationStackIfExists(automationCfClient, stackNames.AutomationAccountSecretsStackName)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation Stack %s: %v", stackNames.AutomationAccountSecretsStackName, err)
				}
				err = awshelper.DeleteCloudFormationStackIfExists(automationCfClient, stackNames.AutomationDynamoDbTablesStackName)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation Stack %s: %v", stackNames.AutomationDynamoDbTablesStackName, err)
				}
				err = awshelper.DeleteSSMParameterIfExists(automationSsmClient, policyDocumentSSMParameterName)
				if err != nil {
					logger.Fatalf("failed to delete SSM Parameter named %s: %v", policyDocumentSSMParameterName, err)
				}
				err = awshelper.DeleteEcrRepoIfExists(automationEcrClient, userOffboardingWorkflowEcrRepoName)
				if err != nil {
					logger.Fatalf("failed to delete ECR repository named %s: %v", userOffboardingWorkflowEcrRepoName, err)
				}
				err = awshelper.DeleteEcrRepoIfExists(automationEcrClient, slackSocketAppEcrRepoName)
				if err != nil {
					logger.Fatalf("failed to delete ECR repository named %s: %v", slackSocketAppEcrRepoName, err)
				}
				spinner.Stop()
			}

			//Deletes SecurityHub StackSets
			if destroyAllStacks && !skipSecurityHubStackSets {
				spinner.Push("...Deleting CloudFormation StackSets for SecurityHub")
				var securityHubEnablerStackSetCallAs cfTypes.CallAs
				var securityHubEnablerStackSetPermissionModel cfTypes.PermissionModels
				var securityHubEnablerStackSetIsServiceManaged bool
				if !helper.IsValEmpty(orgMetadata.SecurityHubAdminAccountId) {
					securityHubEnablerStackSetCallAs = cfTypes.CallAsSelf
					securityHubEnablerStackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
				} else {
					securityHubEnablerStackSetIsServiceManaged = true
					securityHubEnablerStackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
					if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
						securityHubEnablerStackSetCallAs = cfTypes.CallAsSelf
					} else {
						securityHubEnablerStackSetCallAs = cfTypes.CallAsDelegatedAdmin
					}
				}
				securityHubEnablerStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.SecurityHubEnablerStackSetName,
					IsServiceManaged: securityHubEnablerStackSetIsServiceManaged,
					CallAs:           securityHubEnablerStackSetCallAs,
					PermissionModel:  securityHubEnablerStackSetPermissionModel,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, securityHubEnablerStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.SecurityHubEnablerStackSetName, err)
				}

				securityHubAdminDelegationStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.SecurityHubAdminDelegationStackSetName,
					IsServiceManaged: false,
					CallAs:           cfTypes.CallAsSelf,
					PermissionModel:  cfTypes.PermissionModelsSelfManaged,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, securityHubAdminDelegationStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.SecurityHubAdminDelegationStackSetName, err)
				}
				spinner.Stop()
			}

			// Deletes Inspector StackSets
			if destroyAllStacks && !skipInspectorStackSets {
				spinner.Push("...Deleting CloudFormation StackSets for Inspector")
				var inspectorEnablerStackSetIsServiceManaged bool
				var inspectorEnablerStackSetCallAs cfTypes.CallAs
				var inspectorEnablerStackSetPermissionModel cfTypes.PermissionModels
				if !helper.IsValEmpty(orgMetadata.InspectorAdminAccountId) {
					inspectorEnablerStackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
					inspectorEnablerStackSetCallAs = cfTypes.CallAsSelf
				} else {
					inspectorEnablerStackSetIsServiceManaged = true
					inspectorEnablerStackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
					if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
						inspectorEnablerStackSetCallAs = cfTypes.CallAsSelf
					} else {
						inspectorEnablerStackSetCallAs = cfTypes.CallAsDelegatedAdmin
					}
				}
				inspectorEnablerStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.InspectorEnablerStackSetName,
					IsServiceManaged: inspectorEnablerStackSetIsServiceManaged,
					CallAs:           inspectorEnablerStackSetCallAs,
					PermissionModel:  inspectorEnablerStackSetPermissionModel,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, inspectorEnablerStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.InspectorEnablerStackSetName, err)
				}
				inspectorAdminDelegationStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.InspectorAdminDelegationStackSetName,
					IsServiceManaged: false,
					CallAs:           cfTypes.CallAsSelf,
					PermissionModel:  cfTypes.PermissionModelsSelfManaged,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, inspectorAdminDelegationStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.InspectorAdminDelegationStackSetName, err)
				}
				spinner.Stop()
			}

			// Deletes GuardDuty StackSets
			if destroyAllStacks && !skipGuardDutyStackSets {
				spinner.Push("...Deleting CloudFormation StackSets for GuardDuty")
				var guardDutyEnablerStackSetIsServiceManaged bool
				var guardDutyEnablerStackSetCallAs cfTypes.CallAs
				var guardDutyEnablerStackSetPermissionModel cfTypes.PermissionModels
				if !helper.IsValEmpty(orgMetadata.GuardDutyAdminAccountId) {
					guardDutyEnablerStackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
					guardDutyEnablerStackSetCallAs = cfTypes.CallAsSelf
				} else {
					guardDutyEnablerStackSetIsServiceManaged = true
					guardDutyEnablerStackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
					if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
						guardDutyEnablerStackSetCallAs = cfTypes.CallAsSelf
					} else {
						guardDutyEnablerStackSetCallAs = cfTypes.CallAsDelegatedAdmin
					}
				}
				guardDutyEnablerStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.GuardDutyEnablerStackSetName,
					IsServiceManaged: guardDutyEnablerStackSetIsServiceManaged,
					CallAs:           guardDutyEnablerStackSetCallAs,
					PermissionModel:  guardDutyEnablerStackSetPermissionModel,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, guardDutyEnablerStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.GuardDutyEnablerStackSetName, err)
				}
				guardDutyAdminDelegationStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.GuardDutyAdminDelegationStackSetName,
					IsServiceManaged: false,
					CallAs:           cfTypes.CallAsSelf,
					PermissionModel:  cfTypes.PermissionModelsSelfManaged,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, guardDutyAdminDelegationStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.GuardDutyAdminDelegationStackSetName, err)
				}
				var guardDutyDeliveryBucketStackSetIsServiceManaged bool
				var guardDutyDeliveryBucketStackSetCallAs cfTypes.CallAs
				var guardDutyDeliveryBucketStackSetPermissionModel cfTypes.PermissionModels
				if !helper.IsValEmpty(orgMetadata.LogArchiveAccountId) || !helper.IsValEmpty(orgMetadata.GuardDutyAdminAccountId) {
					guardDutyDeliveryBucketStackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
					guardDutyDeliveryBucketStackSetCallAs = cfTypes.CallAsSelf
				} else {
					guardDutyDeliveryBucketStackSetIsServiceManaged = true
					guardDutyDeliveryBucketStackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
					if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
						guardDutyDeliveryBucketStackSetCallAs = cfTypes.CallAsSelf
					} else {
						guardDutyDeliveryBucketStackSetCallAs = cfTypes.CallAsDelegatedAdmin
					}
				}
				guardDutyDeliveryBucketStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.GuardDutyDeliveryBucketStackSetName,
					IsServiceManaged: guardDutyDeliveryBucketStackSetIsServiceManaged,
					CallAs:           guardDutyDeliveryBucketStackSetCallAs,
					PermissionModel:  guardDutyDeliveryBucketStackSetPermissionModel,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, guardDutyDeliveryBucketStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.GuardDutyDeliveryBucketStackSetName, err)
				}

				var guardDutyDeliveryKmsKeyStackSetIsServiceManaged bool
				var guardDutyDeliveryKmsKeyStackSetCallAs cfTypes.CallAs
				var guardDutyDeliveryKmsKeyStackSetPermissionModel cfTypes.PermissionModels
				if !helper.IsValEmpty(orgMetadata.GuardDutyAdminAccountId) {
					guardDutyDeliveryKmsKeyStackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
					guardDutyDeliveryKmsKeyStackSetCallAs = cfTypes.CallAsSelf
				} else {
					guardDutyDeliveryKmsKeyStackSetIsServiceManaged = true
					guardDutyDeliveryKmsKeyStackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
					if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
						guardDutyDeliveryKmsKeyStackSetCallAs = cfTypes.CallAsSelf
					} else {
						guardDutyDeliveryKmsKeyStackSetCallAs = cfTypes.CallAsDelegatedAdmin
					}
				}
				guardDutyDeliveryKmsKeyStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.GuardDutyDeliveryKmsKeyStackSetName,
					IsServiceManaged: guardDutyDeliveryKmsKeyStackSetIsServiceManaged,
					CallAs:           guardDutyDeliveryKmsKeyStackSetCallAs,
					PermissionModel:  guardDutyDeliveryKmsKeyStackSetPermissionModel,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, guardDutyDeliveryKmsKeyStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.GuardDutyDeliveryKmsKeyStackSetName, err)
				}
				spinner.Stop()
			}

			// Deletes Vpc Flow Logs StackSets
			if destroyAllStacks {
				spinner.Push("...Deleting CloudFormation StackSets for VPC FlowLogs")
				var vpcFlowLogsStackSetIsServiceManaged bool
				var vpcFlowLogsStackSetCallAs cfTypes.CallAs
				var vpcFlowLogsStackSetPermissionModel cfTypes.PermissionModels
				if !helper.IsValEmpty(orgMetadata.LogArchiveAccountId) {
					vpcFlowLogsStackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
					vpcFlowLogsStackSetCallAs = cfTypes.CallAsSelf
				} else {
					vpcFlowLogsStackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
					if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
						vpcFlowLogsStackSetCallAs = cfTypes.CallAsSelf
					} else {
						vpcFlowLogsStackSetCallAs = cfTypes.CallAsDelegatedAdmin
					}
				}
				vpcFlowLogsDeliveryBucketStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.VpcFlowLogsDeliveryBucketStackSetName,
					IsServiceManaged: vpcFlowLogsStackSetIsServiceManaged,
					CallAs:           vpcFlowLogsStackSetCallAs,
					PermissionModel:  vpcFlowLogsStackSetPermissionModel,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, vpcFlowLogsDeliveryBucketStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.VpcFlowLogsDeliveryBucketStackSetName, err)
				}
				vpcFlowLogsDeliveryKmsKeyStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.VpcFlowLogsDeliveryKmsKeyStackSetName,
					IsServiceManaged: vpcFlowLogsStackSetIsServiceManaged,
					CallAs:           vpcFlowLogsStackSetCallAs,
					PermissionModel:  vpcFlowLogsStackSetPermissionModel,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, isStandaloneDeployment, vpcFlowLogsDeliveryKmsKeyStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.VpcFlowLogsDeliveryKmsKeyStackSetName, err)
				}
				spinner.Stop()
			}

			// Deletes Management Account stack
			if destroyAllStacks && !skipManagementAccountStack {
				spinner.Push(fmt.Sprintf("...Deleting %s CloudFormation Stack", stackNames.ManagementAccountStackName))
				err = awshelper.DeleteCloudFormationStackIfExists(managementCfClient, stackNames.ManagementAccountStackName)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation Stack %s: %v", stackNames.ManagementAccountStackName, err)
				}
				spinner.Stop()
			}

			// Deletes Lambda layers
			if destroyAllStacks && !skipLambdaLayers {
				spinner.Push("...Deleting Stacks for Lambda Layers from each region")
				err = awshelper.DeleteRegionalStacks(deploymentRegions, orgMetadata.AutomationAccountProfileName, stackNames.LambdaLayersStackName, templatesS3BucketName, "")
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation Stack %s: %v", stackNames.LambdaLayersStackName, err)
				}
				spinner.Stop()
			}

			// deletes CfStackSetExecutionRoleStackSet if exists
			if destroyAllStacks {
				spinner.Push(fmt.Sprintf("...Deleting %s CloudFormation StackSet", stackNames.CfStackSetExecutionRoleStackSetName))
				cfStackSetExecutionRoleStackSetProps := &awshelper.StackSetProps{
					StackSetName:     stackNames.CfStackSetExecutionRoleStackSetName,
					IsServiceManaged: true,
					CallAs:           cfStackSetExecutionRoleStackSetCallAs,
					PermissionModel:  cfTypes.PermissionModelsServiceManaged,
				}
				err = awshelper.DeleteCfStackSetIfExists(orgMetadata.AutomationAccountProfileName, false, cfStackSetExecutionRoleStackSetProps, stackSetOperationPreferences)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation StackSet %s: %v", stackNames.CfStackSetExecutionRoleStackSetName, err)
				}
				spinner.Stop()

				// deletes CfStackSetAdministrationRoleStack if exists
				spinner.Push(fmt.Sprintf("...Deleting %s CloudFormation Stack", stackNames.CfStackSetAdministrationRoleStackName))
				err = awshelper.DeleteCloudFormationStackIfExists(automationCfClient, stackNames.CfStackSetAdministrationRoleStackName)
				if err != nil {
					logger.Fatalf("failed to delete Cloudformation Stack %s: %v", stackNames.CfStackSetAdministrationRoleStackName, err)
				}
				spinner.Stop()

				// Cleanup SSM secrets
				spinner.Push("...Cleaning up SSM Parameters secrets")
				for ssmName, _ := range ssmNamesMap {
					logger.Debugf("...Deleting SSM parameter named '%s' if exists", ssmName)
					err = awshelper.DeleteSSMParameterIfExists(automationSsmClient, ssmName)
					if err != nil {
						logger.Fatalf("failed to delete SSM Parameter named %s: %v", ssmName, err)
					}
				}
				spinner.Stop()

				// Cleaning up SecretsManager secrets
				spinner.Push("...Cleaning up SecretsManager secrets")
				for secretName, _ := range secretNamesMap {
					logger.Debugf("...Deleting SecretsManager secret named '%s' if exists", secretName)
					err = awshelper.DeleteSecretIfExists(automationSecretsManagerClient, secretName)
					if err != nil {
						logger.Fatalf("failed to delete SecretsManager secret named %s: %v", secretName, err)
					}
				}
				for secretName, _ := range notificationsConfigSecretNamesMap {
					logger.Debugf("...Deleting SecretsManager secret named '%s' if exists", secretName)
					err = awshelper.DeleteSecretIfExists(automationSecretsManagerClient, secretName)
					if err != nil {
						logger.Fatalf("failed to delete SecretsManager secret named %s: %v", secretName, err)
					}
				}
				spinner.Stop()
			}
			logger.SuccessMessageln("\nRapidRadar deployment destroyed successfully!\n")
		} else {
			logger.Fatalln("You chose not to proceed. Exiting...")
		}
	},
}

func init() {
	Cmd.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask questions; just destroy")
	Cmd.Flags().StringVarP(&envDirPath, "env-dir", "", "env/", "Directory to search for YAML files")
	Cmd.Flags().StringVarP(&configStackNamesPath, "config-stack-names-path", "", "config/stacks.yml", "Yaml file to get names of Stacks and StackSets")
	Cmd.Flags().BoolVarP(&destroyAllStacks, "all", "", true, "Destroy All Stacks")
	Cmd.Flags().BoolVarP(&skipLambdaLayers, "skip-lambda-layers", "", false, "Skip destroying Lambda layers")
	Cmd.Flags().BoolVarP(&skipManagementAccountStack, "skip-management-account-stack", "", false, "Skip destroying Management Account Stack")
	Cmd.Flags().BoolVarP(&skipAutomationAccountStack, "skip-automation-account-stack", "", false, "Skip destroying Automation Account Stack")
	Cmd.Flags().BoolVarP(&skipOrgChildStackSet, "skip-org-child-stackset", "", false, "Skip destroying Organization Child StackSet")
	Cmd.Flags().BoolVarP(&skipSSMDocumentStacks, "skip-ssm-documents", "", false, "Skip destroying SSM Document Stacks")
	Cmd.Flags().BoolVarP(&skipGuardDutyStackSets, "skip-guardduty", "", false, "Skip destroying GuardDuty StackSets")
	Cmd.Flags().BoolVarP(&skipInspectorStackSets, "skip-inspector", "", false, "Skip destroying Inspector StackSets")
	Cmd.Flags().BoolVarP(&skipSecurityHubStackSets, "skip-securityhub", "", false, "Skip destroying SecurityHub StackSets")
}
