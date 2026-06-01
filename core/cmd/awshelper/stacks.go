package awshelper

import (
	"context"
	"fmt"
	"os"
	"rrcore/cmd/logger"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func DeployCfStackSetAdministrationRoleStack(profile, stackName, templatePath string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)

	params := map[string]string{
		"AdministrationRoleName": os.Getenv("CloudFormationStackSetAdministrationRoleStackName"),
		"ExecutionRoleName":      os.Getenv("CloudFormationStackSetExecutionRoleStackSetName"),
	}
	stackExists, _, err := checkIfStackExists(client, stackName)
	if err != nil {
		return fmt.Errorf("failed to check for existence of CloudFormation Stack %s: %w", stackName, err)
	}
	if !stackExists {
		err = createCloudFormationStack(client, stackName, templatePath, "", params)
		if err != nil {
			return err
		}
	}
	return nil
}

func DeployLambdaLayersStack(deploymentRegions []string, profile, stackName, templatesS3BucketName, templatePath, packagedTemplateDir, organizationId string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(deploymentRegions))

	for _, region := range deploymentRegions {
		wg.Add(1)

		regionTemplatesS3BucketName := fmt.Sprintf("%s-%s", templatesS3BucketName, region)
		packagedTemplatePath := fmt.Sprintf("%s/lambda-layers-%s.yml", packagedTemplateDir, region)
		go func(region string) {
			defer wg.Done()
			cfg, err := config.LoadDefaultConfig(context.TODO(),
				config.WithSharedConfigProfile(profile),
				config.WithRegion(region),
			)
			if err != nil {
				logger.Fatalf("failed to load AWS config: %v", err)
			}
			cfClient := cloudformation.NewFromConfig(cfg)
			s3Client := s3.NewFromConfig(cfg)

			err = createS3BucketIfNotExists(s3Client, regionTemplatesS3BucketName, region)
			if err != nil {
				errChan <- fmt.Errorf("failed to create S3 Bucket %s in %s: %w", regionTemplatesS3BucketName, region, err)
				return
			}
			err = packageTemplate(templatePath, regionTemplatesS3BucketName, packagedTemplatePath, profile, region)
			if err != nil {
				errChan <- fmt.Errorf("failed to package template for Stack %s in %s: %w", stackName, region, err)
				return
			}

			params := map[string]string{
				"ProjectName":    os.Getenv("ProjectName"),
				"OrganizationId": organizationId,
			}
			err = deployCloudFormationStack(cfClient, stackName, packagedTemplatePath, "", params)
			if err != nil {
				errChan <- fmt.Errorf("failed to deploy Stack %s in %s: %w", stackName, region, err)
				return
			}
			logger.Debugf("✅ Successfully deployed Stack %s in region %s\n", stackName, region)
		}(region)
	}
	wg.Wait() // Wait for all Goroutines to finish
	close(errChan)
	// Check if any errors occurred
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	return nil
}

func DeployManagementAccountStack(profile, stackName, templatesS3BucketName, templatePath, organizationId, automationAccountId, automationEventBusName string, ssoRolePermissionAccounts []string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	cfClient := cloudformation.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)

	regionTemplatesS3BucketName := fmt.Sprintf("%s-%s", templatesS3BucketName, cfg.Region)

	params := map[string]string{
		"ProjectName":                                       os.Getenv("ProjectName"),
		"OrganizationId":                                    organizationId,
		"IsControlTowerEnabled":                             os.Getenv("IsControlTowerEnabled"),
		"AutomationAccountId":                               automationAccountId,
		"AutomationEventBusName":                            automationEventBusName,
		"CfStackSetExecutionRoleCreation":                   os.Getenv("CfStackSetExecutionRoleCreation"),
		"CfStackSetExecutionRoleName":                       os.Getenv("CloudFormationStackSetExecutionRoleStackSetName"),
		"SSORolePermissionAccounts":                         strings.Join(ssoRolePermissionAccounts, ","),
		"CreateManagementTrail":                             os.Getenv("CreateManagementTrail"),
		"IsOrganizationTrail":                               os.Getenv("IsOrganizationTrail"),
		"CentralizedLogsS3BucketName":                       os.Getenv("CentralizedLogsS3BucketName"),
		"TrailCloudWatchLogGroupName":                       os.Getenv("TrailCloudWatchLogGroupName"),
		"BlockEC2LaunchWithoutCertainTags":                  os.Getenv("BlockEC2LaunchWithoutCertainTags"),
		"EC2InstanceLaunchSCPTagKeys":                       os.Getenv("EC2InstanceLaunchSCPTagKeys"),
		"BlockEksClusterCreationWithoutCertainTags":         os.Getenv("BlockEksClusterCreationWithoutCertainTags"),
		"EksClusterCreationSCPTagKeys":                      os.Getenv("EksClusterCreationSCPTagKeys"),
		"BlockRdsClusterInstanceCreationWithoutCertainTags": os.Getenv("BlockRdsClusterInstanceCreationWithoutCertainTags"),
		"RdsClusterInstanceCreationSCPTagKeys":              os.Getenv("RdsClusterInstanceCreationSCPTagKeys"),
		"BlockEfsFileSystemCreationWithoutCertainTags":      os.Getenv("BlockEfsFileSystemCreationWithoutCertainTags"),
		"EfsFileSystemCreationSCPTagKeys":                   os.Getenv("EfsFileSystemCreationSCPTagKeys"),
		"BlockEC2LaunchWithoutIMDSV2":                       os.Getenv("BlockEC2LaunchWithoutIMDSV2"),
		"SCPBypassTagKeyEC2LaunchWithoutIMDSV2":             os.Getenv("SCPBypassTagKeyEC2LaunchWithoutIMDSV2"),
		"BlockEC2LaunchWithPublicIP":                        os.Getenv("BlockEC2LaunchWithPublicIP"),
		"SCPBypassTagKeyEC2LaunchWithPublicIP":              os.Getenv("SCPBypassTagKeyEC2LaunchWithPublicIP"),
		"BlockUnencryptedEBSVolumeCreation":                 os.Getenv("BlockUnencryptedEBSVolumeCreation"),
		"SCPBypassTagKeyEBSVolumeCreation":                  os.Getenv("SCPBypassTagKeyEBSVolumeCreation"),
		"BlockLoadBalancerCreation":                         os.Getenv("BlockLoadBalancerCreation"),
		"SCPBypassTagKeyLoadBalancerCreation":               os.Getenv("SCPBypassTagKeyLoadBalancerCreation"),
		"BlockEIPAllocation":                                os.Getenv("BlockEIPAllocation"),
		"SCPBypassTagKeyEIPAllocation":                      os.Getenv("SCPBypassTagKeyEIPAllocation"),
		"BlockIAMUsersCreation":                             os.Getenv("BlockIAMUsersCreation"),
		"SCPBypassTagKeyIAMUsersCreation":                   os.Getenv("SCPBypassTagKeyIAMUsersCreation"),
		"BlockIAMUserCreationWithoutCertainTags":            os.Getenv("BlockIAMUserCreationWithoutCertainTags"),
		"IAMUsersCreationSCPTagKeys":                        os.Getenv("IAMUsersCreationSCPTagKeys"),
		"BlockMakeEBSSnapshotPublic":                        os.Getenv("BlockMakeEBSSnapshotPublic"),
		"BlockUnencryptedRDSCreation":                       os.Getenv("BlockUnencryptedRDSCreation"),
		"SCPBypassTagKeyUnencryptedRDSCreation":             os.Getenv("SCPBypassTagKeyUnencryptedRDSCreation"),
		"DeploymentTargets":                                 os.Getenv("DeploymentTargets"),
		"ExcludeAccounts":                                   os.Getenv("ExcludeAccounts"),
		"CreateDataTrail":                                   os.Getenv("CreateDataTrail"),
	}

	templateUrl, err := uploadTemplateToS3Bucket(s3Client, cfg.Region, regionTemplatesS3BucketName, "management-account-stack.yml", templatePath)
	if err != nil {
		return fmt.Errorf("failed to upload template for Stack %s: %w", stackName, err)
	}

	err = deployCloudFormationStack(cfClient, stackName, "", templateUrl, params)
	if err != nil {
		return fmt.Errorf("failed to deploy Stack %s: %w", stackName, err)
	}
	return nil
}

func DeploySSMDocumentStacks(deploymentRegions []string, profile, stackName, templatePath, managementAccountId, ssmDocumentSSMName string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(deploymentRegions))

	for _, region := range deploymentRegions {
		wg.Add(1)

		go func(region string) {
			defer wg.Done()
			cfg, err := config.LoadDefaultConfig(context.TODO(),
				config.WithSharedConfigProfile(profile),
				config.WithRegion(region),
			)
			if err != nil {
				logger.Fatalf("failed to load AWS config: %v", err)
			}
			cfClient := cloudformation.NewFromConfig(cfg)
			ssmClient := ssm.NewFromConfig(cfg)

			err = createSSMParameter(ssmClient, ssmDocumentSSMName, os.Getenv("SSMDocumentContentJson"), "Shared SSM Document Content", ssmTypes.ParameterTypeString)
			if err != nil {
				errChan <- fmt.Errorf("failed to created SSM Parameter named %s: %w", ssmDocumentSSMName, err)
				return
			}
			params := map[string]string{
				"ProjectName":               os.Getenv("ProjectName"),
				"DeploymentTargets":         os.Getenv("DeploymentTargets"),
				"ExcludeAccounts":           os.Getenv("ExcludeAccounts"),
				"ManagementAccountId":       managementAccountId,
				"SSMDocumentContentJsonSSM": ssmDocumentSSMName,
			}
			err = deployCloudFormationStack(cfClient, stackName, templatePath, "", params)
			if err != nil {
				errChan <- fmt.Errorf("failed to deploy Stack %s in %s: %w", stackName, region, err)
				return
			}
			logger.Debugf("✅ Successfully deployed Stack %s in region %s\n", stackName, region)
		}(region)
	}
	wg.Wait() // Wait for all Goroutines to finish
	close(errChan)
	// Check if any errors occurred
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	return nil
}

func DeployAutomationAccountDynamoDbTablesStack(profile, stackName, templatesS3BucketName, templatePath string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	cfClient := cloudformation.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)
	regionTemplatesS3BucketName := fmt.Sprintf("%s-%s", templatesS3BucketName, cfg.Region)

	templateUrl, err := uploadTemplateToS3Bucket(s3Client, cfg.Region, regionTemplatesS3BucketName, "automation-dynamodb-stack.yml", templatePath)
	if err != nil {
		return fmt.Errorf("failed to upload template for Stack %s: %w", stackName, err)
	}
	params := map[string]string{
		"ProjectName":                          os.Getenv("ProjectName"),
		"TrackSSMDocumentAssociationFailures":  os.Getenv("TrackSSMDocumentAssociationFailures"),
		"AddSupportforIAMKeyPairAccessTracker": os.Getenv("AddSupportforIAMKeyPairAccessTracker"),
		"AddSupportforCMDB":                    os.Getenv("AddSupportforCMDB"),
		"AddSupportforIPTracker":               os.Getenv("AddSupportforIPTracker"),
		"DisableDetectionStoppedEC2Instances":  os.Getenv("DisableDetectionStoppedEC2Instances"),
		"DisableDetectionUnusedSecurityGroups": os.Getenv("DisableDetectionUnusedSecurityGroups"),
		"DisableDetectionUnusedEBSVolumes":     os.Getenv("DisableDetectionUnusedEBSVolumes"),
	}

	err = deployCloudFormationStack(cfClient, stackName, "", templateUrl, params)
	if err != nil {
		return fmt.Errorf("failed to deploy Stack %s: %w", stackName, err)
	}
	return nil
}

func DeployAutomationAccountSecretsStack(
	profile,
	stackName,
	templatesS3BucketName,
	templatePath,
	managementAccountId,
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
	ssmDocumentAssociationFailureTrackerTableName string,
) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	cfClient := cloudformation.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)
	regionTemplatesS3BucketName := fmt.Sprintf("%s-%s", templatesS3BucketName, cfg.Region)

	templateUrl, err := uploadTemplateToS3Bucket(s3Client, cfg.Region, regionTemplatesS3BucketName, "automation-secrets-stack.yml", templatePath)
	if err != nil {
		return fmt.Errorf("failed to upload template for Stack %s: %w", stackName, err)
	}
	params := map[string]string{
		"ProjectName":                                          os.Getenv("ProjectName"),
		"ManagementAccountId":                                  managementAccountId,
		"EnableGuardDuty":                                      os.Getenv("EnableGuardDuty"),
		"EnableVpcFlowLogs":                                    os.Getenv("EnableVpcFlowLogs"),
		"FlowLogsDeliveryBucketPrefix":                         os.Getenv("FlowLogsDeliveryBucketPrefix"),
		"VpcFlowLogsTagKeyValue":                               os.Getenv("VpcFlowLogsTagKeyValue"),
		"SecurityGroupTableName":                               securityGroupTableName,
		"IAMUsersTableName":                                    iamUsersTableName,
		"S3BucketsTableName":                                   s3BucketsTableName,
		"RootIAMLoginsTableName":                               rootIAMLoginsTableName,
		"UnusedEC2InstancesTableName":                          unusedEC2InstancesTableName,
		"UnusedSecurityGroupsTableName":                        unusedSecurityGroupsTableName,
		"UnusedEBSVolumesTableName":                            unusedEBSVolumesTableName,
		"RemediatedResourcesTableName":                         remediatedResourcesTableName,
		"ActiveResourcesTableName":                             activeResourcesTableName,
		"DeletedResourcesTableName":                            deletedResourcesTableName,
		"DailyUserCostReportsTableName":                        dailyUserCostReportsTableName,
		"WeeklyUserCostReportsTableName":                       weeklyUserCostReportsTableName,
		"MonthlyUserCostReportsTableName":                      monthlyUserCostReportsTableName,
		"IPCorrelationTableName":                               ipCorrelationTableName,
		"SSOUserIPHistoryTableName":                            ssoUserIPHistoryTableName,
		"IAMKeyPairAccessTrackerTableName":                     iamKeyPairAccessTrackerTableName,
		"SSMDocumentAssociationFailureTrackerTableName":        ssmDocumentAssociationFailureTrackerTableName,
		"AutoAttachIAMRoleEC2":                                 os.Getenv("AutoAttachIAMRoleEC2"),
		"ExistingEC2SSMIAMRoleName":                            os.Getenv("ExistingEC2SSMIAMRoleName"),
		"AutoAttachMissingPolicies":                            os.Getenv("AutoAttachMissingPolicies"),
		"NamesOfAdditionalPoliciesToAutoAttach":                os.Getenv("NamesOfAdditionalPoliciesToAutoAttach"),
		"CreateNewManagedPolicy":                               os.Getenv("CreateNewManagedPolicy"),
		"ManagedPolicyName":                                    os.Getenv("ManagedPolicyName"),
		"EnableEC2InstanceConfigurator":                        os.Getenv("EnableEC2InstanceConfigurator"),
		"SSMDocumentName":                                      ssmDocumentName,
		"TrackSSMDocumentAssociationFailures":                  os.Getenv("TrackSSMDocumentAssociationFailures"),
		"CreatePagerDutyIncidentsForSSMFailures":               os.Getenv("CreatePagerDutyIncidentsForSSMFailures"),
		"EnableHourlySSMFailureReminders":                      os.Getenv("EnableHourlySSMFailureReminders"),
		"AddSupportforIAMKeyPairAccessTracker":                 os.Getenv("AddSupportforIAMKeyPairAccessTracker"),
		"AddSupportforCMDB":                                    os.Getenv("AddSupportforCMDB"),
		"EnableCostOptimizerRecommendations":                   os.Getenv("EnableCostOptimizerRecommendations"),
		"AddSupportforIPTracker":                               os.Getenv("AddSupportforIPTracker"),
		"TrackTailscaleIPs":                                    os.Getenv("TrackTailscaleIPs"),
		"TailnetName":                                          os.Getenv("TailnetName"),
		"OAuthClientId":                                        os.Getenv("OAuthClientId"),
		"OAuthClientSecretSSM":                                 os.Getenv("OAuthClientSecretSSM"),
		"BlockEC2LaunchWithoutCertainTags":                     os.Getenv("BlockEC2LaunchWithoutCertainTags"),
		"EC2InstanceLaunchSCPTagKeys":                          os.Getenv("EC2InstanceLaunchSCPTagKeys"),
		"BlockEksClusterCreationWithoutCertainTags":            os.Getenv("BlockEksClusterCreationWithoutCertainTags"),
		"EksClusterCreationSCPTagKeys":                         os.Getenv("EksClusterCreationSCPTagKeys"),
		"BlockRdsClusterInstanceCreationWithoutCertainTags":    os.Getenv("BlockRdsClusterInstanceCreationWithoutCertainTags"),
		"RdsClusterInstanceCreationSCPTagKeys":                 os.Getenv("RdsClusterInstanceCreationSCPTagKeys"),
		"BlockEfsFileSystemCreationWithoutCertainTags":         os.Getenv("BlockEfsFileSystemCreationWithoutCertainTags"),
		"EfsFileSystemCreationSCPTagKeys":                      os.Getenv("EfsFileSystemCreationSCPTagKeys"),
		"BlockEC2LaunchWithoutIMDSV2":                          os.Getenv("BlockEC2LaunchWithoutIMDSV2"),
		"SCPBypassTagKeyEC2LaunchWithoutIMDSV2":                os.Getenv("SCPBypassTagKeyEC2LaunchWithoutIMDSV2"),
		"AlertOnEC2LaunchIMDSV2Bypass":                         os.Getenv("AlertOnEC2LaunchIMDSV2Bypass"),
		"BlockEC2LaunchWithPublicIP":                           os.Getenv("BlockEC2LaunchWithPublicIP"),
		"SCPBypassTagKeyEC2LaunchWithPublicIP":                 os.Getenv("SCPBypassTagKeyEC2LaunchWithPublicIP"),
		"AlertOnEC2LaunchPublicIPBypass":                       os.Getenv("AlertOnEC2LaunchPublicIPBypass"),
		"BlockUnencryptedEBSVolumeCreation":                    os.Getenv("BlockUnencryptedEBSVolumeCreation"),
		"SCPBypassTagKeyEBSVolumeCreation":                     os.Getenv("SCPBypassTagKeyEBSVolumeCreation"),
		"AlertOnUnencryptedEBSVolumeCreationBypass":            os.Getenv("AlertOnUnencryptedEBSVolumeCreationBypass"),
		"BlockLoadBalancerCreation":                            os.Getenv("BlockLoadBalancerCreation"),
		"SCPBypassTagKeyLoadBalancerCreation":                  os.Getenv("SCPBypassTagKeyLoadBalancerCreation"),
		"AlertOnLoadBalancerCreationBypass":                    os.Getenv("AlertOnLoadBalancerCreationBypass"),
		"BlockEIPAllocation":                                   os.Getenv("BlockEIPAllocation"),
		"SCPBypassTagKeyEIPAllocation":                         os.Getenv("SCPBypassTagKeyEIPAllocation"),
		"AlertOnEIPAllocationBypass":                           os.Getenv("AlertOnEIPAllocationBypass"),
		"BlockMakeEBSSnapshotPublic":                           os.Getenv("BlockMakeEBSSnapshotPublic"),
		"BlockUnencryptedRDSCreation":                          os.Getenv("BlockUnencryptedRDSCreation"),
		"SCPBypassTagKeyUnencryptedRDSCreation":                os.Getenv("SCPBypassTagKeyUnencryptedRDSCreation"),
		"AlertOnUnencryptedRDSCreationBypass":                  os.Getenv("AlertOnUnencryptedRDSCreationBypass"),
		"BlockIAMUsersCreation":                                os.Getenv("BlockIAMUsersCreation"),
		"SCPBypassTagKeyIAMUsersCreation":                      os.Getenv("SCPBypassTagKeyIAMUsersCreation"),
		"AlertOnIAMUsersCreationBypass":                        os.Getenv("AlertOnIAMUsersCreationBypass"),
		"BlockIAMUserCreationWithoutCertainTags":               os.Getenv("BlockIAMUserCreationWithoutCertainTags"),
		"IAMUsersCreationSCPTagKeys":                           os.Getenv("IAMUsersCreationSCPTagKeys"),
		"AWSServiceDeploymentAction":                           os.Getenv("AWSServiceDeploymentAction"),
		"TagVPCs":                                              os.Getenv("TagVPCs"),
		"TagVPCUsingTagTemplateForTerraformDeployment":         os.Getenv("TagVPCUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueVPCs":                                     os.Getenv("TagsKeyValueVPCs"),
		"SendMissingTagsNotificationVPCs":                      os.Getenv("SendMissingTagsNotificationVPCs"),
		"TagSubnets":                                           os.Getenv("TagSubnets"),
		"TagSubnetUsingTagTemplateForTerraformDeployment":      os.Getenv("TagSubnetUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueSubnets":                                  os.Getenv("TagsKeyValueSubnets"),
		"SendMissingTagsNotificationSubnets":                   os.Getenv("SendMissingTagsNotificationSubnets"),
		"TagEbsVolumes":                                        os.Getenv("TagEbsVolumes"),
		"TagEbsVolumeUsingTagTemplateForTerraformDeployment":   os.Getenv("TagEbsVolumeUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueEbsVolumes":                               os.Getenv("TagsKeyValueEbsVolumes"),
		"SendMissingTagsNotificationEbsVolumes":                os.Getenv("SendMissingTagsNotificationEbsVolumes"),
		"TagEIPs":                                              os.Getenv("TagEIPs"),
		"TagEIPUsingTagTemplateForTerraformDeployment":         os.Getenv("TagEIPUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueEIPs":                                     os.Getenv("TagsKeyValueEIPs"),
		"SendMissingTagsNotificationEIPs":                      os.Getenv("SendMissingTagsNotificationEIPs"),
		"TagEbsSnapshots":                                      os.Getenv("TagEbsSnapshots"),
		"TagEbsSnapshotUsingTagTemplateForTerraformDeployment": os.Getenv("TagEbsSnapshotUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueEbsSnapshots":                             os.Getenv("TagsKeyValueEbsSnapshots"),
		"SendMissingTagsNotificationEbsSnapshots":              os.Getenv("SendMissingTagsNotificationEbsSnapshots"),
		"TagAMIs": os.Getenv("TagAMIs"),
		"TagAMIUsingTagTemplateForTerraformDeployment": os.Getenv("TagAMIUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueAMIs":                                            os.Getenv("TagsKeyValueAMIs"),
		"SendMissingTagsNotificationAMIs":                             os.Getenv("SendMissingTagsNotificationAMIs"),
		"TagEC2Instances":                                             os.Getenv("TagEC2Instances"),
		"TagEC2InstanceUsingTagTemplateForTerraformDeployment":        os.Getenv("TagEC2InstanceUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueEC2Instances":                                    os.Getenv("TagsKeyValueEC2Instances"),
		"SendMissingTagsNotificationEC2Instances":                     os.Getenv("SendMissingTagsNotificationEC2Instances"),
		"TagEksClusters":                                              os.Getenv("TagEksClusters"),
		"TagEksClusterUsingTagTemplateForTerraformDeployment":         os.Getenv("TagEksClusterUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueEksClusters":                                     os.Getenv("TagsKeyValueEksClusters"),
		"SendMissingTagsNotificationEksClusters":                      os.Getenv("SendMissingTagsNotificationEksClusters"),
		"TagRDSClusterInstances":                                      os.Getenv("TagRDSClusterInstances"),
		"TagRDSClusterInstanceUsingTagTemplateForTerraformDeployment": os.Getenv("TagRDSClusterInstanceUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueRDSClusterInstances":                             os.Getenv("TagsKeyValueRDSClusterInstances"),
		"SendMissingTagsNotificationRDSClusterInstances":              os.Getenv("SendMissingTagsNotificationRDSClusterInstances"),
		"TagEFS": os.Getenv("TagEFS"),
		"TagEfsUsingTagTemplateForTerraformDeployment": os.Getenv("TagEfsUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueEFS":                os.Getenv("TagsKeyValueEFS"),
		"SendMissingTagsNotificationEFS": os.Getenv("SendMissingTagsNotificationEFS"),
		"TagFSX":                         os.Getenv("TagFSX"),
		"TagFsxUsingTagTemplateForTerraformDeployment": os.Getenv("TagFsxUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueFSX":                os.Getenv("TagsKeyValueFSX"),
		"SendMissingTagsNotificationFSX": os.Getenv("SendMissingTagsNotificationFSX"),
		"TagSecrets":                     os.Getenv("TagSecrets"),
		"TagSecretUsingTagTemplateForTerraformDeployment":       os.Getenv("TagSecretUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueSecrets":                                   os.Getenv("TagsKeyValueSecrets"),
		"SendMissingTagsNotificationSecrets":                    os.Getenv("SendMissingTagsNotificationSecrets"),
		"TagBackupPlans":                                        os.Getenv("TagBackupPlans"),
		"TagBackupPlanUsingTagTemplateForTerraformDeployment":   os.Getenv("TagBackupPlanUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueBackupPlans":                               os.Getenv("TagsKeyValueBackupPlans"),
		"SendMissingTagsNotificationBackupPlans":                os.Getenv("SendMissingTagsNotificationBackupPlans"),
		"TagLoadbalancers":                                      os.Getenv("TagLoadbalancers"),
		"TagLoadbalancerUsingTagTemplateForTerraformDeployment": os.Getenv("TagLoadbalancerUsingTagTemplateForTerraformDeployment"),
		"TagsKeyValueLoadbalancers":                             os.Getenv("TagsKeyValueLoadbalancers"),
		"SendMissingTagsNotificationLoadbalancers":              os.Getenv("SendMissingTagsNotificationLoadbalancers"),
		"AllTrafficSGRulesRemediation":                          os.Getenv("AllTrafficSGRulesRemediation"),
		"RemoteAccessPortsSGRulesRemediation":                   os.Getenv("RemoteAccessPortsSGRulesRemediation"),
		"TrafficPortsSGRulesRemediation":                        os.Getenv("TrafficPortsSGRulesRemediation"),
		"LaunchWizardSGRemediation":                             os.Getenv("LaunchWizardSGRemediation"),
		"S3AccountPublicBlockRemediation":                       os.Getenv("S3AccountPublicBlockRemediation"),
		"EBSPublicSnapshotsRemediation":                         os.Getenv("EBSPublicSnapshotsRemediation"),
		"PublicAMIsRemediation":                                 os.Getenv("PublicAMIsRemediation"),
		"PublicRDSSnapshotsRemediation":                         os.Getenv("PublicRDSSnapshotsRemediation"),
		"AttachedOverPermissiveRolesRemediation":                os.Getenv("AttachedOverPermissiveRolesRemediation"),
		"UnusedSecretAccessKeypairRemediation":                  os.Getenv("UnusedSecretAccessKeypairRemediation"),
		"InactiveCriteriaDays":                                  os.Getenv("DeactivateUnusedSecretAccessKeypairInDays"),
		"SenderEmailAddress":                                    os.Getenv("SenderEmailAddress"),
		"ReceiverEmailAddressess":                               os.Getenv("ReceiverEmailAddressess"),
		"SendHourlyAlertsForSeverityTypes":                      os.Getenv("SendHourlyAlertsForSeverityTypes"),
		"AlertSuppressionResourceTagKeyValue":                   os.Getenv("AlertSuppressionResourceTagKeyValue"),
		"AlertSuppressionPermissionSetTagKeyValue":              os.Getenv("AlertSuppressionPermissionSetTagKeyValue"),
		"EC2SecurityGroupIngressTrafficPorts":                   os.Getenv("EC2SecurityGroupIngressTrafficPorts"),
		"EC2SecurityGroupIngressRemoteAccessPorts":              os.Getenv("EC2SecurityGroupIngressRemoteAccessPorts"),
		"EC2SecurityGroupIngressIgnorePorts":                    os.Getenv("EC2SecurityGroupIngressIgnorePorts"),
		"LoadBalancerSecurityGroupIngressTrafficPorts":          os.Getenv("LoadBalancerSecurityGroupIngressTrafficPorts"),
		"LoadBalancerSecurityGroupIngressRemoteAccessPorts":     os.Getenv("LoadBalancerSecurityGroupIngressRemoteAccessPorts"),
		"LoadBalancerSecurityGroupIngressIgnorePorts":           os.Getenv("LoadBalancerSecurityGroupIngressIgnorePorts"),
		"EIPAssociationOverrideTagKeyBase64":                    os.Getenv("EIPAssociationOverrideTagKeyBase64"),
		"EC2InstanceIAMRoleDetectionBypassTagKey":               os.Getenv("EC2InstanceIAMRoleDetectionBypassTagKey"),
		"DisableFindingEC2LaunchWithoutIMDSv2":                  os.Getenv("DisableFindingEC2LaunchWithoutIMDSv2"),
		"DisableFindingEC2LaunchWithPublicIP":                   os.Getenv("DisableFindingEC2LaunchWithPublicIP"),
		"DisableFindingUnencryptedEBSVolume":                    os.Getenv("DisableFindingUnencryptedEBSVolume"),
		"DisbleIAMSecretAccessKeyExpiryReminders":               os.Getenv("DisbleIAMSecretAccessKeyExpiryReminders"),
		"IAMSecretAccessKeyExpiryInDays":                        os.Getenv("IAMSecretAccessKeyExpiryInDays"),
		"AddSupportforPagerDuty":                                os.Getenv("AddSupportforPagerDuty"),
		"CreateIncidentForSeverityTypes":                        os.Getenv("CreateIncidentForSeverityTypes"),
		"PagerDutyIntegrationType":                              os.Getenv("PagerDutyIntegrationType"),
		"PagerDutyRoutingKeySSM":                                os.Getenv("PagerDutyRoutingKeySSM"),
		"PagerDutyApiTokenSSM":                                  os.Getenv("PagerDutyApiTokenSSM"),
		"PagerDutyServiceId":                                    os.Getenv("PagerDutyServiceId"),
		"PagerDutyUserEmailAddress":                             os.Getenv("PagerDutyUserEmailAddress"),
		"AddSupportforAzureCloud":                               os.Getenv("AddSupportforAzureCloud"),
		"AzureCustomerId":                                       os.Getenv("AzureCustomerId"),
		"AzureSharedKeySSM":                                     os.Getenv("AzureSharedKeySSM"),
		"AzureLogType":                                          os.Getenv("AzureLogType"),
	}

	err = deployCloudFormationStack(cfClient, stackName, "", templateUrl, params)
	if err != nil {
		return fmt.Errorf("failed to deploy Stack %s: %w", stackName, err)
	}
	return nil
}

func DeployAutomationAccountStack(
	profile,
	stackName,
	templatesS3BucketName,
	templatePath,
	packagedTemplateDir,
	organizationId,
	crossAccountRole,
	slackActionsCrossAccountRole,
	managementAccountId,
	orgChildStackSetName,
	userOffboardingWorkflowEcrImageUri,
	slackSocketAppEcrImageURI,
	policyDocumentSSMName,
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
	ssmDocumentAssociationFailureTrackerTableName string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	cfClient := cloudformation.NewFromConfig(cfg)
	ssmClient := ssm.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)

	regionTemplatesS3BucketName := fmt.Sprintf("%s-%s", templatesS3BucketName, cfg.Region)
	packagedTemplatePath := fmt.Sprintf("%s/main-stack.yml", packagedTemplateDir)

	managedPolicyDocumentJson := os.Getenv("ManagedPolicyDocumentJson")
	createNewManagedPolicy, err := strconv.ParseBool(os.Getenv("CreateNewManagedPolicy"))
	if err != nil {
		logger.Errorf("Error parsing boolean for key CreateNewManagedPolicy: %v", err)
	}
	if !createNewManagedPolicy {
		managedPolicyDocumentJson = "{}"
	}
	err = createSSMParameter(ssmClient, policyDocumentSSMName, managedPolicyDocumentJson, "Managed Policy JSON", ssmTypes.ParameterTypeString)
	if err != nil {
		return fmt.Errorf("failed to created SSM Parameter named %s: %w", policyDocumentSSMName, err)
	}

	err = packageTemplate(templatePath, regionTemplatesS3BucketName, packagedTemplatePath, profile, cfg.Region)
	if err != nil {
		return fmt.Errorf("failed to package template for Stack %s: %w", stackName, err)
	}
	templateUrl, err := uploadTemplateToS3Bucket(s3Client, cfg.Region, regionTemplatesS3BucketName, "automation-account-stack.yml", packagedTemplatePath)
	if err != nil {
		return fmt.Errorf("failed to upload template for Stack %s: %w", stackName, err)
	}

	params := map[string]string{
		"ProjectName":                                       os.Getenv("ProjectName"),
		"AwsOrgName":                                        os.Getenv("AwsOrgName"),
		"OrganizationId":                                    organizationId,
		"IsControlTowerEnabled":                             os.Getenv("IsControlTowerEnabled"),
		"CrossAccountRole":                                  crossAccountRole,
		"SlackActionsCrossAccountRole":                      slackActionsCrossAccountRole,
		"DeploymentTargets":                                 os.Getenv("DeploymentTargets"),
		"ExcludeAccounts":                                   os.Getenv("ExcludeAccounts"),
		"ActiveRegions":                                     os.Getenv("ActiveRegions"),
		"ManagementAccountId":                               managementAccountId,
		"LogArchiveAccountId":                               os.Getenv("LogArchiveAccountId"),
		"IsOrganizationTrail":                               os.Getenv("IsOrganizationTrail"),
		"CentralizedLogsS3BucketName":                       os.Getenv("CentralizedLogsS3BucketName"),
		"HomeRegion":                                        cfg.Region,
		"ChildAccountsStackSetName":                         orgChildStackSetName,
		"EnableVpcFlowLogs":                                 os.Getenv("EnableVpcFlowLogs"),
		"FlowLogsDeliveryBucketPrefix":                      os.Getenv("FlowLogsDeliveryBucketPrefix"),
		"SecurityGroupTableName":                            securityGroupTableName,
		"IAMUsersTableName":                                 iamUsersTableName,
		"S3BucketsTableName":                                s3BucketsTableName,
		"RootIAMLoginsTableName":                            rootIAMLoginsTableName,
		"UnusedEC2InstancesTableName":                       unusedEC2InstancesTableName,
		"UnusedSecurityGroupsTableName":                     unusedSecurityGroupsTableName,
		"UnusedEBSVolumesTableName":                         unusedEBSVolumesTableName,
		"RemediatedResourcesTableName":                      remediatedResourcesTableName,
		"ActiveResourcesTableName":                          activeResourcesTableName,
		"DeletedResourcesTableName":                         deletedResourcesTableName,
		"DailyUserCostReportsTableName":                     dailyUserCostReportsTableName,
		"WeeklyUserCostReportsTableName":                    weeklyUserCostReportsTableName,
		"MonthlyUserCostReportsTableName":                   monthlyUserCostReportsTableName,
		"IPCorrelationTableName":                            ipCorrelationTableName,
		"SSOUserIPHistoryTableName":                         ssoUserIPHistoryTableName,
		"IAMKeyPairAccessTrackerTableName":                  iamKeyPairAccessTrackerTableName,
		"SSMDocumentAssociationFailureTrackerTableName":     ssmDocumentAssociationFailureTrackerTableName,
		"UserOffboardingWorkflowECRImageURI":                userOffboardingWorkflowEcrImageUri,
		"EnableGuardDuty":                                   os.Getenv("EnableGuardDuty"),
		"GuardDutySeverityLevels":                           os.Getenv("GuardDutySeverityLevels"),
		"SSOUsersSecretName":                                ssoUsersSecretName,
		"EventsProcessorLambdaEnvVarsSecretName":            eventsProcessorLambdaEnvVarsSecretName,
		"AddSupportforPostDeploySSMAutomation":              os.Getenv("AddSupportforPostDeploySSMAutomation"),
		"AutoAttachIAMRoleEC2":                              os.Getenv("AutoAttachIAMRoleEC2"),
		"ExistingEC2SSMIAMRoleName":                         os.Getenv("ExistingEC2SSMIAMRoleName"),
		"AutoAttachMissingPolicies":                         os.Getenv("AutoAttachMissingPolicies"),
		"NamesOfAdditionalPoliciesToAutoAttach":             os.Getenv("NamesOfAdditionalPoliciesToAutoAttach"),
		"AutoCreateVPCEndpoints":                            os.Getenv("AutoCreateVPCEndpoints"),
		"VPCEndpointsList":                                  os.Getenv("VPCEndpointsList"),
		"CreateNewManagedPolicy":                            os.Getenv("CreateNewManagedPolicy"),
		"ManagedPolicyName":                                 os.Getenv("ManagedPolicyName"),
		"ManagedPolicyDocumentJsonSSM":                      policyDocumentSSMName,
		"EnableEC2InstanceConfigurator":                     os.Getenv("EnableEC2InstanceConfigurator"),
		"TrackSSMDocumentAssociationFailures":               os.Getenv("TrackSSMDocumentAssociationFailures"),
		"AddSupportforUserOffboardingWorkflow":              os.Getenv("AddSupportforUserOffboardingWorkflow"),
		"AddSupportforIAMKeyPairAccessTracker":              os.Getenv("AddSupportforIAMKeyPairAccessTracker"),
		"AddSupportforCMDB":                                 os.Getenv("AddSupportforCMDB"),
		"AddSupportforIPTracker":                            os.Getenv("AddSupportforIPTracker"),
		"TrackTailscaleIPs":                                 os.Getenv("TrackTailscaleIPs"),
		"TagVPCs":                                           os.Getenv("TagVPCs"),
		"TagsKeyValueVPCs":                                  os.Getenv("TagsKeyValueVPCs"),
		"TagSubnets":                                        os.Getenv("TagSubnets"),
		"TagsKeyValueSubnets":                               os.Getenv("TagsKeyValueSubnets"),
		"TagEbsVolumes":                                     os.Getenv("TagEbsVolumes"),
		"TagsKeyValueEbsVolumes":                            os.Getenv("TagsKeyValueEbsVolumes"),
		"TagEIPs":                                           os.Getenv("TagEIPs"),
		"TagsKeyValueEIPs":                                  os.Getenv("TagsKeyValueEIPs"),
		"TagEbsSnapshots":                                   os.Getenv("TagEbsSnapshots"),
		"TagsKeyValueEbsSnapshots":                          os.Getenv("TagsKeyValueEbsSnapshots"),
		"TagAMIs":                                           os.Getenv("TagAMIs"),
		"TagsKeyValueAMIs":                                  os.Getenv("TagsKeyValueAMIs"),
		"TagEC2Instances":                                   os.Getenv("TagEC2Instances"),
		"TagsKeyValueEC2Instances":                          os.Getenv("TagsKeyValueEC2Instances"),
		"TagEksClusters":                                    os.Getenv("TagEksClusters"),
		"TagsKeyValueEksClusters":                           os.Getenv("TagsKeyValueEksClusters"),
		"TagRDSClusterInstances":                            os.Getenv("TagRDSClusterInstances"),
		"TagsKeyValueRDSClusterInstances":                   os.Getenv("TagsKeyValueRDSClusterInstances"),
		"TagEFS":                                            os.Getenv("TagEFS"),
		"TagsKeyValueEFS":                                   os.Getenv("TagsKeyValueEFS"),
		"TagFSX":                                            os.Getenv("TagFSX"),
		"TagsKeyValueFSX":                                   os.Getenv("TagsKeyValueFSX"),
		"TagSecrets":                                        os.Getenv("TagSecrets"),
		"TagsKeyValueSecrets":                               os.Getenv("TagsKeyValueSecrets"),
		"TagBackupPlans":                                    os.Getenv("TagBackupPlans"),
		"TagsKeyValueBackupPlans":                           os.Getenv("TagsKeyValueBackupPlans"),
		"TagLoadbalancers":                                  os.Getenv("TagLoadbalancers"),
		"TagsKeyValueLoadbalancers":                         os.Getenv("TagsKeyValueLoadbalancers"),
		"EngineerFacingNotificationsConfigsSecretName":      os.Getenv("EngineerFacingNotificationsConfigsSecretName"),
		"SecurityAdminFacingNotificationsConfigsSecretName": os.Getenv("SecurityAdminFacingNotificationsConfigsSecretName"),
		"EnableSlackSocketMode":                             os.Getenv("EnableSlackSocketMode"),
		"SlackSocketAppEcrImageURI":                         slackSocketAppEcrImageURI,
		"SlackBotConfigSecretName":                          os.Getenv("SlackBotConfigSecretName"),
		"SlackApiDomainName":                                os.Getenv("SlackApiDomainName"),
		"SlackApiDomainCertificateArn":                      os.Getenv("SlackApiDomainCertificateArn"),
		"SenderEmailAddress":                                os.Getenv("SenderEmailAddress"),
		"ReceiverEmailAddressess":                           os.Getenv("ReceiverEmailAddressess"),
		"UnusedResourcesDetectionBypassTagKey":              os.Getenv("UnusedResourcesDetectionBypassTagKey"),
		"DisableDetectionStoppedEC2Instances":               os.Getenv("DisableDetectionStoppedEC2Instances"),
		"DisableDetectionUnusedSecurityGroups":              os.Getenv("DisableDetectionUnusedSecurityGroups"),
		"DisableDetectionUnusedEBSVolumes":                  os.Getenv("DisableDetectionUnusedEBSVolumes"),
		"AddSupportforAzureCloud":                           os.Getenv("AddSupportforAzureCloud"),
		"AzureCustomerId":                                   os.Getenv("AzureCustomerId"),
		"AzureSharedKeySSM":                                 os.Getenv("AzureSharedKeySSM"),
		"AzureLogType":                                      os.Getenv("AzureLogType"),
	}

	err = deployCloudFormationStack(cfClient, stackName, "", templateUrl, params)
	if err != nil {
		return fmt.Errorf("failed to deploy Stack %s: %w", stackName, err)
	}
	return nil
}

func DeleteRegionalStacks(deploymentRegions []string, profile, stackName, templatesS3BucketName, ssmDocumentSSMName string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(deploymentRegions))

	for _, region := range deploymentRegions {
		wg.Add(1)

		go func(region string) {
			defer wg.Done()
			cfg, err := config.LoadDefaultConfig(context.TODO(),
				config.WithSharedConfigProfile(profile),
				config.WithRegion(region),
			)
			if err != nil {
				logger.Fatalf("failed to load AWS config: %v", err)
			}
			cfClient := cloudformation.NewFromConfig(cfg)
			ssmClient := ssm.NewFromConfig(cfg)
			s3Client := s3.NewFromConfig(cfg)

			err = DeleteCloudFormationStackIfExists(cfClient, stackName)
			if err != nil {
				errChan <- fmt.Errorf("failed to delete Stack %s in %s: %w", stackName, region, err)
				return
			}

			if ssmDocumentSSMName != "" {
				err = DeleteSSMParameterIfExists(ssmClient, ssmDocumentSSMName)
				if err != nil {
					errChan <- fmt.Errorf("failed to delete SSM Parameter named %s: %w", ssmDocumentSSMName, err)
					return
				}
			}
			if templatesS3BucketName != "" {
				regionTemplatesS3BucketName := fmt.Sprintf("%s-%s", templatesS3BucketName, region)
				err = DeleteS3BucketIfExists(s3Client, regionTemplatesS3BucketName)
				if err != nil {
					errChan <- fmt.Errorf("failed to delete S3 Bucket %s in %s: %w", regionTemplatesS3BucketName, region, err)
					return
				}
			}
			logger.Debugf("✅ Successfully deleted Stack %s in region %s\n", stackName, region)
		}(region)
	}
	wg.Wait() // Wait for all Goroutines to finish
	close(errChan)
	// Check if any errors occurred
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	return nil
}
