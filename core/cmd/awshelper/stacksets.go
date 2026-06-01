package awshelper

import (
	"context"
	"fmt"
	"os"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

func DeployCfStackSetExecutionRoleStackSet(profile, automationAccountId, managementAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"AdministratorAccountId": automationAccountId,
		"ExecutionRoleName":      os.Getenv("CloudFormationStackSetExecutionRoleStackSetName"),
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeployVpcFlowLogsDeliveryKmsKeyStackSet(profile, automationAccountId, managementAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":         os.Getenv("ProjectName"),
		"LogArchiveAccountId": os.Getenv("LogArchiveAccountId"),
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeployVpcFlowLogsDeliveryBucketStackSet(profile, automationAccountId, managementAccountId, flowLogsAdminAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":                  os.Getenv("ProjectName"),
		"FlowLogsDeliveryBucketPrefix": os.Getenv("FlowLogsDeliveryBucketPrefix"),
		"AdminAccountId":               flowLogsAdminAccountId,
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeployGuardDutyDeliveryKmsKeyStackSet(profile, automationAccountId, managementAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":         os.Getenv("ProjectName"),
		"LogArchiveAccountId": os.Getenv("LogArchiveAccountId"),
		"AutomationAccountId": automationAccountId,
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeployGuardDutyDeliveryBucketStackSet(profile, automationAccountId, managementAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":                   os.Getenv("ProjectName"),
		"GuardDutyAdminAccountId":       os.Getenv("GuardDutyAdminAccountId"),
		"GuardDutyDeliveryBucketPrefix": os.Getenv("GuardDutyDeliveryS3BucketPrefix"),
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeployGuardDutyAdminDelegationStackSet(profile, automationAccountId, managementAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":             os.Getenv("ProjectName"),
		"GuardDutyAdminAccountId": os.Getenv("GuardDutyAdminAccountId"),
		"AutomationAccountId":     automationAccountId,
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeployGuardDutyEnablerStackSet(profile, automationAccountId, managementAccountId, automationEventBusName string, requireCentralLoggingBucket bool, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":                     os.Getenv("ProjectName"),
		"GuardDutyAdminAccountId":         os.Getenv("GuardDutyAdminAccountId"),
		"DeploymentTargets":               os.Getenv("DeploymentTargets"),
		"ExcludeAccounts":                 os.Getenv("ExcludeAccounts"),
		"ManagementAccountId":             managementAccountId,
		"AutomationAccountId":             automationAccountId,
		"LogArchiveAccountId":             os.Getenv("LogArchiveAccountId"),
		"HomeRegion":                      cfg.Region,
		"AutomationEventBusName":          automationEventBusName,
		"FindingPublishingFrequency":      os.Getenv("FindingPublishingFrequency"),
		"GuardDutyDeliveryBucketPrefix":   os.Getenv("GuardDutyDeliveryS3BucketPrefix"),
		"IsCentralLoggingBucket":          strconv.FormatBool(requireCentralLoggingBucket),
		"GuardDutySeverityLevels":         os.Getenv("GuardDutySeverityLevels"),
		"AutoEnableS3Logs":                os.Getenv("AutoEnableS3Logs"),
		"EnableEKSAuditLogs":              os.Getenv("EnableEKSAuditLogs"),
		"AutoEnableMalwareProtection":     os.Getenv("AutoEnableMalwareProtection"),
		"EnableRDSLoginEvents":            os.Getenv("EnableRDSLoginEvents"),
		"EnableEKSRuntimeMonitoring":      os.Getenv("EnableEKSRuntimeMonitoring"),
		"EnableEKSAddonManagement":        os.Getenv("EnableEKSAddonManagement"),
		"EnableLambdaNetworkLogs":         os.Getenv("EnableLambdaNetworkLogs"),
		"EnableEcsFargateAgentManagement": os.Getenv("EnableEcsFargateAgentManagement"),
		"EnableEc2AgentManagement":        os.Getenv("EnableEc2AgentManagement"),
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeployInspectorAdminDelegationStackSet(profile, automationAccountId, managementAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":             os.Getenv("ProjectName"),
		"InspectorAdminAccountId": os.Getenv("InspectorAdminAccountId"),
		"AutomationAccountId":     automationAccountId,
		"ScanComponents":          os.Getenv("ScanComponents"),
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeployInspectorEnablerStackSet(profile, automationAccountId, managementAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":             os.Getenv("ProjectName"),
		"InspectorAdminAccountId": os.Getenv("InspectorAdminAccountId"),
		"DeploymentTargets":       os.Getenv("DeploymentTargets"),
		"ExcludeAccounts":         os.Getenv("ExcludeAccounts"),
		"ManagementAccountId":     managementAccountId,
		"AutomationAccountId":     automationAccountId,
		"ScanComponents":          os.Getenv("ScanComponents"),
		"PushEcrRescanDuration":   os.Getenv("PushEcrRescanDuration"),
		"PullEcrRescanDuration":   os.Getenv("PullEcrRescanDuration"),
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeploySecurityHubAdminDelegationStackSet(profile, automationAccountId, managementAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":                          os.Getenv("ProjectName"),
		"SecurityHubAdminAccountId":            os.Getenv("SecurityHubAdminAccountId"),
		"AutomationAccountId":                  automationAccountId,
		"EnableSecurityBestPracticesStandard":  os.Getenv("EnableSecurityBestPracticesStandard"),
		"SecurityBestPracticesStandardVersion": os.Getenv("SecurityBestPracticesStandardVersion"),
		"EnableCISStandard":                    os.Getenv("EnableCISStandard"),
		"CISStandardVersion":                   os.Getenv("CISStandardVersion"),
		"EnablePCIStandard":                    os.Getenv("EnablePCIStandard"),
		"PCIStandardVersion":                   os.Getenv("PCIStandardVersion"),
		"EnableNISTStandard":                   os.Getenv("EnableNISTStandard"),
		"NISTStandardVersion":                  os.Getenv("NISTStandardVersion"),
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeploySecurityHubEnablerStackSet(profile, automationAccountId, managementAccountId string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	params := map[string]string{
		"ProjectName":                          os.Getenv("ProjectName"),
		"SecurityHubAdminAccountId":            os.Getenv("SecurityHubAdminAccountId"),
		"HomeRegion":                           cfg.Region,
		"DeploymentTargets":                    os.Getenv("DeploymentTargets"),
		"ExcludeAccounts":                      os.Getenv("ExcludeAccounts"),
		"ActiveRegions":                        strings.Join(deploymentRegions, ","),
		"ManagementAccountId":                  managementAccountId,
		"AutomationAccountId":                  automationAccountId,
		"EnableSecurityBestPracticesStandard":  os.Getenv("EnableSecurityBestPracticesStandard"),
		"SecurityBestPracticesStandardVersion": os.Getenv("SecurityBestPracticesStandardVersion"),
		"EnableCISStandard":                    os.Getenv("EnableCISStandard"),
		"CISStandardVersion":                   os.Getenv("CISStandardVersion"),
		"EnablePCIStandard":                    os.Getenv("EnablePCIStandard"),
		"PCIStandardVersion":                   os.Getenv("PCIStandardVersion"),
		"EnableNISTStandard":                   os.Getenv("EnableNISTStandard"),
		"NISTStandardVersion":                  os.Getenv("NISTStandardVersion"),
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func DeployOrgChildStackSet(profile, automationAccountId, managementAccountId, automationEventBusName, ssmDocumentName, stepFunctionExecutorLambdaARN, captureExistingResourcesSfnARN, autoTaggerSfnARN string, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts []string, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) (*StackSetInstanceStateInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)
	slackBotTokenProvided := "false"
	if !helper.IsValEmpty(os.Getenv("SlackBotConfigSecretName")) {
		slackBotTokenProvided = "true"
	}
	params := map[string]string{
		"ProjectName":                                        os.Getenv("ProjectName"),
		"IsControlTowerEnabled":                              os.Getenv("IsControlTowerEnabled"),
		"AutomationAccountId":                                automationAccountId,
		"AutomationEventBusName":                             automationEventBusName,
		"LogArchiveAccountId":                                os.Getenv("LogArchiveAccountId"),
		"HomeRegion":                                         cfg.Region,
		"EnableEBSDefaultEncryption":                         os.Getenv("EnableEBSDefaultEncryption"),
		"SlackBotTokenProvided":                              slackBotTokenProvided,
		"StepFunctionExecutorLambdaARN":                      stepFunctionExecutorLambdaARN,
		"CaptureExistingResourcesSfnARN":                     captureExistingResourcesSfnARN,
		"AutoTaggerSfnARN":                                   autoTaggerSfnARN,
		"VpcFlowLogsTagKeyValue":                             os.Getenv("VpcFlowLogsTagKeyValue"),
		"EnableVpcFlowLogs":                                  os.Getenv("EnableVpcFlowLogs"),
		"FlowLogsDeliveryBucketPrefix":                       os.Getenv("FlowLogsDeliveryBucketPrefix"),
		"CreateManagementTrail":                              os.Getenv("CreateManagementTrail"),
		"CreateDataTrail":                                    os.Getenv("CreateDataTrail"),
		"AddSupportforPostDeploySSMAutomation":               os.Getenv("AddSupportforPostDeploySSMAutomation"),
		"EnableEC2InstanceConfigurator":                      os.Getenv("EnableEC2InstanceConfigurator"),
		"SSMDocumentName":                                    ssmDocumentName,
		"TrackSSMDocumentAssociationFailures":                os.Getenv("TrackSSMDocumentAssociationFailures"),
		"AddSupportforIAMKeyPairAccessTracker":               os.Getenv("AddSupportforIAMKeyPairAccessTracker"),
		"AddSupportforCMDB":                                  os.Getenv("AddSupportforCMDB"),
		"EnableCostOptimizerRecommendations":                 os.Getenv("EnableCostOptimizerRecommendations"),
		"TagVPCs":                                            os.Getenv("TagVPCs"),
		"TagVPCUsingTagTemplateForTerraformDeployment":       os.Getenv("TagVPCUsingTagTemplateForTerraformDeployment"),
		"VPCTagKeysForTagTemplateGeneration":                 os.Getenv("VPCTagKeysForTagTemplateGeneration"),
		"TagSubnets":                                         os.Getenv("TagSubnets"),
		"TagSubnetUsingTagTemplateForTerraformDeployment":    os.Getenv("TagSubnetUsingTagTemplateForTerraformDeployment"),
		"SubnetTagKeysForTagTemplateGeneration":              os.Getenv("SubnetTagKeysForTagTemplateGeneration"),
		"TagEbsVolumes":                                      os.Getenv("TagEbsVolumes"),
		"TagEbsVolumeUsingTagTemplateForTerraformDeployment": os.Getenv("TagEbsVolumeUsingTagTemplateForTerraformDeployment"),
		"EbsVolumeTagKeysForTagTemplateGeneration":           os.Getenv("EbsVolumeTagKeysForTagTemplateGeneration"),
		"TagEIPs": os.Getenv("TagEIPs"),
		"TagEIPUsingTagTemplateForTerraformDeployment":         os.Getenv("TagEIPUsingTagTemplateForTerraformDeployment"),
		"EIPTagKeysForTagTemplateGeneration":                   os.Getenv("EIPTagKeysForTagTemplateGeneration"),
		"TagEbsSnapshots":                                      os.Getenv("TagEbsSnapshots"),
		"TagEbsSnapshotUsingTagTemplateForTerraformDeployment": os.Getenv("TagEbsSnapshotUsingTagTemplateForTerraformDeployment"),
		"EbsSnapshotTagKeysForTagTemplateGeneration":           os.Getenv("EbsSnapshotTagKeysForTagTemplateGeneration"),
		"TagAMIs": os.Getenv("TagAMIs"),
		"TagAMIUsingTagTemplateForTerraformDeployment":                os.Getenv("TagAMIUsingTagTemplateForTerraformDeployment"),
		"AMITagKeysForTagTemplateGeneration":                          os.Getenv("AMITagKeysForTagTemplateGeneration"),
		"TagEC2Instances":                                             os.Getenv("TagEC2Instances"),
		"TagEC2InstanceUsingTagTemplateForTerraformDeployment":        os.Getenv("TagEC2InstanceUsingTagTemplateForTerraformDeployment"),
		"EC2InstanceTagKeysForTagTemplateGeneration":                  os.Getenv("EC2InstanceTagKeysForTagTemplateGeneration"),
		"TagEksClusters":                                              os.Getenv("TagEksClusters"),
		"TagEksClusterUsingTagTemplateForTerraformDeployment":         os.Getenv("TagEksClusterUsingTagTemplateForTerraformDeployment"),
		"EksClusterTagKeysForTagTemplateGeneration":                   os.Getenv("EksClusterTagKeysForTagTemplateGeneration"),
		"TagRDSClusterInstances":                                      os.Getenv("TagRDSClusterInstances"),
		"TagRDSClusterInstanceUsingTagTemplateForTerraformDeployment": os.Getenv("TagRDSClusterInstanceUsingTagTemplateForTerraformDeployment"),
		"RDSClusterInstanceTagKeysForTagTemplateGeneration":           os.Getenv("RDSClusterInstanceTagKeysForTagTemplateGeneration"),
		"TagEFS": os.Getenv("TagEFS"),
		"TagEfsUsingTagTemplateForTerraformDeployment":          os.Getenv("TagEfsUsingTagTemplateForTerraformDeployment"),
		"EFSTagKeysForTagTemplateGeneration":                    os.Getenv("EFSTagKeysForTagTemplateGeneration"),
		"TagFSX":                                                os.Getenv("TagFSX"),
		"TagFsxUsingTagTemplateForTerraformDeployment":          os.Getenv("TagFsxUsingTagTemplateForTerraformDeployment"),
		"FSXTagKeysForTagTemplateGeneration":                    os.Getenv("FSXTagKeysForTagTemplateGeneration"),
		"TagSecrets":                                            os.Getenv("TagSecrets"),
		"TagSecretUsingTagTemplateForTerraformDeployment":       os.Getenv("TagSecretUsingTagTemplateForTerraformDeployment"),
		"SecretTagKeysForTagTemplateGeneration":                 os.Getenv("SecretTagKeysForTagTemplateGeneration"),
		"TagBackupPlans":                                        os.Getenv("TagBackupPlans"),
		"TagBackupPlanUsingTagTemplateForTerraformDeployment":   os.Getenv("TagBackupPlanUsingTagTemplateForTerraformDeployment"),
		"BackupPlanTagKeysForTagTemplateGeneration":             os.Getenv("BackupPlanTagKeysForTagTemplateGeneration"),
		"TagLoadbalancers":                                      os.Getenv("TagLoadbalancers"),
		"TagLoadbalancerUsingTagTemplateForTerraformDeployment": os.Getenv("TagLoadbalancerUsingTagTemplateForTerraformDeployment"),
		"LoadbalancerTagKeysForTagTemplateGeneration":           os.Getenv("LoadbalancerTagKeysForTagTemplateGeneration"),
		"UnusedResourcesDetectionBypassTagKey":                  os.Getenv("UnusedResourcesDetectionBypassTagKey"),
		"DisableDetectionStoppedEC2Instances":                   os.Getenv("DisableDetectionStoppedEC2Instances"),
		"DisableDetectionUnusedSecurityGroups":                  os.Getenv("DisableDetectionUnusedSecurityGroups"),
		"DisableDetectionUnusedEBSVolumes":                      os.Getenv("DisableDetectionUnusedEBSVolumes"),
	}

	stackSetInstanceStateInfo, err := deployStackSet(client, automationAccountId, managementAccountId, cfg.Region, params, deploymentRegions, deploymentAccounts, deploymentTargetOUAccounts, stackSetProps, stackSetOpsPreferences)
	if err != nil {
		logger.Fatalf("failed to deploy StackSet: %v", err)
	}
	return stackSetInstanceStateInfo, nil
}

func CleanupStackSetInstances(profile string, stackSetProps *StackSetProps, isStandaloneDeployment bool, deploymentRegions, accountIds, regions []string, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)

	var stackSetOUs []string
	var stackSetAccounts []string
	var stackSetRegions []string
	if !isStandaloneDeployment {
		stackSetOUs, stackSetRegions, err = getStackSetOUsAndRegions(client, stackSetProps.StackSetName, stackSetProps.CallAs)
		if err != nil {
			return fmt.Errorf("failed to get deployed OUs for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
		}
	} else {
		stackSetAccounts, stackSetRegions, err = getAllStackInstanceAccountsAndRegions(client, stackSetProps.StackSetName, stackSetProps.CallAs)
		if err != nil {
			return fmt.Errorf("failed to get deployed accounts and regions for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
		}
	}

	if len(stackSetOUs) != 0 {
		if len(accountIds) > 0 {
			stackSetDeploymentTargets := &cfTypes.DeploymentTargets{
				OrganizationalUnitIds: stackSetOUs,
				Accounts:              accountIds,
				AccountFilterType:     cfTypes.AccountFilterTypeIntersection,
			}
			err = deleteStackSetInstances(client, stackSetProps.StackSetName, stackSetProps.CallAs, stackSetDeploymentTargets, stackSetRegions, []string{}, stackSetOpsPreferences)
			if err != nil {
				return fmt.Errorf("failed to delete Instances for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
			}
		}

		if len(regions) > 0 {
			stackSetDeploymentTargets := &cfTypes.DeploymentTargets{OrganizationalUnitIds: stackSetOUs}
			err = deleteStackSetInstances(client, stackSetProps.StackSetName, stackSetProps.CallAs, stackSetDeploymentTargets, regions, []string{}, stackSetOpsPreferences)
			if err != nil {
				return fmt.Errorf("failed to delete Instances for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
			}
		}
	} else if len(stackSetAccounts) != 0 {
		err = deleteStackSetInstances(client, stackSetProps.StackSetName, stackSetProps.CallAs, &cfTypes.DeploymentTargets{}, stackSetRegions, stackSetAccounts, stackSetOpsPreferences)
		if err != nil {
			return fmt.Errorf("failed to delete Instances for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
		}
	}
	return nil
}

func DeleteCfStackSetIfExists(profile string, isStandaloneDeployment bool, stackSetProps *StackSetProps, stackSetOpsPreferences *cfTypes.StackSetOperationPreferences) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		logger.Fatalf("failed to load AWS config: %v", err)
	}
	client := cloudformation.NewFromConfig(cfg)

	stackSetExists, err := checkIfStackSetExists(client, stackSetProps.StackSetName, stackSetProps.CallAs)
	if err != nil {
		return fmt.Errorf("failed to check for existance of CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
	}
	if stackSetExists {
		logger.Debugf("StackSet %s exist. Checking if it contains any instances...", stackSetProps.StackSetName)
		var stackSetOUs []string
		var stackSetAccounts []string
		var stackSetRegions []string
		if !isStandaloneDeployment {
			if stackSetProps.PermissionModel == cfTypes.PermissionModelsSelfManaged {
				stackSetAccounts, stackSetRegions, err = getAllStackInstanceAccountsAndRegions(client, stackSetProps.StackSetName, stackSetProps.CallAs)
				if err != nil {
					return fmt.Errorf("failed to get deployed accounts and regions for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
				}
			} else {
				stackSetOUs, stackSetRegions, err = getStackSetOUsAndRegions(client, stackSetProps.StackSetName, stackSetProps.CallAs)
				if err != nil {
					return fmt.Errorf("failed to get deployed OUs for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
				}
			}
		} else {
			stackSetAccounts, stackSetRegions, err = getAllStackInstanceAccountsAndRegions(client, stackSetProps.StackSetName, stackSetProps.CallAs)
			if err != nil {
				return fmt.Errorf("failed to get deployed accounts and regions for CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
			}
		}

		if len(stackSetOUs) > 0 {
			logger.Debugf("OU Instances found for StackSet %s. Deleting...", stackSetProps.StackSetName)
			stackSetDeploymentTargets := &cfTypes.DeploymentTargets{OrganizationalUnitIds: stackSetOUs}
			err = deleteStackSetInstances(client, stackSetProps.StackSetName, stackSetProps.CallAs, stackSetDeploymentTargets, stackSetRegions, []string{}, stackSetOpsPreferences)
			if err != nil {
				return fmt.Errorf("failed to delete OU instances of CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
			}
			logger.Debugf("Stack Instances of StackSet %s deleted successfully!", stackSetProps.StackSetName)
		} else if len(stackSetAccounts) > 0 {
			logger.Debugf("Account Instances found for StackSet %s. Deleting...", stackSetProps.StackSetName)
			err = deleteStackSetInstances(client, stackSetProps.StackSetName, stackSetProps.CallAs, &cfTypes.DeploymentTargets{}, stackSetRegions, stackSetAccounts, stackSetOpsPreferences)
			if err != nil {
				return fmt.Errorf("failed to delete account instances of CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
			}
		}
		logger.Debugf("Deleting StackSet %s...", stackSetProps.StackSetName)
		err = deleteCloudFormationStackSet(client, stackSetProps.StackSetName)
		if err != nil {
			return fmt.Errorf("failed to delete CloudFormation StackSet %s: %w", stackSetProps.StackSetName, err)
		}
	}
	return nil
}
